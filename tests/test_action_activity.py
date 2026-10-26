import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from apachewatch_app import create_app
from apachewatch_app.activity import get_action_activity
from apachewatch_app.actions import get_action_items, sync_action_items, update_action_item, update_action_note
from apachewatch_app.database import init_database


def candidate(key='disk', summary='Disk usage is 91%'):
    return {'source': 'alert', 'source_key': key, 'severity': 'critical',
            'title': 'High disk usage', 'summary': summary, 'evidence': {'value': 91}}


def utc(value):
    return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat()


class ActionActivityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = str(Path(directory.name) / 'activity.db')
        self.app = create_app({'database': self.db})
        self.client = self.app.test_client()
        sync_action_items(self.db, [candidate()])
        self.item_id = self.item()['id']
        self.url = f'/api/action-items/{self.item_id}'

    def item(self):
        return next(item for item in get_action_items(self.db, status='all')[0] if item['source_key'] == 'disk')

    def events(self):
        return list(reversed(get_action_activity(self.db, self.item_id, limit=100)['events']))

    def test_first_seen_is_recorded_once_without_poll_or_evidence_update_noise(self):
        for _ in range(4):
            sync_action_items(self.db, [candidate(), candidate(summary='Disk usage is 94%')])
            self.item()
        events = self.events()
        self.assertEqual([event['event_type'] for event in events], ['first_seen'])
        self.assertEqual(self.item()['summary'], 'Disk usage is 94%')
        self.assertIsNotNone(datetime.fromisoformat(events[0]['occurred_at']).tzinfo)

    def test_notes_retain_added_edited_and_cleared_versions_without_duplicate_saves(self):
        first = 'Checking disk.\nMeghan — <keep this text>.'
        for note in (first, first, 'Cleanup completed.', ''):
            self.assertEqual(self.client.patch(self.url, json={'note': note}).status_code, 200)
        events = [event for event in self.events() if event['event_type'] == 'note_changed']
        self.assertEqual([(e['details']['previous_note'], e['details']['note']) for e in events],
                         [('', first), (first, 'Cleanup completed.'), ('Cleanup completed.', '')])
        before = self.item()['updated_at']
        update_action_note(self.db, self.item_id, '')
        self.assertEqual(self.item()['updated_at'], before)

    def test_status_and_note_saved_together_record_both_actual_changes(self):
        self.client.patch(self.url, json={'status': 'acknowledged', 'note': 'Assigned to Meghan'})
        self.client.patch(self.url, json={'status': 'acknowledged', 'note': 'Assigned to Meghan'})
        events = self.events()
        self.assertEqual([e['event_type'] for e in events], ['first_seen', 'note_changed', 'status_changed'])
        self.assertEqual(events[-1]['details']['from_status'], 'new')
        self.assertEqual(events[-1]['details']['to_status'], 'acknowledged')
        self.assertEqual(events[-1]['details']['reason'], 'user')
        self.assertEqual(events[-1]['occurred_at'], events[-2]['occurred_at'])

    def test_review_rescheduling_and_note_saving_preserve_the_correct_deadlines(self):
        update_action_item(self.db, self.item_id, 'snoozed', snooze_minutes=60)
        first = self.item()['snoozed_until']
        update_action_note(self.db, self.item_id, 'Waiting for maintenance')
        self.assertEqual(self.item()['snoozed_until'], first)
        update_action_item(self.db, self.item_id, 'snoozed', snooze_minutes=240)
        second = self.item()['snoozed_until']
        event = self.events()[-1]
        self.assertEqual(event['event_type'], 'review_rescheduled')
        self.assertEqual(event['details'], {'previous_review_time': utc(first), 'snoozed_until': utc(second)})
        self.assertEqual(self.item()['status'], 'snoozed')

    def test_expired_review_is_recorded_once_even_with_concurrent_refreshes(self):
        update_action_item(self.db, self.item_id, 'snoozed')
        deadline = (datetime.now() - timedelta(minutes=1)).isoformat()
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE action_items SET snoozed_until = ? WHERE id = ?', (deadline, self.item_id))
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda _: get_action_items(self.db), range(8)))
        events = [event for event in self.events() if event['details'].get('reason') == 'review_due']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['details']['snoozed_until'], utc(deadline))
        self.assertEqual(self.item()['status'], 'new')

    def test_absence_return_and_automatic_reopening_are_distinct_events(self):
        update_action_item(self.db, self.item_id, 'resolved')
        sync_action_items(self.db, [candidate()])
        self.assertEqual(self.item()['status'], 'resolved')
        sync_action_items(self.db, [])
        sync_action_items(self.db, [])
        sync_action_items(self.db, [candidate()])
        sync_action_items(self.db, [candidate()])
        events = self.events()
        observation = [event['details']['observed'] for event in events if event['event_type'] == 'observation_changed']
        self.assertEqual(observation, [False, True])
        self.assertEqual(events[-1]['details']['reason'], 'finding_returned')
        self.assertEqual(events[-1]['details']['from_status'], 'resolved')
        self.assertEqual(self.item()['status'], 'new')
        update_action_item(self.db, self.item_id, 'dismissed')
        sync_action_items(self.db, [])
        sync_action_items(self.db, [candidate()])
        self.assertEqual(self.item()['status'], 'dismissed')
        self.assertEqual(self.events()[-1]['event_type'], 'observation_changed')

    def test_repeated_concurrent_updates_do_not_duplicate_events(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            changed = list(executor.map(lambda _: update_action_item(self.db, self.item_id,
                'acknowledged', note='Checking the same finding'), range(8)))
        self.assertTrue(all(changed))
        self.assertEqual([event['event_type'] for event in self.events()],
                         ['first_seen', 'note_changed', 'status_changed'])

    def test_state_rolls_back_when_its_activity_cannot_be_saved(self):
        previous, history = self.item(), self.events()
        with patch('apachewatch_app.actions.record_activity', side_effect=sqlite3.OperationalError('test write failure')):
            with self.assertRaises(sqlite3.OperationalError):
                update_action_item(self.db, self.item_id, 'resolved', note='Changed note')
        self.assertEqual(self.item(), previous)
        self.assertEqual(self.events(), history)
        with patch('apachewatch_app.actions.record_activity', side_effect=sqlite3.OperationalError('test write failure')):
            with self.assertRaises(sqlite3.OperationalError):
                sync_action_items(self.db, [candidate(summary='Changed summary'), candidate('new-finding')])
        self.assertEqual(self.item(), previous)
        self.assertEqual(len(get_action_items(self.db, status='all')[0]), 1)

    def test_older_pages_are_stable_and_isolated_to_the_selected_finding(self):
        sync_action_items(self.db, [candidate(), candidate('other')])
        other = next(item for item in get_action_items(self.db, status='all')[0] if item['source_key'] == 'other')
        update_action_note(self.db, other['id'], 'Another finding')
        for index in range(12):
            update_action_note(self.db, self.item_id, f'Note version {index}')
        expected = [e['id'] for e in reversed(self.events())]
        first = self.client.get(self.url + '/activity?limit=4').get_json()
        collected = [e['id'] for e in first['events']]
        update_action_note(self.db, self.item_id, 'Newer event while paging')
        page = first
        while page['next_before']:
            page = self.client.get(self.url + '/activity', query_string={
                'limit': 4, 'before': page['next_before']}).get_json()
            collected.extend(e['id'] for e in page['events'])
        self.assertEqual(collected, expected)
        self.assertEqual(first['total'], 13)
        self.assertEqual(self.client.get(self.url + '/activity').get_json()['events'][0]['details']['note'],
                         'Newer event while paging')
        self.assertFalse(any(e['details'].get('note') == 'Another finding' for e in self.events()))

    def test_legacy_findings_keep_known_first_seen_and_a_current_state_snapshot(self):
        created = '2026-09-20T10:00:00'
        updated = '2026-10-19T12:00:00'
        with sqlite3.connect(self.db) as conn:
            conn.execute('DROP TABLE action_item_activity')
            conn.execute('UPDATE action_items SET status = ?, note = ?, created_at = ?, updated_at = ?',
                         ('acknowledged', 'Already investigating', created, updated))
        for _ in range(3):
            init_database(self.db)
        events = self.events()
        self.assertEqual([e['event_type'] for e in events], ['first_seen', 'tracking_started'])
        self.assertEqual(datetime.fromisoformat(events[0]['occurred_at']), datetime.fromisoformat(created).astimezone(timezone.utc))
        self.assertEqual(events[1]['details']['status'], 'acknowledged')
        self.assertEqual(events[1]['details']['note'], 'Already investigating')
        self.assertEqual(self.item()['updated_at'], updated)
        update_action_note(self.db, self.item_id, 'Next step')
        self.assertEqual(self.events()[-1]['details']['previous_note'], 'Already investigating')

    def test_invalid_or_missing_items_do_not_add_activity(self):
        history = self.events()
        for payload in ({'status': []}, {'status': 'deleted'}, {'note': 7},
                        {'status': 'resolved', 'note': 'x' * 2001}):
            self.assertEqual(self.client.patch(self.url, json=payload).status_code, 400)
        self.assertEqual(self.client.patch('/api/action-items/9999', json={'note': 'Missing'}).status_code, 404)
        self.assertEqual(self.events(), history)
        self.assertEqual(self.client.get('/api/action-items/9999/activity').status_code, 404)
        self.assertEqual(self.client.get('/api/action-items/999999999999999999999999/activity').status_code, 404)
        for query in ('limit=abc', 'before=abc', 'before=0', 'before=-1', 'before=99999999999999999999999'):
            self.assertEqual(self.client.get(self.url + '/activity?' + query).status_code, 400)

    def test_activity_reads_do_not_rescan_findings_or_change_notes_and_review_state(self):
        update_action_item(self.db, self.item_id, 'snoozed', note='Review after maintenance')
        before = self.item()
        with patch('apachewatch_app.routes.build_action_candidates') as builder:
            first = self.client.get(self.url + '/activity')
            restarted = create_app({'database': self.db}).test_client().get(self.url + '/activity')
        builder.assert_not_called()
        self.assertEqual(first.get_json(), restarted.get_json())
        self.assertEqual(self.item(), before)


if __name__ == '__main__':
    unittest.main()
