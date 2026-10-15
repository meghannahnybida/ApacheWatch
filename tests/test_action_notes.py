import tempfile
import unittest
from pathlib import Path

from apachewatch_app import create_app
from apachewatch_app.actions import get_action_items, sync_action_items, update_action_item


class ActionNoteTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db_path = str(Path(directory.name) / 'notes.db')
        self.app = create_app({'database': self.db_path})
        self.client = self.app.test_client()
        self.candidate = {
            'source': 'alert', 'source_key': 'alert:disk_percent',
            'severity': 'critical', 'title': 'Disk usage is above threshold',
            'summary': 'Disk usage is 91%', 'evidence': {'value': 91},
        }
        sync_action_items(self.db_path, [self.candidate])
        self.item_id = self.item()['id']
        self.url = f'/api/action-items/{self.item_id}'

    def item(self):
        return get_action_items(self.db_path, status='all')[0][0]

    def test_note_saves_without_status_and_survives_evidence_refresh(self):
        note = 'Checking disk cleanup.\nAssigned to Meghan — <keep this text>.'
        response = self.client.patch(self.url, json={'note': note})
        self.assertEqual(response.status_code, 200)
        self.candidate['summary'] = 'Disk usage is 94%'
        sync_action_items(self.db_path, [self.candidate])
        item = self.item()
        self.assertEqual(item['note'], note)
        self.assertEqual(item['status'], 'new')
        self.assertEqual(item['summary'], 'Disk usage is 94%')
        # A new app connection reads the same saved note.
        self.assertEqual(get_action_items(self.db_path, status='all')[0][0]['note'], note)

    def test_note_edit_preserves_later_status_and_exact_return_time(self):
        update_action_item(self.db_path, self.item_id, 'snoozed', snooze_minutes=240)
        before = self.item()
        response = self.client.patch(self.url, json={'note': 'Review after maintenance.'})
        self.assertEqual(response.status_code, 200)
        after = self.item()
        self.assertEqual(after['note'], 'Review after maintenance.')
        self.assertEqual(after['status'], 'snoozed')
        self.assertEqual(after['snoozed_until'], before['snoozed_until'])

    def test_empty_note_clears_text_and_preserves_resolved_status(self):
        update_action_item(self.db_path, self.item_id, 'resolved', note='Old note')
        self.assertEqual(self.client.patch(self.url, json={'note': ''}).status_code, 200)
        item = self.item()
        self.assertEqual(item['note'], '')
        self.assertEqual(item['status'], 'resolved')

    def test_invalid_note_does_not_replace_saved_text(self):
        self.client.patch(self.url, json={'note': 'Keep this note'})
        for value in (None, 42, True, [], {}, 'x' * 2001):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(self.client.patch(self.url, json={'note': value}).status_code, 400)
                self.assertEqual(self.item()['note'], 'Keep this note')
        self.assertEqual(self.client.patch('/api/action-items/99999', json={'note': 'Missing finding'}).status_code, 404)
        self.assertEqual(self.client.patch(self.url, json={}).status_code, 400)


if __name__ == '__main__':
    unittest.main()
