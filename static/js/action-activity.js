// A finding's saved timeline loads independently of the editable note.
window.ApacheWatchActivity = class {
    constructor() {
        this.list = document.getElementById('actionActivityList');
        this.status = document.getElementById('actionActivityStatus');
        this.more = document.getElementById('earlierActionActivity');
        this.disclosure = document.getElementById('actionActivityDisclosure');
        this.itemId = null;
        this.version = 0;
        this.disclosure.addEventListener('toggle', () => {
            if (this.disclosure.open) this.load();
            else this.cancel();
        });
        document.getElementById('refreshActionActivity').addEventListener('click', () => this.refresh());
        this.more.addEventListener('click', () => { if (!this.loading) this.load(true); });
        const dialog = document.getElementById('actionDialog');
        dialog.addEventListener('close', () => { if (!dialog.open) this.close(); });
    }

    cancel() {
        this.controller?.abort();
        this.version++;
        this.loading = false;
        this.list.setAttribute('aria-busy', 'false');
        this.status.textContent = 'Loading activity…';
    }

    close() {
        this.cancel();
        this.itemId = null;
    }

    open(itemId) {
        this.close();
        this.itemId = itemId;
        this.disclosure.open = false;
        this.nextBefore = null;
        this.list.replaceChildren();
        this.more.hidden = true;
        this.status.textContent = 'Loading activity…';
    }

    refresh(itemId = this.itemId) {
        if (itemId != null && itemId === this.itemId && this.disclosure.open) return this.load();
    }

    async load(append = false) {
        if (this.itemId == null || !this.disclosure.open || (append && !this.nextBefore)) return;
        this.controller?.abort();
        this.controller = new AbortController();
        const version = ++this.version;
        this.loading = true;
        this.more.disabled = true;
        this.list.setAttribute('aria-busy', 'true');
        this.status.textContent = 'Loading activity…';
        try {
            const params = new URLSearchParams({ limit: '10' });
            if (append) params.set('before', this.nextBefore);
            const response = await fetch(`/api/action-items/${this.itemId}/activity?${params}`, { signal: this.controller.signal });
            if (!response.ok) throw new Error('Unable to load activity. Try Refresh.');
            const data = await response.json();
            if (version !== this.version) return;
            if (!append) {
                this.list.replaceChildren();
                this.list.scrollTop = 0;
            }
            data.events.forEach(event => this.list.appendChild(this.renderEvent(event)));
            this.nextBefore = data.next_before;
            this.more.hidden = !this.nextBefore;
            this.status.textContent = data.total ? `Showing ${this.list.children.length} of ${data.total} events · Latest first` : 'No activity recorded yet.';
        } catch (error) {
            if (version === this.version && error.name !== 'AbortError') this.status.textContent = error.message;
        } finally {
            if (version === this.version) {
                this.loading = false;
                this.more.disabled = false;
                this.list.setAttribute('aria-busy', 'false');
            }
        }
    }

    date(value) {
        const date = new Date(value);
        return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Unknown time';
    }

    statusName(value) {
        return { new: 'Needs attention', acknowledged: 'In progress', snoozed: 'Later',
            resolved: 'Resolved', dismissed: 'Dismissed' }[value] || value;
    }

    renderEvent(event) {
        const details = event.details || {};
        let title = 'Finding updated';
        let description = '';
        let note;
        let noteLabel = 'View saved note';
        if (event.event_type === 'first_seen') title = 'Finding first seen';
        else if (event.event_type === 'tracking_started') {
            title = 'Activity tracking started';
            description = `Earlier changes weren’t recorded. Existing status: ${this.statusName(details.status)}.`;
            if (details.note) { note = details.note; noteLabel = 'View note at start'; }
        } else if (event.event_type === 'observation_changed') {
            title = details.observed ? 'Seen again in a monitoring check' : 'Not seen in the latest check';
        } else if (event.event_type === 'status_changed') {
            title = { acknowledged: 'Marked in progress', snoozed: 'Moved to Later',
                resolved: 'Marked resolved', dismissed: 'Dismissed', new: 'Returned to Needs attention' }[details.to_status] || title;
            description = `${this.statusName(details.from_status)} → ${this.statusName(details.to_status)}`;
            if (details.reason === 'review_due') {
                title = 'Review time reached';
                description = 'Returned from Later to Needs attention.';
            } else if (details.reason === 'finding_returned') {
                title = 'Finding returned and was reopened';
                description = 'Seen again after being marked resolved.';
            } else if (details.to_status === 'snoozed' && details.snoozed_until) {
                description = `Returns to Needs attention ${this.date(details.snoozed_until)}.`;
            }
        } else if (event.event_type === 'review_rescheduled') {
            title = 'Review time updated';
            description = `Review moved from ${this.date(details.previous_review_time)} to ${this.date(details.snoozed_until)}.`;
        } else if (event.event_type === 'note_changed') {
            title = !details.note ? 'Note cleared' : details.previous_note ? 'Note updated' : 'Note added';
            note = details.note || details.previous_note;
            if (!details.note) noteLabel = 'View previous note';
        }
        const row = document.createElement('li');
        row.dataset.eventId = event.id;
        const heading = document.createElement('strong');
        heading.textContent = title;
        const time = document.createElement('time');
        time.dateTime = event.occurred_at;
        time.textContent = this.date(event.occurred_at);
        row.append(heading, time);
        if (description) {
            const text = document.createElement('p');
            text.textContent = description;
            row.appendChild(text);
        }
        if (typeof note === 'string' && note) {
            const disclosure = document.createElement('details');
            const summary = document.createElement('summary');
            summary.textContent = `${noteLabel} ›`;
            const text = document.createElement('pre');
            text.textContent = note;
            disclosure.append(summary, text);
            row.appendChild(disclosure);
        }
        return row;
    }
};
