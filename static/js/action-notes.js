// Save finding notes independently of workflow actions, retaining failed drafts.
window.ApacheWatchNotes = class {
    constructor({ field, status, button, dialog, onSaved }) {
        Object.assign(this, { field, status, button, onSaved });
        this.states = new Map();
        this.current = null;
        this.busy = false;
        field.addEventListener('input', () => {
            const state = this.current;
            if (!state) return;
            state.value = field.value;
            state.failed = false;
            this.keepDraft(state);
            this.render(state);
            clearTimeout(state.timer);
            state.timer = setTimeout(() => this.flush(state), 500);
        });
        field.addEventListener('blur', () => this.flush());
        button.addEventListener('click', () => this.flush());
        dialog.addEventListener('close', () => this.flush());
        window.addEventListener('pagehide', () => {
            this.states.forEach(state => this.flush(state));
        });
    }

    open(item) {
        let state = this.states.get(item.id);
        if (!state) {
            const server = document.querySelector('.eyebrow').textContent.trim();
            const key = `apachewatch.noteDraft:${server}:${item.source_key || item.id}:${item.id}`;
            let draft;
            try {
                draft = JSON.parse(localStorage.getItem(key));
            } catch (_) { /* An unavailable draft store does not prevent server saves. */ }
            state = {
                id: item.id, key, savedValue: item.note || '',
                value: typeof draft?.value === 'string' && draft.value.length <= 2000 ? draft.value : item.note || '',
                saving: false, failed: false, hasSaved: false, draftKept: false,
                timer: null, promise: null
            };
            this.states.set(item.id, state);
            this.keepDraft(state);
        }
        this.current = state;
        this.field.value = state.value;
        this.render(state);
        if (state.value !== state.savedValue) this.flush(state);
    }

    keepDraft(state) {
        try {
            if (state.value === state.savedValue) {
                localStorage.removeItem(state.key);
                state.draftKept = false;
            } else {
                localStorage.setItem(state.key, JSON.stringify({ value: state.value }));
                state.draftKept = true;
            }
        } catch (_) {
            state.draftKept = false;
        }
    }

    render(state = this.current) {
        if (!state || state !== this.current) return;
        this.status.classList.toggle('note-save-error', state.failed);
        this.status.textContent = state.saving ? 'Saving…'
            : state.failed ? (state.draftKept ? 'Couldn’t save. Draft kept in this browser.' : 'Couldn’t save. Keep this window open and retry.')
            : state.value !== state.savedValue ? 'Unsaved changes…'
            : state.hasSaved ? 'Saved' : 'Notes save automatically.';
        this.button.hidden = !state.failed;
        this.button.disabled = this.busy || state.saving || state.value === state.savedValue;
    }

    setBusy(busy) {
        this.busy = busy;
        this.field.disabled = busy;
        this.render();
    }

    flush(state = this.current) {
        if (!state) return Promise.resolve(true);
        clearTimeout(state.timer);
        if (state.promise) return state.promise;
        if (state.value === state.savedValue) return Promise.resolve(true);
        state.promise = this.save(state);
        return state.promise;
    }

    async save(state) {
        state.failed = false;
        state.saving = true;
        this.render(state);
        try {
            // Serialize writes per finding so older requests cannot erase newer text.
            while (state.value !== state.savedValue) {
                const value = state.value;
                const response = await fetch(`/api/action-items/${state.id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ note: value }),
                    keepalive: true
                });
                if (!response.ok) throw new Error('Unable to save note');
                state.savedValue = value;
                state.hasSaved = true;
                this.onSaved(state.id, value);
                this.keepDraft(state);
            }
            return true;
        } catch (_) {
            state.failed = true;
            this.keepDraft(state);
            return false;
        } finally {
            state.saving = false;
            state.promise = null;
            this.render(state);
        }
    }
};
