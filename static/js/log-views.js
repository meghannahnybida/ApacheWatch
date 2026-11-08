window.ApacheWatchSavedLogViews = class {
    constructor({ getState, applyState }) {
        Object.assign(this, { getState, applyState });
        this.root = document.getElementById('savedLogViewsPanel');
        this.select = document.getElementById('savedLogViewSelect');
        this.form = document.getElementById('savedLogViewForm');
        this.name = document.getElementById('savedLogViewName');
        this.status = document.getElementById('savedLogViewStatus');
        this.retry = document.getElementById('retryLogViews');
        this.confirm = document.getElementById('confirmDeleteLogView');
        this.items = [];
        this.selectedId = null;
        this.available = false;
        document.getElementById('saveLogView').addEventListener('click', () => this.edit(false));
        document.getElementById('editLogView').addEventListener('click', () => this.edit(true));
        document.getElementById('cancelLogView').addEventListener('click', () => this.closeForm());
        document.getElementById('deleteLogView').addEventListener('click', () => {
            this.confirm.hidden = false;
            document.getElementById('deleteLogViewPrompt').textContent = `Delete “${this.items.find(item => item.id === this.editId).name}”? Your current filters will stay open.`;
            document.getElementById('removeLogView').focus();
        });
        document.getElementById('keepLogView').addEventListener('click', () => {
            this.confirm.hidden = true;
            document.getElementById('deleteLogView').focus();
        });
        document.getElementById('removeLogView').addEventListener('click', () => this.remove());
        this.form.addEventListener('submit', event => { event.preventDefault(); this.save(); });
        this.form.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !this.busy) {
                event.preventDefault();
                this.closeForm();
            }
        });
        this.select.addEventListener('change', () => this.open());
        this.retry.addEventListener('click', () => this.load());
        this.load();
    }

    message(text, error = false) {
        this.status.textContent = text;
        this.status.classList.toggle('is-error', error);
    }

    setBusy(busy) {
        this.busy = busy;
        this.root.setAttribute('aria-busy', String(busy));
        for (const control of this.root.querySelectorAll('button, input')) control.disabled = busy || !this.available;
        this.retry.disabled = busy;
        this.select.disabled = busy || !this.available || !this.items.length;
        document.getElementById('savedLogViewPicker').hidden = !this.available || !this.items.length;
        this.root.classList.toggle('is-empty', this.available && !this.items.length);
        const edit = document.getElementById('editLogView');
        edit.disabled = busy || !this.selectedId || !this.available;
        edit.hidden = !this.selectedId || !this.available;
    }

    async request(url, options) {
        const response = await fetch(url, options);
        if (response.status === 204) return null;
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to access saved views. Try again.');
        return data;
    }

    async load() {
        this.setBusy(true);
        this.message('Loading saved views…');
        try {
            const data = await this.request('/api/log-views');
            this.items = data.views;
            this.available = true;
            this.retry.hidden = true;
            if (!this.items.some(item => item.id === this.selectedId)) {
                this.selectedId = null;
                this.form.hidden = true;
            }
            this.render();
            this.message(this.items.length ? 'Saved for this server · views reopen paused.' : 'Save a view to reopen these filters in one click.');
        } catch (error) {
            this.available = false;
            this.retry.hidden = false;
            this.message(error.message, true);
            this.select.replaceChildren(new Option('Saved views unavailable', ''));
        } finally {
            this.setBusy(false);
        }
    }

    render() {
        const placeholder = new Option('Choose a saved view', '');
        placeholder.disabled = true;
        placeholder.hidden = true;
        this.select.replaceChildren(placeholder);
        this.items.sort((a, b) => a.name.localeCompare(b.name));
        for (const item of this.items) this.select.append(new Option(item.name, String(item.id)));
        this.select.value = this.selectedId === null ? '' : String(this.selectedId);
        this.setBusy(this.busy);
    }

    open() {
        this.selectedId = Number(this.select.value) || null;
        const item = this.items.find(item => item.id === this.selectedId);
        this.form.hidden = true;
        this.setBusy(false);
        if (!item) return this.message('Save filters you use often. Views reopen paused.');
        this.applying = true;
        try {
            this.applyState(item.state);
            this.modified = false;
            this.message(`Opened “${item.name}” · live updates paused.`);
        } finally {
            this.applying = false;
        }
    }

    sync() {
        if (this.applying || this.busy || !this.form.hidden) return;
        const item = this.items.find(item => item.id === this.selectedId);
        if (!item) return;
        const current = this.getState();
        const modified = Object.keys(item.state).some(key => item.state[key] !== current[key]);
        if (modified === this.modified) return;
        this.modified = modified;
        this.select.value = modified ? '' : String(item.id);
        this.message(modified ? `Filters changed from “${item.name}”. Use Edit view to save the changes.` : `Using “${item.name}”.`);
    }

    edit(existing) {
        const item = existing ? this.items.find(item => item.id === this.selectedId) : null;
        this.editId = item?.id ?? null;
        this.name.value = item?.name || '';
        document.getElementById('submitLogView').textContent = item ? 'Update view' : 'Save view';
        document.getElementById('deleteLogView').hidden = !item;
        this.confirm.hidden = true;
        this.form.hidden = false;
        this.name.focus();
        this.name.select();
    }

    closeForm() {
        this.form.hidden = true;
        this.confirm.hidden = true;
        document.getElementById(this.editId ? 'editLogView' : 'saveLogView').focus();
        this.sync();
    }

    async save() {
        if (this.busy) return;
        this.setBusy(true);
        const updating = this.editId !== null;
        try {
            const data = await this.request(updating ? `/api/log-views/${this.editId}` : '/api/log-views', {
                method: updating ? 'PATCH' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: this.name.value, state: this.getState() }),
            });
            this.items = this.items.filter(item => item.id !== data.view.id);
            this.items.push(data.view);
            this.selectedId = data.view.id;
            this.modified = false;
            this.form.hidden = true;
            this.render();
            this.message(`${updating ? 'Updated' : 'Saved'} “${data.view.name}”. Choose it from Saved views to reopen it.`);
        } catch (error) {
            this.message(error.message, true);
        } finally {
            this.setBusy(false);
            this.sync();
            if (this.form.hidden) this.select.focus();
        }
    }

    async remove() {
        if (this.busy || this.editId === null) return;
        this.setBusy(true);
        try {
            await this.request(`/api/log-views/${this.editId}`, { method: 'DELETE' });
            this.items = this.items.filter(item => item.id !== this.editId);
            this.selectedId = null;
            this.form.hidden = true;
            this.confirm.hidden = true;
            this.render();
            this.message('Saved view deleted. Your current filters are unchanged.');
        } catch (error) {
            this.retry.hidden = false;
            this.message(error.message, true);
        } finally {
            this.setBusy(false);
            if (this.form.hidden) document.getElementById('saveLogView').focus();
        }
    }
};
