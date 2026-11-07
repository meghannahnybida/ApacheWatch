// Search server-side pages without losing the selected snapshot or accepting stale responses.
window.ApacheWatchLogSearch = class {
    constructor({ getParams, onResult, onStream, onError, onBrowse }) {
        Object.assign(this, { getParams, onResult, onStream, onError, onBrowse });
        this.pages = [];
        this.index = -1;
        this.loading = false;
        this.version = 0;
        this.status = document.getElementById('logSearchStatus');
        this.previous = document.getElementById('newerLogResults');
        this.next = document.getElementById('olderLogResults');
        this.cancelButton = document.getElementById('cancelLogSearch');
        this.previous.addEventListener('click', () => {
            if (this.index <= 0 || this.loading) return;
            this.onBrowse();
            this.index--;
            this.showPage();
        });
        this.next.addEventListener('click', () => {
            if (this.loading) return;
            this.onBrowse();
            if (this.index + 1 < this.pages.length) {
                this.index++;
                this.showPage();
            } else if (this.pages[this.index]?.next_cursor) this.load(this.pages[this.index].next_cursor);
        });
        this.cancelButton.addEventListener('click', () => {
            this.abort();
            this.onBrowse();
            this.status.textContent = 'Search stopped. Refresh to try again.';
        });
        document.getElementById('refreshLogSearch').addEventListener('click', () => this.search());
        this.controls();
    }

    abort() {
        clearTimeout(this.timer);
        this.controller?.abort();
        this.version++;
        this.loading = false;
        this.controls();
    }

    controls() {
        this.previous.disabled = this.loading || this.index <= 0;
        this.next.disabled = this.loading || !(this.index + 1 < this.pages.length || this.pages[this.index]?.next_cursor);
        this.cancelButton.hidden = !this.loading;
        document.getElementById('logResults').setAttribute('aria-busy', String(this.loading));
    }

    schedule() {
        this.abort();
        this.loading = true;
        this.controls();
        this.status.textContent = 'Searching…';
        this.timer = setTimeout(() => this.search(), 350);
    }

    search() {
        this.abort();
        this.streamCursor = null;
        this.pages = [];
        this.index = -1;
        this.params = this.getParams();
        return this.load();
    }

    async poll() {
        if (this.loading || !this.streamCursor) return false;
        this.loading = true;
        this.controller = new AbortController();
        const version = this.version;
        try {
            const params = new URLSearchParams({ ...this.params, cursor: this.streamCursor });
            const response = await fetch(`/api/log-stream?${params}`, { signal: this.controller.signal });
            const data = await response.json();
            if (version !== this.version) return false;
            if (!response.ok) throw new Error(data.error || 'Unable to read new log lines.');
            this.streamCursor = data.stream_cursor;
            this.onStream(data);
            return data.has_more;
        } catch (error) {
            if (version !== this.version || error.name === 'AbortError') return false;
            this.onBrowse();
            this.status.textContent = `${error.message} Live updates paused; output retained.`;
        } finally {
            if (version === this.version) {
                this.loading = false;
                this.controls();
            }
        }
        return false;
    }

    async load(cursor = '') {
        const olderPage = Boolean(cursor);
        this.loading = true;
        this.controls();
        this.status.textContent = 'Searching log…';
        this.controller = new AbortController();
        const version = this.version;
        let scanned = 0;
        try {
            let data;
            do {
                const params = new URLSearchParams(this.params);
                if (cursor) params.set('cursor', cursor);
                const response = await fetch(`/api/log-search?${params}`, { signal: this.controller.signal });
                data = await response.json();
                if (version !== this.version) return;
                if (!response.ok) throw new Error(data.error || 'Unable to search this log.');
                scanned += data.scanned_lines;
                cursor = data.next_cursor;
                this.status.textContent = `Searching older entries… ${scanned.toLocaleString()} lines checked`;
            } while (!data.count && cursor);
            if (version !== this.version) return;
            if (olderPage && !data.count) {
                this.pages[this.index].next_cursor = null;
                this.showPage();
                return;
            }
            this.pages.push(data);
            this.index = this.pages.length - 1;
            this.showPage();
        } catch (error) {
            if (version !== this.version || error.name === 'AbortError') return;
            this.status.textContent = error.message;
            this.onError(error.message);
        } finally {
            if (version === this.version) {
                this.loading = false;
                this.controls();
            }
        }
    }

    showPage() {
        const data = this.pages[this.index];
        this.streamCursor = data.stream_cursor;
        this.onResult(data);
        const count = `${data.count} matching ${data.count === 1 ? 'line' : 'lines'}`;
        this.status.textContent = `${count} · Page ${this.index + 1}${data.next_cursor ? '' : ' · End of log'}`;
        if (data.unparsed_count) this.status.textContent += ` · ${data.unparsed_count} unrecognized; view in Terminal`;
        this.controls();
    }
};
