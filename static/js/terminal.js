// Original log text stays in text nodes, including when it contains HTML.
window.ApacheWatchTerminal = class {
    constructor({ output, follow, jump, status }) {
        Object.assign(this, { output, follow, jump, status });
        this.rows = new Map();
        this.following = true;
        this.unread = 0;
        this.characters = 0;
        this.requests = new Set();
        follow.addEventListener('click', () => this.setFollow(!this.following));
        jump.addEventListener('click', () => this.setFollow(true));
        output.addEventListener('scroll', () => {
            if (output.scrollHeight - output.clientHeight - output.scrollTop > 24) this.setFollow(false);
            else if (!this.following) this.setFollow(true);
        });
    }

    setFollow(enabled) {
        this.following = enabled;
        this.follow.setAttribute('aria-pressed', String(enabled));
        if (enabled) {
            this.unread = 0;
            this.output.scrollTop = this.output.scrollHeight;
        }
        this.updateStatus();
    }

    tokens(raw) {
        const spans = [];
        const access = raw.match(/^(\S+)(\s+\S+\s+\S+\s+)(\[[^\]]+\])(\s+")([A-Z]+)(\s+)(\S+)(\s+HTTP\/[\d.]+"\s+)(\d{3})(?=\s)/);
        if (access) {
            const status = Number(access[9]);
            const kinds = { 1: 'ip', 3: 'time', 5: 'method', 7: 'path',
                9: status >= 500 ? 'error' : status >= 400 ? 'warning' : status >= 300 ? 'info' : 'success' };
            let start = 0;
            for (let i = 1; i < access.length; i++) {
                if (kinds[i]) spans.push({ start, end: start + access[i].length, kind: kinds[i] });
                start += access[i].length;
            }
        } else {
            const error = raw.match(/^(\[[^\]]+\])(\s+)(\[(?:[\w.-]+:)?(emerg|alert|crit|error|warn(?:ing)?|notice|info|debug|trace[1-8])\])/i);
            if (error) {
                spans.push({ start: 0, end: error[1].length, kind: 'time' });
                const level = error[4].toLowerCase();
                const kind = /^(emerg|alert|crit|error)$/.test(level) ? 'error' : level.startsWith('warn') ? 'warning' : 'info';
                spans.push({ start: error[1].length + error[2].length, end: error[0].length, kind });
                const client = /\[(?:client|remote)\s+(?:\[[^\]]+\](?::\d+)?|[^\]]+)\]/i.exec(raw);
                if (client) spans.push({ start: client.index, end: client.index + client[0].length, kind: 'ip' });
            }
        }
        return spans;
    }

    textNode(raw) {
        const node = document.createElement('span');
        node.className = 'terminal-line-text';
        const terms = [...new Set(this.terms.filter(Boolean))].sort((a, b) => b.length - a.length);
        const tokens = this.tokens(raw);
        const matches = [];
        if (terms.length) {
            const expression = new RegExp(terms.map(term => term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'giu');
            for (const match of raw.matchAll(expression)) {
                matches.push({ start: match.index, end: match.index + match[0].length });
                if (matches.length === 500) break;
            }
        }
        if (!tokens.length && !matches.length) {
            node.textContent = raw;
            return node;
        }
        const points = [...new Set([0, raw.length, ...tokens.flatMap(span => [span.start, span.end]),
            ...matches.flatMap(span => [span.start, span.end])])].sort((a, b) => a - b);
        let tokenIndex = 0, matchIndex = 0;
        for (let i = 0; i < points.length - 1; i++) {
            const start = points[i], end = points[i + 1];
            while (tokens[tokenIndex]?.end <= start) tokenIndex++;
            while (matches[matchIndex]?.end <= start) matchIndex++;
            const highlighted = matches[matchIndex]?.start <= start;
            const token = tokens[tokenIndex]?.start <= start ? tokens[tokenIndex] : null;
            if (!highlighted && !token) node.append(document.createTextNode(raw.slice(start, end)));
            else {
                const span = document.createElement(highlighted ? 'mark' : 'span');
                if (!highlighted) span.className = `terminal-token-${token.kind}`;
                span.textContent = raw.slice(start, end);
                node.append(span);
            }
        }
        return node;
    }

    clear() {
        this.show({ terminal_lines: [] }, { terms: this.terms, filtered: this.filtered, live: this.live });
        this.cleared = true;
    }

    show(data, { append = false, terms = [], filtered = false, live = false } = {}) {
        const scrollTop = this.output.scrollTop;
        if (!append) {
            for (const request of this.requests) request.abort();
            this.requests.clear();
            this.rows.clear();
            this.output.replaceChildren();
            this.characters = this.unread = 0;
            this.trimmed = false;
            this.cleared = false;
            this.terms = terms;
            this.filtered = filtered;
        }
        this.live = live;
        let added = 0;
        for (const record of data.terminal_lines || []) {
            const previous = this.rows.get(record.offset);
            if (previous?.raw === record.raw) continue;
            const row = document.createElement('div');
            row.className = 'terminal-line';
            const main = document.createElement('div');
            main.className = 'terminal-line-main';
            main.append(this.textNode(record.raw));
            row.append(main);
            if (this.filtered) {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'terminal-context-button';
                button.textContent = 'Context';
                button.setAttribute('aria-label', `Show surrounding lines for: ${record.raw.slice(0, 120)}`);
                button.setAttribute('aria-expanded', 'false');
                const context = document.createElement('div');
                context.className = 'terminal-context';
                context.hidden = true;
                main.prepend(button);
                row.append(context);
                button.addEventListener('click', () => this.toggleContext(button, context, record, data));
            }
            if (previous) {
                this.characters -= previous.raw.length;
                previous.node.replaceWith(row);
            } else {
                this.output.append(row);
                added++;
            }
            this.rows.set(record.offset, { raw: record.raw, node: row });
            this.characters += record.raw.length;
        }
        let removedHeight = 0;
        while (this.rows.size > 5000 || this.characters > 2 * 1024 * 1024) {
            const [offset, record] = this.rows.entries().next().value;
            removedHeight += record.node.getBoundingClientRect().height;
            record.node.remove();
            this.characters -= record.raw.length;
            this.rows.delete(offset);
            this.trimmed = true;
        }
        if (append && !this.following) this.unread += added;
        if (this.rows.size) this.cleared = false;
        this.output.hidden = false;
        this.output.scrollTop = this.following ? this.output.scrollHeight : Math.max(0, scrollTop - removedHeight);
        this.updateStatus();
    }

    async toggleContext(button, context, record, data) {
        const expanded = button.getAttribute('aria-expanded') === 'true';
        button.setAttribute('aria-expanded', String(!expanded));
        context.hidden = expanded;
        if (expanded || context.dataset.loaded) return;
        const controller = new AbortController();
        this.requests.add(controller);
        button.disabled = true;
        context.textContent = 'Loading surrounding lines…';
        try {
            const params = new URLSearchParams({ source: data.source, snapshot: data.snapshot, offset: record.offset });
            const response = await fetch(`/api/log-context?${params}`, { signal: controller.signal });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Unable to read surrounding lines.');
            if (!this.output.contains(context)) return;
            context.replaceChildren();
            const label = document.createElement('div');
            label.className = 'terminal-context-label';
            label.textContent = 'Up to 3 lines before and after · surrounding lines ignore filters';
            context.append(label);
            for (const line of result.lines) {
                const node = document.createElement('div');
                node.className = line.offset === record.offset ? 'terminal-context-match' : 'terminal-context-line';
                node.append(this.textNode(line.raw));
                context.append(node);
            }
            context.dataset.loaded = 'true';
        } catch (error) {
            if (error.name !== 'AbortError') context.textContent = error.message;
        } finally {
            button.disabled = false;
            this.requests.delete(controller);
        }
    }

    updateStatus() {
        this.jump.hidden = this.following || !this.unread;
        this.jump.textContent = `${this.unread.toLocaleString()} new ${this.unread === 1 ? 'line' : 'lines'} ↓`;
        this.status.textContent = `${this.rows.size.toLocaleString()} ${this.rows.size === 1 ? 'line' : 'lines'} · ${this.live ? 'Live · 5s' : 'Paused'}${this.trimmed ? ' · Oldest output released; search to revisit' : ''}`;
    }
};
