// Viewer actions only: commands never execute on the server or in a shell.
window.ApacheWatchTerminalTools = class {
    constructor({ viewer, onSearch, onToggleLive, onTail, onClear, getFilename }) {
        Object.assign(this, { viewer, onSearch, onToggleLive, onTail, onClear, getFilename });
        this.root = document.getElementById('rawLogEntries');
        this.dialog = document.getElementById('terminalFullscreenDialog');
        this.findForm = document.getElementById('terminalFindForm');
        this.findInput = document.getElementById('terminalFindInput');
        this.commandForm = document.getElementById('terminalCommandForm');
        this.commandInput = document.getElementById('terminalCommandInput');
        this.notice = document.getElementById('terminalNotice');
        this.noticeText = document.getElementById('terminalNoticeText');
        this.history = [];
        this.historyIndex = 0;
        this.draft = '';
        document.getElementById('terminalFindToggle').addEventListener('click', () => this.toggleForm('find'));
        document.getElementById('terminalLive').addEventListener('click', () => onToggleLive());
        document.getElementById('terminalCommandsToggle').addEventListener('click', () => this.toggleForm('commands'));
        this.findInput.addEventListener('input', () => onSearch(this.findInput.value, false));
        this.findForm.addEventListener('submit', event => {
            event.preventDefault();
            onSearch(this.findInput.value, true);
        });
        document.getElementById('terminalFindClear').addEventListener('click', () => {
            this.findInput.value = '';
            onSearch('', true);
            this.findInput.focus();
        });
        document.getElementById('terminalWrap').addEventListener('click', () => this.setWrap(!this.root.classList.contains('terminal-wrap')));
        document.getElementById('terminalCopy').addEventListener('click', () => this.copy());
        document.getElementById('terminalDownload').addEventListener('click', () => this.download());
        document.getElementById('terminalFullscreen').addEventListener('click', () => this.toggleFullscreen());
        document.getElementById('terminalShortcuts').addEventListener('click', () => this.showShortcuts());
        document.getElementById('terminalNoticeDismiss').addEventListener('click', () => this.message(''));
        this.dialog.addEventListener('close', () => {
            this.placeholder.replaceWith(this.root);
            this.placeholder = null;
            this.fullscreenButton(false);
            document.getElementById('terminalFullscreen').focus({ preventScroll: true });
            if (viewer.following) viewer.setFollow(true);
        });
        this.root.addEventListener('keydown', event => this.keydown(event));
        this.commandForm.addEventListener('submit', event => {
            event.preventDefault();
            this.execute(this.commandInput.value);
        });
        this.commandInput.addEventListener('keydown', event => this.navigateHistory(event));
        this.commandInput.addEventListener('input', () => {
            this.historyIndex = this.history.length;
            this.draft = this.commandInput.value;
        });
        this.setWrap(localStorage.getItem('terminalWrap') === 'true');
    }

    syncSearch(value) {
        if (this.findInput.value !== value) this.findInput.value = value;
    }

    toggleForm(kind, open) {
        const find = kind === 'find';
        const form = find ? this.findForm : this.commandForm;
        const input = find ? this.findInput : this.commandInput;
        const button = document.getElementById(find ? 'terminalFindToggle' : 'terminalCommandsToggle');
        open = open ?? form.hidden;
        form.hidden = !open;
        button.setAttribute('aria-expanded', String(open));
        if (open) {
            const other = find ? this.commandForm : this.findForm;
            other.hidden = true;
            document.getElementById(find ? 'terminalCommandsToggle' : 'terminalFindToggle').setAttribute('aria-expanded', 'false');
            input.focus();
            if (find) input.select();
        } else this.viewer.output.focus({ preventScroll: true });
    }

    setWrap(enabled) {
        this.root.classList.toggle('terminal-wrap', enabled);
        document.getElementById('terminalWrap').setAttribute('aria-pressed', String(enabled));
        localStorage.setItem('terminalWrap', String(enabled));
        if (this.viewer.following) this.viewer.setFollow(true);
    }

    message(text) {
        this.noticeText.textContent = text;
        this.notice.hidden = !text;
    }

    rawOutput() {
        const lines = [...this.viewer.rows.values()].map(record => record.raw);
        return lines.length ? lines.join('\n') + '\n' : '';
    }

    async copy() {
        if (!this.viewer.rows.size) return this.message('There are no displayed log lines to copy.');
        try {
            await navigator.clipboard.writeText(this.rawOutput());
            this.message('Copied displayed log lines.');
        } catch {
            this.message('Clipboard access is unavailable. Use Download to save the displayed lines.');
        }
    }

    download() {
        if (!this.viewer.rows.size) return this.message('There are no displayed log lines to download.');
        const blob = new Blob([this.rawOutput()], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        const filename = this.getFilename().replace(/[^\w.-]/g, '_').replace(/\.log$/i, '');
        link.href = url;
        link.download = `${filename}-view.log`;
        this.root.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        this.message('Downloaded displayed log lines.');
    }

    toggleFullscreen() {
        if (this.dialog.open) return this.dialog.close();
        this.placeholder = document.createComment('Terminal location');
        this.root.before(this.placeholder);
        this.dialog.append(this.root);
        this.dialog.showModal();
        this.fullscreenButton(true);
        this.viewer.output.focus({ preventScroll: true });
        if (this.viewer.following) this.viewer.setFollow(true);
    }

    fullscreenButton(enabled) {
        const button = document.getElementById('terminalFullscreen');
        button.textContent = enabled ? 'Exit fullscreen' : 'Fullscreen';
        button.setAttribute('aria-pressed', String(enabled));
    }

    showShortcuts() {
        this.message('/  Find in this log\nSpace  Pause / resume live (when output is focused)\nHome / End  First / latest displayed line (when output is focused)\nW  Toggle line wrapping\nF  Enter / exit fullscreen\n:  Open viewer commands\n↑ / ↓  Command history (in command input)\nEsc  Close search, commands, or fullscreen\n?  Show shortcuts\n\nShortcuts apply while the terminal is focused.');
    }

    keydown(event) {
        if (event.defaultPrevented || event.isComposing || event.ctrlKey || event.metaKey || event.altKey) return;
        const editing = event.target.matches('input, textarea, select, [contenteditable="true"]');
        if (event.key === 'Escape') {
            if (!this.findForm.hidden || !this.commandForm.hidden || !this.notice.hidden) {
                event.preventDefault();
                this.toggleForm('find', false);
                this.toggleForm('commands', false);
                this.message('');
            }
            return;
        }
        if (editing) return;
        let handled = true;
        switch (event.key) {
            case '/': this.toggleForm('find', true); break;
            case ':': this.toggleForm('commands', true); break;
            case 'f': case 'F': this.toggleFullscreen(); break;
            case 'w': case 'W': this.setWrap(!this.root.classList.contains('terminal-wrap')); break;
            case '?': this.showShortcuts(); break;
            case ' ':
                if (event.target === this.viewer.output) this.onToggleLive();
                else handled = false;
                break;
            case 'End':
                if (event.target === this.viewer.output) this.viewer.setFollow(true);
                else handled = false;
                break;
            case 'Home':
                if (event.target === this.viewer.output) {
                    this.viewer.setFollow(false);
                    this.viewer.output.scrollTop = 0;
                } else handled = false;
                break;
            default: handled = false;
        }
        if (handled) event.preventDefault();
    }

    navigateHistory(event) {
        if (event.isComposing || !['ArrowUp', 'ArrowDown'].includes(event.key) || !this.history.length) return;
        event.preventDefault();
        if (this.historyIndex === this.history.length) this.draft = this.commandInput.value;
        this.historyIndex = Math.max(0, Math.min(this.history.length, this.historyIndex + (event.key === 'ArrowUp' ? -1 : 1)));
        this.commandInput.value = this.historyIndex === this.history.length ? this.draft : this.history[this.historyIndex];
        this.commandInput.setSelectionRange(this.commandInput.value.length, this.commandInput.value.length);
    }

    execute(command) {
        command = command.trim();
        if (!command) return;
        if (this.history.at(-1) !== command) this.history.push(command);
        if (this.history.length > 50) this.history.shift();
        this.historyIndex = this.history.length;
        this.commandInput.value = this.draft = '';
        const [, verb, args = ''] = command.match(/^(\S+)(?:\s+([\s\S]*))?$/);
        try {
            if (verb === 'help' && !args) {
                this.message('Log viewer commands\n\ntail [error|access] [-n 10|20|50|100|500] [-f]\n  Reset filters and show the latest lines. -f watches live.\nfind <text>\n  Search literal text with the current filters. Quotes around text are optional.\nfind ""\n  Clear the text search; other filters stay active.\nclear\n  Clear displayed output in this browser. Log files stay intact.\nhelp\n  Show these commands.\n\nUse ↑ / ↓ for this tab’s command history.');
            } else if (verb === 'find') {
                if (!args) return this.toggleForm('find', true);
                const quoted = args.length >= 2 && ((args.startsWith('"') && args.endsWith('"')) || (args.startsWith("'") && args.endsWith("'")));
                const query = quoted ? args.slice(1, -1) : args;
                if (query.length > 1000) throw new Error('Search text must be 1,000 characters or fewer.');
                this.onSearch(query, true);
                this.message(query ? 'Searching this log with the current filters.' : 'Text search cleared. Other filters stay active.');
            } else if (verb === 'clear' && !args) {
                this.onClear();
                this.message('Displayed output cleared. Log files stay intact; Refresh reloads saved lines.');
            } else if (verb === 'tail') {
                const tokens = args ? args.split(/\s+/) : [];
                let source, limit, live = false, options = true;
                for (let i = 0; i < tokens.length; i++) {
                    const token = tokens[i];
                    if (options && token === '--') options = false;
                    else if (options && token === '-f') live = true;
                    else if (options && token === '-n' && limit === undefined) {
                        limit = tokens[++i];
                        if (!['10', '20', '50', '100', '500'].includes(limit)) throw new Error('Choose -n 10, 20, 50, 100, or 500.');
                    } else if (/^(error|access)(\.log)?$/.test(token) && source === undefined) source = token.replace(/\.log$/, '');
                    else throw new Error('Use tail [error|access] [-n 10|20|50|100|500] [-f].');
                }
                this.onTail({ source, limit, live });
                this.message(live ? 'Watching the latest log output. Filters reset.' : 'Loading the latest log output. Live paused; filters reset.');
            } else throw new Error('Unknown viewer command. Type help for available commands.');
        } catch (error) {
            this.message(error.message);
        }
    }
};
