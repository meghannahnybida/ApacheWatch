// Resource details show recorded values without rendering a chart.
window.ApacheWatchResourceDetails = class {
    constructor() {
        this.dialog = document.getElementById('resourceDetailsDialog');
        this.readings = document.getElementById('resourceDetailsReadings');
        this.empty = document.getElementById('resourceDetailsEmpty');
        this.status = document.getElementById('resourceDetailsStatus');
        this.range = document.getElementById('resourceDetailsRange');
        this.insight = document.getElementById('resourceDetailsInsight');
        this.finding = document.getElementById('resourceDetailsFinding');
        this.names = { cpu: 'CPU', memory: 'Memory', disk: 'Disk' };
        this.version = 0;
        document.querySelectorAll('[data-resource-details]').forEach(button => {
            button.addEventListener('click', () => this.open(button.dataset.resourceDetails));
        });
        document.getElementById('closeResourceDetails').addEventListener('click', () => this.dialog.close());
        document.getElementById('refreshResourceDetails').addEventListener('click', () => this.load());
        this.range.addEventListener('change', () => this.load());
        this.dialog.addEventListener('close', () => { if (!this.dialog.open) this.reset(); });
    }

    reset() {
        this.request?.abort();
        this.version++;
    }

    open(resource) {
        if (!this.names[resource]) return;
        this.resource = resource;
        document.getElementById('resourceDetailsTitle').textContent = `${this.names[resource]} details`;
        const descriptions = { cpu:'Processor capacity in use', memory:'Physical memory in use', disk:'Disk space in use' };
        const icons = {
            cpu:'M7 7h10v10H7zM10 10h4v4h-4zM9 3v4m6-4v4M9 17v4m6-4v4M3 9h4m-4 6h4m10-6h4m-4 6h4',
            memory:'M3 6h18v12H3zM7 10v4m5-4v4m5-4v4M6 18v3m4-3v3m4-3v3m4-3v3',
            disk:'M20 6c0 2-3.6 3-8 3S4 8 4 6s3.6-3 8-3 8 1 8 3ZM4 6v12c0 2 3.6 3 8 3s8-1 8-3V6M4 12c0 2 3.6 3 8 3s8-1 8-3'
        };
        document.getElementById('resourceDetailsDescription').textContent = descriptions[resource];
        document.getElementById('resourceDetailsIconPath').setAttribute('d', icons[resource]);
        if (!this.dialog.open) this.dialog.showModal();
        this.load();
    }

    percent(value) {
        return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}%` : '—';
    }

    async load() {
        if (!this.dialog.open) return;
        this.reset();
        const version = this.version;
        this.request = new AbortController();
        this.readings.hidden = true;
        this.empty.hidden = false;
        this.empty.textContent = 'Loading readings…';
        this.finding.hidden = true;
        this.insight.textContent = '';
        this.status.textContent = '';
        this.dialog.setAttribute('aria-busy', 'true');
        try {
            const params = new URLSearchParams({ resource: this.resource, hours: this.range.value });
            const response = await fetch(`/api/resource-history?${params}`, { signal: this.request.signal });
            if (!response.ok) throw new Error('Unable to load readings. Choose Refresh to try again.');
            const data = await response.json();
            if (version !== this.version || !this.dialog.open) return;
            if (!data.samples) {
                this.empty.textContent = 'No recorded readings in this time range. Try another range.';
                return;
            }
            ['Latest', 'Average', 'Peak'].forEach(key => {
                document.getElementById(`resourceDetails${key}`).textContent = this.percent(data.summary[key.toLowerCase()]);
            });
            if (data.threshold) {
                const threshold = data.threshold;
                const count = threshold.readings_at_or_above;
                const subject = count ? `${count.toLocaleString()} of ${data.samples.toLocaleString()} recorded readings` : 'No recorded readings';
                const label = threshold.kind === 'alert' ? 'alert threshold' : 'high-usage guide';
                const off = threshold.kind === 'alert' && threshold.enabled === false ? ' (alerts off)' : '';
                this.insight.textContent = `${subject} reached the ${threshold.value}% ${label}${off}.`;
                this.finding.dataset.tone = count ? 'high' : 'low';
                document.getElementById('resourceDetailsFindingTitle').textContent = count
                    ? 'High readings recorded' : 'No high readings recorded';
                document.getElementById('resourceDetailsFindingIcon').setAttribute('d', count
                    ? 'M12 5v9m0 4v.01' : 'm5 12 4 4L19 6');
                this.finding.hidden = false;
            }
            const latest = new Date(data.summary.latest_at).toLocaleString(undefined, {
                month:'short', day:'numeric', hour:'numeric', minute:'2-digit', timeZoneName:'short'
            });
            this.status.textContent = `${data.samples.toLocaleString()} recorded ${data.samples === 1 ? 'reading' : 'readings'} · Latest ${latest}`;
            this.readings.hidden = false;
            this.empty.hidden = true;
        } catch (error) {
            if (version !== this.version || error.name === 'AbortError') return;
            this.empty.textContent = error.message;
        } finally {
            if (version === this.version) this.dialog.setAttribute('aria-busy', 'false');
        }
    }
};
