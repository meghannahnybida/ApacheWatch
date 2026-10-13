let tailInterval = null;
const liveLogButton = document.getElementById('liveLogButton');
const logEntries = document.getElementById('logEntries');
const rawLogEntries = document.getElementById('rawLogEntries');
const terminalOutput = document.getElementById('terminalOutput');
const terminalMessage = document.getElementById('terminalMessage');
const terminalFollow = document.getElementById('terminalFollow');
let terminalFollowEnabled = true;
let terminalError = '';
let terminalFilename = 'error.log';
const accessLogEntries = document.getElementById('accessLogEntries');
const accessSummary = document.getElementById('accessSummary');
const errorLogFilters = document.getElementById('errorLogFilters');
const accessLogFilters = document.getElementById('accessLogFilters');
const logLimit = document.getElementById('logLimit');
const logSearch = document.getElementById('logSearch');
let currentLogs = []; // Incident groups currently loaded
let currentRawLogs = [];
let currentAccessLogs = [];
let currentAccessSummary = {};
let activeAccessStatus = 'all';
const initialErrorLevel = new URLSearchParams(window.location.search).get('level') || '';
let activeErrorLevel = ['', 'error', 'warn', 'notice', 'info'].includes(initialErrorLevel) ? initialErrorLevel : '';
const savedLogView = localStorage.getItem('logView');
let activeLogFormat = localStorage.getItem('logFormat') === 'terminal' || (!localStorage.getItem('logFormat') && savedLogView === 'raw') ? 'terminal' : 'formatted';
let activeLogSource = localStorage.getItem('logSource') === 'access' || savedLogView === 'access' ? 'access' : 'error';
let activeLogView = activeLogFormat === 'terminal' ? 'raw' : activeLogSource === 'access' ? 'access' : 'grouped';
let liveRefreshEnabled = false;
const logRequestIds = { grouped: 0, raw: 0, access: 0 };

function readJSON(response) {
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response.json();
}

document.querySelector('.skip-link').addEventListener('click', event => {
    event.preventDefault();
    document.getElementById('mainContent').focus();
});

const viewMeta = {
    overview: ['Overview', 'Server health and findings that need your attention.'],
    actions: ['Action Center', 'Review findings, track progress, and resolve issues.'],
    logs: ['Log Explorer', 'Find the requests and errors behind an issue.'],
    security: ['Security', 'Review suspicious traffic and suggested rules before taking action.'],
    analytics: ['Analytics', 'Understand traffic volume, response status, and visitors.']
};

function showView(viewName) {
    const selected = viewMeta[viewName] ? viewName : 'overview';
    document.querySelectorAll('[data-view]').forEach(view => {
        const active = view.dataset.view === selected;
        view.hidden = !active;
        view.classList.toggle('active', active);
    });
    document.querySelectorAll('[data-view-link]').forEach(link => {
        const active = link.dataset.viewLink === selected;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
    });
    document.getElementById('view-title').textContent = viewMeta[selected][0];
    document.getElementById('view-description').textContent = viewMeta[selected][1];
    document.title = `${viewMeta[selected][0]} · ApacheWatch`;
    // Keep every section at the top when navigating from a long list.
    window.scrollTo({ top: 0, behavior: 'instant' });

    if (selected === 'analytics') {
        requestAnimationFrame(() => {
            Object.values(charts).forEach(chart => {
                if (chart) chart.resize();
            });
        });
    }
}

function syncViewFromHash() {
    const requested = window.location.hash.slice(1).toLowerCase();
    showView(requested === 'incidents' ? 'logs' : requested || 'overview');
}

window.addEventListener('hashchange', syncViewFromHash);

const savedLogLimit = localStorage.getItem('logLimit');
if (Array.from(logLimit.options).some(option => option.value === savedLogLimit)) {
    logLimit.value = savedLogLimit;
}

setLogSource(activeLogSource);
fetchLogs();

if (localStorage.getItem('tailMode') === 'true') {
    setLogView('raw');
    startTailMode();
}

liveLogButton.addEventListener('click', function() {
    if (liveRefreshEnabled) {
        stopTailMode();
    } else {
        setLogView('raw');
        startTailMode();
    }
});

logLimit.addEventListener('change', function() {
    localStorage.setItem('logLimit', this.value);
    fetchActiveLogData();
});

logSearch.addEventListener('input', function() {
    renderActiveLogView();
});

document.querySelectorAll('[data-log-source]').forEach(button => {
    button.addEventListener('click', () => setLogSource(button.dataset.logSource));
});

document.querySelectorAll('[data-log-format]').forEach(button => {
    button.addEventListener('click', () => {
        if (button.dataset.logFormat === 'formatted' && liveRefreshEnabled) stopTailMode();
        setLogView(button.dataset.logFormat === 'terminal' ? 'raw' : activeLogSource === 'access' ? 'access' : 'grouped');
    });
});

terminalFollow.addEventListener('click', () => {
    terminalFollowEnabled = !terminalFollowEnabled;
    terminalFollow.setAttribute('aria-pressed', String(terminalFollowEnabled));
    if (terminalFollowEnabled) terminalOutput.scrollTop = terminalOutput.scrollHeight;
});
terminalOutput.addEventListener('scroll', () => {
    if (terminalFollowEnabled && terminalOutput.scrollHeight - terminalOutput.clientHeight - terminalOutput.scrollTop > 24) {
        terminalFollowEnabled = false;
        terminalFollow.setAttribute('aria-pressed', 'false');
    }
});

document.querySelectorAll('[data-status-filter]').forEach(button => {
    button.addEventListener('click', () => {
        activeAccessStatus = button.dataset.statusFilter;
        document.querySelectorAll('[data-status-filter]').forEach(item => {
            item.classList.toggle('active', item === button);
            item.setAttribute('aria-pressed', String(item === button));
        });
        filterAndDisplayAccessLogs();
    });
});

function syncErrorLevelButtons() {
    document.querySelectorAll('[data-error-level]').forEach(button => {
        const active = button.dataset.errorLevel === activeErrorLevel;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
    });
}

document.querySelectorAll('[data-error-level]').forEach(button => {
    button.addEventListener('click', () => {
        activeErrorLevel = button.dataset.errorLevel;
        syncErrorLevelButtons();
        const url = new URL(window.location.href);
        if (activeErrorLevel) url.searchParams.set('level', activeErrorLevel);
        else url.searchParams.delete('level');
        window.history.replaceState(null, '', url);
        // Refresh both formats so switching displays preserves the selected level.
        fetchLogs();
        fetchRawLogs();
    });
});
syncErrorLevelButtons();

function setLogSource(source) {
    const nextSource = source === 'access' ? 'access' : 'error';
    if (nextSource !== activeLogSource) {
        logSearch.value = '';
        currentRawLogs = [];
        terminalOutput.textContent = '';
        terminalError = '';
        ++logRequestIds.raw;
    }
    terminalFilename = `${nextSource}.log`;
    activeLogSource = nextSource;
    localStorage.setItem('logSource', activeLogSource);
    document.querySelectorAll('[data-log-source]').forEach(button => {
        const active = button.dataset.logSource === activeLogSource;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
    });
    setLogView(activeLogFormat === 'terminal' || liveRefreshEnabled ? 'raw' : activeLogSource === 'access' ? 'access' : 'grouped');
    if (liveRefreshEnabled) startTailMode();
}

function openLogExplorer(source, query = '', statusFamily = 'all') {
    // A drill-down should show all matching evidence, regardless of an earlier level filter.
    if (source === 'error') {
        activeErrorLevel = '';
        syncErrorLevelButtons();
        const url = new URL(window.location.href);
        url.searchParams.delete('level');
        window.history.replaceState(null, '', url);
        fetchLogs();
        fetchRawLogs();
    }
    setLogSource(source);
    logSearch.value = query;
    if (source === 'access') {
        activeAccessStatus = statusFamily;
        document.querySelectorAll('[data-status-filter]').forEach(button => {
            const active = button.dataset.statusFilter === activeAccessStatus;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', String(active));
        });
    }
    if (window.location.hash !== '#logs') window.location.hash = 'logs';
    else showView('logs');
    if (source === 'access') fetchAccessLogs();
    else renderActiveLogView();
}

function setLogView(view) {
    activeLogView = view === 'raw' ? 'raw' : activeLogSource === 'access' ? 'access' : 'grouped';
    activeLogFormat = activeLogView === 'raw' ? 'terminal' : 'formatted';
    localStorage.setItem('logFormat', activeLogFormat);
    document.querySelectorAll('[data-log-format]').forEach(button => {
        const active = button.dataset.logFormat === activeLogFormat;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
    });
    const largeLimit = logLimit.querySelector('[value="500"]');
    largeLimit.disabled = activeLogView !== 'raw';
    largeLimit.hidden = activeLogView !== 'raw';
    if (activeLogView !== 'raw' && Number(logLimit.value) > 100) logLimit.value = '100';
    logEntries.hidden = activeLogView !== 'grouped';
    rawLogEntries.hidden = activeLogView !== 'raw';
    accessLogEntries.hidden = activeLogView !== 'access';
    errorLogFilters.hidden = activeLogView !== 'grouped';
    accessLogFilters.hidden = activeLogView !== 'access';
    accessSummary.hidden = activeLogView !== 'access';
    const helpText = {
        grouped: 'Repeated messages are grouped together. Expand an issue for evidence.',
        raw: 'Original log lines, oldest to newest. Watch live checks for updates every 5 seconds.',
        access: 'Recent requests. Expand a row for its referrer, protocol, and user agent.'
    };
    document.getElementById('logViewHelp').textContent = helpText[activeLogView];
    logSearch.placeholder = activeLogView === 'raw' ? 'Find text in these lines' : activeLogView === 'access' ? 'Search requests, IPs, or status' : 'Search messages or URLs';
    updateLiveLogButton();
    if (activeLogView === 'raw') {
        document.getElementById('terminalFile').textContent = terminalFilename;
        filterAndDisplayRawLogs();
        fetchRawLogs();
    } else if (activeLogView === 'access' && currentAccessLogs.length === 0) fetchAccessLogs();
    else renderActiveLogView();
}

function renderActiveLogView() {
    if (activeLogView === 'access') filterAndDisplayAccessLogs();
    else if (activeLogView === 'raw') filterAndDisplayRawLogs();
    else filterAndDisplayLogs();
}

function fetchActiveLogData() {
    if (activeLogView === 'access') fetchAccessLogs();
    else if (activeLogView === 'raw') fetchRawLogs();
    else fetchLogs();
}

function startTailMode() {
    liveRefreshEnabled = true;
    localStorage.setItem('tailMode', 'true');
    if (tailInterval) clearInterval(tailInterval);
    fetchActiveLogData();
    tailInterval = setInterval(fetchActiveLogData, 5000);
    updateLiveLogButton();
}

function stopTailMode() {
    liveRefreshEnabled = false;
    localStorage.setItem('tailMode', 'false');
    if (tailInterval) {
        clearInterval(tailInterval);
        tailInterval = null;
    }
    updateLiveLogButton();
}

function updateLiveLogButton() {
    liveLogButton.classList.toggle('watching', liveRefreshEnabled);
    liveLogButton.setAttribute('aria-pressed', liveRefreshEnabled ? 'true' : 'false');
    liveLogButton.querySelector('.live-log-label').textContent = liveRefreshEnabled ? 'Pause live' : 'Watch live';
    if (activeLogView === 'raw') filterAndDisplayRawLogs();
}

function filterAndDisplayLogs() {
    const searchTerm = logSearch.value.toLowerCase().trim();

    if (currentLogs.length === 0) {
        logEntries.innerHTML = '<div class="empty-state">No recent issues at this severity. Check the log-file warning on Overview if you expected activity.</div>';
        return;
    }

    // Filter logs based on search term
    let filteredLogs = currentLogs;
    if (searchTerm) {
        filteredLogs = currentLogs.filter(entry => {
            return entry.message.toLowerCase().includes(searchTerm) ||
                   entry.level.toLowerCase().includes(searchTerm) ||
                   entry.affected_urls.some(url => url.toLowerCase().includes(searchTerm));
        });
    }

    if (filteredLogs.length === 0) {
        logEntries.innerHTML = `<div class="empty-state">No issues match “${escapeHtml(searchTerm)}”.</div>`;
        return;
    }

    logEntries.innerHTML = filteredLogs.map(entry => {
        const maxTrend = Math.max(...entry.trend, 1);
        const bars = entry.trend.map(value => `<span style="height:${Math.max(3, value / maxTrend * 22)}px" title="${value} occurrence${value === 1 ? '' : 's'}"></span>`).join('');
        const urls = entry.affected_urls.length
            ? `<div class="incident-urls"><strong>Affected URLs:</strong> ${entry.affected_urls.map(escapeHtml).join(', ')}</div>`
            : '';
        const occurrences = entry.occurrences.map(occurrence => `
            <div class="occurrence-row">
                <time>${escapeHtml(occurrence.timestamp || 'Unknown time')}</time>
                <code>${escapeHtml(occurrence.message)}</code>
            </div>`).join('');
        return `<details class="incident-card">
            <summary class="incident-main"><span class="level level-${escapeHtml(entry.level)}">${escapeHtml(entry.level.toUpperCase())}</span>
            <span class="incident-message">${escapeHtml(entry.message)}</span>
            <span class="incident-count">${entry.count} ${entry.count === 1 ? 'occurrence' : 'occurrences'}</span><span class="disclosure-chevron" aria-hidden="true">⌄</span></summary>
            <div class="incident-body">
            ${urls}
            <div class="incident-meta"><span>First: ${formatIncidentTime(entry.first_seen)}</span><span>Last: ${formatIncidentTime(entry.last_seen)}</span>
            <span class="incident-trend" aria-label="Occurrence trend">${bars}</span></div>
            <div class="occurrence-list">${occurrences}</div>
            ${entry.occurrences_truncated ? `<p class="incident-muted">Showing the latest ${entry.occurrences.length} of ${entry.count} occurrences.</p>` : ''}
            </div>
        </details>`;
    }).join('');
}

function filterAndDisplayRawLogs() {
    const search = logSearch.value.trim().toLowerCase();
    const filtered = search ? currentRawLogs.filter(line => line.toLowerCase().includes(search)) : currentRawLogs;
    const text = filtered.join('\n');
    const scrollTop = terminalOutput.scrollTop;
    // Preserve text selection and scroll position when a poll returns the same lines.
    if (terminalOutput.textContent !== text) terminalOutput.textContent = text;
    terminalOutput.hidden = filtered.length === 0;
    terminalMessage.hidden = filtered.length > 0 && !terminalError;
    terminalMessage.textContent = terminalError || (search ? 'No lines match this search.' : 'No lines in this log yet.');
    terminalMessage.classList.toggle('raw-log-error', Boolean(terminalError));
    document.getElementById('terminalFile').textContent = terminalFilename;
    document.getElementById('terminalStatus').textContent = terminalError ? 'Unable to read log' : `${filtered.length}${search ? ` of ${currentRawLogs.length}` : ''} lines · ${liveRefreshEnabled ? 'Live · 5s' : 'Paused'}`;
    terminalOutput.scrollTop = terminalFollowEnabled ? terminalOutput.scrollHeight : scrollTop;
}

function filterAndDisplayAccessLogs() {
    const searchTerm = logSearch.value.toLowerCase().trim();
    const filtered = currentAccessLogs.filter(entry => {
        const statusMatches = activeAccessStatus === 'all' || String(entry.status).startsWith(activeAccessStatus);
        const searchable = [entry.timestamp, entry.status, entry.method, entry.path, entry.ip,
            entry.protocol, entry.referer, entry.user_agent, entry.user].filter(Boolean).join(' ').toLowerCase();
        return statusMatches && (!searchTerm || searchable.includes(searchTerm));
    });

    renderAccessSummary();
    if (filtered.length === 0) {
        accessLogEntries.innerHTML = `<div class="access-log-empty">${searchTerm || activeAccessStatus !== 'all' ? 'No requests match the current filters.' : 'No recent access-log requests found.'}</div>`;
        return;
    }

    accessLogEntries.innerHTML = `
        <div class="access-log-heading" aria-hidden="true"><span>Time</span><span>Status</span><span>Request</span><span>Path</span><span>Client</span><span>Size</span><span></span></div>
        ${filtered.map(entry => {
            const family = Math.floor(entry.status / 100);
            return `<details class="access-request">
                <summary class="access-request-row">
                    <time>${escapeHtml(entry.timestamp)}</time>
                    <span class="http-status status-${family}xx">${entry.status}</span>
                    <span class="request-method">${escapeHtml(entry.method)}</span>
                    <code class="request-path">${escapeHtml(entry.path)}</code>
                    <code class="request-ip">${escapeHtml(entry.ip)}</code>
                    <span class="request-size">${formatBytes(entry.size)}</span>
                    <span class="recommendation-chevron">⌄</span>
                </summary>
                <div class="access-request-details">
                    <div><span>Protocol</span><code>${escapeHtml(entry.protocol || 'Unknown')}</code></div>
                    <div><span>User</span><code>${escapeHtml(entry.user || 'Anonymous')}</code></div>
                    <div><span>Referrer</span><code>${escapeHtml(entry.referer || 'Direct / unavailable')}</code></div>
                    <div class="user-agent-detail"><span>User agent</span><code>${escapeHtml(entry.user_agent || 'Unavailable')}</code></div>
                </div>
            </details>`;
        }).join('')}`;
}

function renderAccessSummary() {
    const summary = currentAccessSummary;
    accessSummary.innerHTML = `
        <div><strong>${summary.total || 0}</strong><span>Loaded requests</span></div>
        <div><strong>${summary.unique_ips || 0}</strong><span>Unique clients</span></div>
        <div class="summary-success"><strong>${summary.success || 0}</strong><span>Successful</span></div>
        <div class="summary-warning"><strong>${summary.client_errors || 0}</strong><span>Client errors</span></div>
        <div class="summary-danger"><strong>${summary.server_errors || 0}</strong><span>Server errors</span></div>`;
}

function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(value) {
    const node = document.createElement('div');
    node.textContent = value == null ? '' : String(value);
    return node.innerHTML;
}

function formatIncidentTime(value) {
    if (!value) return 'Unknown';
    return new Date(value).toLocaleString();
}

// ── Action Center ───────────────────────────────────────────────────

let currentActionItems = [];
let currentActionSummary = {};
let currentActionFilter = 'open';
let selectedActionItem = null;
const actionSearch = document.getElementById('actionSearch');
const actionSourceFilter = document.getElementById('actionSourceFilter');

function sortActionItems(items, historical = false) {
    const priorities = { critical: 0, warning: 1, info: 2 };
    return items.slice().sort((a, b) => {
        if (historical) return String(b.updated_at || b.last_seen).localeCompare(String(a.updated_at || a.last_seen));
        return (priorities[a.severity] ?? 2) - (priorities[b.severity] ?? 2)
            || Number(b.currently_observed) - Number(a.currently_observed)
            || String(b.last_seen).localeCompare(String(a.last_seen));
    });
}

function actionStatusLabel(status) {
    return {
        new: 'New', acknowledged: 'In progress', snoozed: 'Snoozed',
        resolved: 'Resolved', dismissed: 'Dismissed'
    }[status] || status;
}

function actionSourceLabel(source) {
    return { alert: 'Threshold alert', error: 'Apache error', security: 'Traffic threat' }[source] || source;
}

function isOpenAction(item) {
    return ['new', 'acknowledged'].includes(item.status);
}

function renderActionRow(item, compact = false) {
    const observed = item.currently_observed
        ? '<span class="action-observed">Observed now</span>'
        : '<span class="action-not-observed">Not in latest scan</span>';
    return `<button type="button" class="action-item action-${item.severity} ${compact ? 'action-item-compact' : ''}" data-action-item-id="${item.id}">
        <span class="action-severity-dot" aria-hidden="true"></span>
        <span class="action-item-content">
            <span class="action-item-heading"><strong>${escapeHtml(item.title)}</strong><span class="action-status action-status-${item.status}">${escapeHtml(actionStatusLabel(item.status))}</span></span>
            <span class="action-item-summary">${escapeHtml(item.summary)}</span>
            <span class="action-item-meta"><span class="action-priority">${escapeHtml(item.severity)}</span> · ${escapeHtml(actionSourceLabel(item.source))} · ${item.occurrence_count} occurrence${item.occurrence_count === 1 ? '' : 's'} · ${observed}</span>
        </span>
        <span class="action-item-time">${formatIncidentTime(item.last_seen)}</span>
        <span class="action-item-arrow">→</span>
    </button>`;
}

function bindActionRows(container) {
    container.querySelectorAll('[data-action-item-id]').forEach(button => {
        button.addEventListener('click', () => {
            const item = currentActionItems.find(candidate => candidate.id === Number(button.dataset.actionItemId));
            if (item) openActionDialog(item);
        });
    });
}

function renderActionCenter() {
    const summary = currentActionSummary;
    document.getElementById('actionOpenCount').textContent = summary.open || 0;
    document.getElementById('actionSnoozedCount').textContent = summary.snoozed || 0;
    document.getElementById('actionHistoryCount').textContent = (summary.resolved || 0) + (summary.dismissed || 0);

    const navCount = document.getElementById('actionNavCount');
    navCount.textContent = summary.open || 0;
    navCount.hidden = !(summary.open > 0);

    const openItems = sortActionItems(currentActionItems.filter(isOpenAction));
    const criticalCount = openItems.filter(item => item.severity === 'critical').length;
    document.getElementById('actionOverviewSummary').innerHTML = summary.open
        ? `<strong>${summary.open} open finding${summary.open === 1 ? '' : 's'}</strong><span>${criticalCount ? `${criticalCount} critical · ` : ''}${summary.new || 0} new</span>`
        : '<strong>All clear</strong><span>No findings need attention.</span>';
    const overviewList = document.getElementById('actionOverviewList');
    overviewList.innerHTML = openItems.length
        ? openItems.slice(0, 4).map(item => renderActionRow(item, true)).join('')
        : '<div class="action-empty action-empty-compact">Nothing is waiting for review.</div>';
    bindActionRows(overviewList);

    renderActionList();
}

function renderActionList() {
    let filtered = currentActionItems.filter(item => {
        if (currentActionFilter === 'open') return isOpenAction(item);
        if (currentActionFilter === 'history') return ['resolved', 'dismissed'].includes(item.status);
        return item.status === 'snoozed';
    });
    const search = actionSearch.value.trim().toLowerCase();
    const source = actionSourceFilter.value;
    const hasFilters = Boolean(search || source !== 'all');
    filtered = sortActionItems(filtered.filter(item => {
        const matchesSource = source === 'all' || item.source === source;
        const text = [item.title, item.summary, item.related_query, item.note, actionSourceLabel(item.source)].filter(Boolean).join(' ').toLowerCase();
        return matchesSource && (!search || text.includes(search));
    }), currentActionFilter === 'history');
    document.getElementById('clearActionFilters').hidden = !hasFilters;
    const queueTotal = currentActionFilter === 'history'
        ? (currentActionSummary.resolved || 0) + (currentActionSummary.dismissed || 0)
        : currentActionSummary[currentActionFilter] || 0;
    document.getElementById('actionResultCount').textContent = `${filtered.length} finding${filtered.length === 1 ? '' : 's'}${queueTotal > filtered.length ? ` of ${queueTotal}${hasFilters ? ' in this queue' : ' · latest loaded'}` : ''}`;
    document.getElementById('actionQueueHint').textContent = currentActionFilter === 'history' ? 'Most recently updated first' : 'Highest priority first';
    const emptyMessages = {
        open: ['All clear', 'No findings need attention right now.'],
        snoozed: ['Nothing snoozed', 'Snoozed findings return to Needs attention when their timer expires.'],
        history: ['No history yet', 'Resolved and dismissed findings will appear here.']
    };
    const [emptyTitle, emptyDescription] = hasFilters
        ? ['No matching findings', 'Try a different search or clear the filters.']
        : emptyMessages[currentActionFilter];
    const list = document.getElementById('actionItems');
    list.innerHTML = filtered.length
        ? filtered.map(item => renderActionRow(item)).join('')
        : `<div class="action-empty"><strong>${emptyTitle}</strong><span>${emptyDescription}</span></div>`;
    bindActionRows(list);
}

function fetchActionItems() {
    const refreshButton = document.getElementById('refreshActionItems');
    refreshButton.disabled = true;
    refreshButton.textContent = 'Refreshing…';
    return fetch('/api/action-items?status=all&limit=500')
        .then(response => {
            if (!response.ok) throw new Error('Unable to load action items');
            return response.json();
        })
        .then(data => {
            currentActionItems = data.items || [];
            currentActionSummary = data.summary || {};
            renderActionCenter();
        })
        .catch(error => {
            console.error('Error fetching action items:', error);
            document.getElementById('actionItems').innerHTML = '<div class="action-empty action-error">Unable to refresh findings.</div>';
            document.getElementById('actionOverviewList').innerHTML = '<div class="action-empty action-empty-compact">Unable to refresh findings.</div>';
        })
        .finally(() => {
            refreshButton.disabled = false;
            refreshButton.textContent = 'Refresh findings';
        });
}

function renderActionEvidence(item) {
    const evidence = item.evidence || {};
    if (item.source === 'alert') {
        return `<div class="action-evidence-line">
            <span>Current value</span><strong>${escapeHtml(evidence.value)}</strong>
            <span class="action-evidence-separator">Configured threshold</span><strong>${escapeHtml(evidence.threshold)}</strong>
        </div>`;
    }
    if (item.source === 'error') {
        const urls = (evidence.affected_urls || []).map(url => `<code>${escapeHtml(url)}</code>`).join('');
        const occurrences = (evidence.occurrences || []).slice(0, 3).map(occurrence => `
            <div class="action-occurrence"><time>${escapeHtml(occurrence.timestamp || 'Unknown time')}</time><code>${escapeHtml(occurrence.message)}</code></div>`).join('');
        return `<p class="action-evidence-lead">Seen <strong>${evidence.count || item.occurrence_count} times</strong>${evidence.first_seen && evidence.last_seen ? ` between ${formatIncidentTime(evidence.first_seen)} and ${formatIncidentTime(evidence.last_seen)}` : ''}.</p>
            ${urls ? `<div class="action-evidence-block"><span>Affected URLs</span><div class="action-code-list">${urls}</div></div>` : ''}
            ${occurrences ? `<div class="action-evidence-block"><span>Recent log lines</span><div class="action-occurrences">${occurrences}</div></div>` : ''}`;
    }
    const reasons = (evidence.reasons || []).map(reason => `<li>${escapeHtml(reason)}</li>`).join('');
    const paths = (evidence.suspicious_paths || []).slice(0, 5).map(path => `<code>${escapeHtml(path)}</code>`).join('');
    const rules = evidence.rules || {};
    return `${reasons ? `<ul class="action-reason-list">${reasons}</ul>` : '<p class="action-evidence-lead">Suspicious access behavior was detected.</p>'}
        ${paths ? `<div class="action-evidence-block"><span>Flagged URLs</span><div class="action-code-list">${paths}</div></div>` : ''}
        ${rules.apache ? `<details class="action-rule-disclosure"><summary>Show suggested blocking rules</summary><p>These commands are never applied automatically.</p><code class="action-rule">${escapeHtml(rules.apache)}</code><code class="action-rule">${escapeHtml(rules.ufw || '')}</code></details>` : ''}`;
}

function openActionDialog(item) {
    selectedActionItem = item;
    document.getElementById('actionDialogSource').textContent = actionSourceLabel(item.source);
    document.getElementById('actionDialogTitle').textContent = item.title;
    document.getElementById('actionDialogSummary').textContent = item.summary;
    document.getElementById('actionDialogMeta').innerHTML = `
        <span class="badge badge-${item.severity}">${escapeHtml(item.severity)}</span>
        <span class="action-status action-status-${item.status}">${escapeHtml(actionStatusLabel(item.status))}</span>
        <span>Last seen ${formatIncidentTime(item.last_seen)}</span>`;
    document.getElementById('actionEvidenceTitle').textContent = item.source === 'security'
        ? 'Why this was flagged'
        : item.source === 'error' ? 'Recent evidence' : 'Threshold details';
    document.getElementById('actionDialogEvidence').innerHTML = renderActionEvidence(item);
    document.getElementById('actionNote').value = item.note || '';
    document.getElementById('actionUpdateError').hidden = true;
    document.getElementById('actionMoreOptions').open = false;
    document.querySelector('[data-action-status="acknowledged"]').hidden = item.status !== 'new';
    document.querySelector('[data-action-status="new"]').hidden = isOpenAction(item);
    document.querySelector('[data-action-status="resolved"]').hidden = ['resolved', 'dismissed'].includes(item.status);
    document.querySelector('[data-action-status="resolved"]').className = item.status === 'acknowledged' ? 'primary-button' : 'secondary-button';
    document.getElementById('actionMoreOptions').hidden = !isOpenAction(item);
    document.getElementById('actionRelatedButton').hidden = !item.related_view;
    document.getElementById('actionRelatedButton').textContent = {
        error: 'Open error logs →', security: 'Open access logs →'
    }[item.source] || 'View related activity →';
    const dialog = document.getElementById('actionDialog');
    if (!dialog.open) dialog.showModal();
}

function updateSelectedAction(status) {
    if (!selectedActionItem) return;
    const controls = document.querySelectorAll('[data-action-status]');
    controls.forEach(button => button.disabled = true);
    document.getElementById('actionUpdateError').hidden = true;
    const payload = {
        status,
        note: document.getElementById('actionNote').value,
        snooze_minutes: 60
    };
    fetch(`/api/action-items/${selectedActionItem.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
        .then(response => {
            if (!response.ok) throw new Error('Unable to update finding');
            document.getElementById('actionDialog').close();
            return fetchActionItems();
        })
        .catch(error => {
            console.error('Error updating action item:', error);
            const message = document.getElementById('actionUpdateError');
            message.textContent = 'Unable to save this change. Please try again.';
            message.hidden = false;
        })
        .finally(() => controls.forEach(button => button.disabled = false));
}

document.querySelectorAll('[data-action-filter]').forEach(button => {
    button.addEventListener('click', () => {
        currentActionFilter = button.dataset.actionFilter;
        document.querySelectorAll('[data-action-filter]').forEach(candidate => {
            candidate.classList.toggle('active', candidate === button);
            candidate.setAttribute('aria-pressed', String(candidate === button));
        });
        renderActionList();
    });
});
actionSearch.addEventListener('input', renderActionList);
actionSourceFilter.addEventListener('change', renderActionList);
document.getElementById('clearActionFilters').addEventListener('click', () => {
    actionSearch.value = '';
    actionSourceFilter.value = 'all';
    renderActionList();
    actionSearch.focus();
});
document.querySelectorAll('[data-action-status]').forEach(button => {
    button.addEventListener('click', () => updateSelectedAction(button.dataset.actionStatus));
});
document.getElementById('refreshActionItems').addEventListener('click', fetchActionItems);
document.getElementById('actionRelatedButton').addEventListener('click', () => {
    if (!selectedActionItem) return;
    document.getElementById('actionDialog').close();
    const evidence = selectedActionItem.evidence || {};
    if (selectedActionItem.source === 'error') {
        openLogExplorer('error', selectedActionItem.related_query || '');
    } else if (selectedActionItem.source === 'security') {
        openLogExplorer('access', selectedActionItem.related_query || '');
    } else if (evidence.alert_type === 'server_errors_5xx') {
        openLogExplorer('access', '', '5');
    } else if (evidence.alert_type === 'client_errors_4xx') {
        openLogExplorer('access', '', '4');
    } else {
        window.location.hash = selectedActionItem.related_view || 'overview';
    }
});

function fetchLogs() {
    const requestId = ++logRequestIds.grouped;
    const params = new URLSearchParams({ limit: logLimit.value });
    if (activeErrorLevel) params.set('level', activeErrorLevel);
    fetch(`/api/incidents?${params}`)
        .then(readJSON)
        .then(data => {
            if (requestId !== logRequestIds.grouped) return;
            // Get last N entries based on user preference
            const limit = parseInt(logLimit.value);
            currentLogs = data.incidents.slice(0, limit);
            filterAndDisplayLogs();
        })
        .catch(error => {
            if (requestId !== logRequestIds.grouped) return;
            console.error('Error fetching logs:', error);
            logEntries.innerHTML = '<div class="empty-state action-error">Unable to load issues. Try refreshing the page.</div>';
        });
}

function fetchRawLogs() {
    const requestId = ++logRequestIds.raw;
    const source = activeLogSource;
    const params = new URLSearchParams({source, limit:logLimit.value});
    return fetch(`/api/log-tail?${params}`)
        .then(async response => {
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Unable to read this log file.');
            return data;
        })
        .then(data => {
            if (requestId !== logRequestIds.raw || source !== activeLogSource) return;
            currentRawLogs = data.lines || [];
            terminalFilename = data.filename || `${source}.log`;
            terminalError = '';
            filterAndDisplayRawLogs();
        })
        .catch(error => {
            if (requestId !== logRequestIds.raw || source !== activeLogSource) return;
            terminalError = error.message || 'Unable to read this log file.';
            filterAndDisplayRawLogs();
        });
}

function fetchAccessLogs() {
    const requestId = ++logRequestIds.access;
    const params = new URLSearchParams({ limit: logLimit.value });
    fetch(`/api/access-logs?${params.toString()}`)
        .then(readJSON)
        .then(data => {
            if (requestId !== logRequestIds.access) return;
            currentAccessLogs = data.entries || [];
            currentAccessSummary = data.summary || {};
            filterAndDisplayAccessLogs();
        })
        .catch(error => {
            if (requestId !== logRequestIds.access) return;
            console.error('Error fetching access logs:', error);
            accessLogEntries.innerHTML = '<div class="access-log-empty access-log-error">Unable to read the access log.</div>';
        });
}

// Fetch access log analytics
function fetchAccessStats() {
    fetch('/api/access-stats')
        .then(readJSON)
        .then(stats => {
            // Display top IPs with hostname and bot detection
            const topIpsDiv = document.getElementById('topIps');
            if (stats.top_ips && stats.top_ips.length > 0) {
                topIpsDiv.innerHTML = stats.top_ips.map(item => {
                    // Build bot/human badge
                    let badge = '';
                    if (item.is_bot === true) {
                        const botName = item.bot_name || 'Bot';
                        badge = `<span class="badge badge-bot">${escapeHtml(botName)}</span>`;
                    } else if (item.is_bot === false) {
                        badge = `<span class="badge badge-human">User</span>`;
                    } else {
                        badge = `<span class="badge badge-unknown">Unknown</span>`;
                    }

                    return `
                        <button type="button" class="stat-row stat-row-link ip-row" data-access-query="${encodeURIComponent(item.ip)}" aria-label="View requests from this client">
                            <div class="ip-info">
                                <div class="ip-main">
                                    <span class="stat-label">${escapeHtml(item.ip)}</span>
                                    ${badge}
                                </div>
                                ${item.hostname ? `<div class="ip-details">${escapeHtml(item.hostname)}</div>` : ''}
                            </div>
                            <span class="stat-value">${item.requests}<small> requests →</small></span>
                        </button>
                    `;
                }).join('');
            } else {
                topIpsDiv.innerHTML = '<div class="empty-state">No recent traffic recorded.</div>';
            }

            // Update bot stats
            if (stats.bot_stats) {
                document.getElementById('humanCount').textContent = stats.bot_stats.total_humans || 0;
                document.getElementById('botCount').textContent = stats.bot_stats.total_bots || 0;
                document.getElementById('botPercentage').textContent = stats.bot_stats.bot_percentage || 0;
            }

            // Display top pages
            const topPagesDiv = document.getElementById('topPages');
            if (stats.top_pages && stats.top_pages.length > 0) {
                topPagesDiv.innerHTML = stats.top_pages.map(item => `
                    <button type="button" class="stat-row stat-row-link" data-access-query="${encodeURIComponent(item.path)}" aria-label="View requests for this path">
                        <span class="stat-label">${escapeHtml(item.path)}</span>
                        <span class="stat-value">${item.requests}<small> requests →</small></span>
                    </button>
                `).join('');
            } else {
                topPagesDiv.innerHTML = '<div class="empty-state">No recent traffic recorded.</div>';
            }
            document.querySelectorAll('[data-access-query]').forEach(button => {
                button.addEventListener('click', () => openLogExplorer('access', decodeURIComponent(button.dataset.accessQuery)));
            });
        })
        .catch(error => {
            console.error('Error fetching access stats:', error);
            document.getElementById('topIps').innerHTML = '<div class="empty-state action-error">Unable to load recent traffic.</div>';
            document.getElementById('topPages').innerHTML = '<div class="empty-state action-error">Unable to load recent traffic.</div>';
        });
}

function fetchMonitoringHealth() {
    return fetch('/api/monitoring-health')
        .then(readJSON)
        .then(data => {
            const logs = data.logs || [];
            const problems = logs.filter(log => log.status !== 'ready');
            const notice = document.getElementById('logSourceNotice');
            notice.hidden = problems.length === 0;
            const problemLabels = problems.map(log => log.label);
            document.getElementById('logSourceNoticeText').textContent = problems.length
                ? `${problemLabels.join(' and ')} cannot be read. Some log analysis may be unavailable.`
                : '';
            const descriptions = {
                ready: 'Ready for analysis.',
                missing: 'File not found. Check the configured path.',
                unreadable: 'ApacheWatch does not have permission to read this file.',
                not_configured: 'Choose a log file in config.yaml.'
            };
            const labels = {ready:'Ready', missing:'Missing file', unreadable:'Access denied', not_configured:'Not configured'};
            document.getElementById('logSourceStatus').innerHTML = logs.map(log => `
                <div class="log-source-status-row">
                    <div><strong>${escapeHtml(log.label)}</strong><span class="badge ${log.status === 'ready' ? 'badge-ok' : 'badge-warning'}">${escapeHtml(labels[log.status] || 'Not configured')}</span></div>
                    <p>${escapeHtml(descriptions[log.status] || descriptions.not_configured)}</p>
                    ${log.path ? `<code>${escapeHtml(log.path)}</code>` : ''}
                </div>`).join('');
        })
        .catch(() => {
            document.getElementById('logSourceNotice').hidden = false;
            document.getElementById('logSourceNoticeText').textContent = 'Unable to check log files. Log analysis may be incomplete.';
            document.getElementById('logSourceStatus').innerHTML = '<p>Unable to check log files. Refresh the page to try again.</p>';
        });
}

document.getElementById('openLogDetails').addEventListener('click', () => {
    document.getElementById('logProblemDialog').showModal();
});

function recommendationLabel(action) {
    if (action === 'block_ip') return 'Block IP';
    if (action === 'consider_range') return 'Review range';
    return 'Watch';
}

function copyRule(button, value) {
    const original = button.textContent;
    navigator.clipboard.writeText(value).then(() => {
        button.textContent = 'Copied';
    }).catch(() => {
        button.textContent = 'Unable to copy';
    }).finally(() => {
        setTimeout(() => { button.textContent = original; }, 1600);
    });
}

let activeThreatFilter = 'all';

function applyThreatFilter(filter) {
    activeThreatFilter = activeThreatFilter === filter ? 'all' : filter;
    document.querySelectorAll('[data-threat-filter]').forEach(button => {
        const active = activeThreatFilter === button.dataset.threatFilter;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    document.querySelectorAll('#blockRecommendations [data-action]').forEach(row => {
        row.hidden = activeThreatFilter !== 'all' && row.dataset.action !== activeThreatFilter;
    });
}

function fetchBlockRecommendations() {
    fetch('/api/block-recommendations')
        .then(readJSON)
        .then(data => {
            const container = document.getElementById('blockRecommendations');
            const expandedTargets = new Set(Array.from(container.querySelectorAll('.recommendation-card[open]')).map(card => card.dataset.target));
            document.getElementById('securityScanMeta').textContent =
                `${(data.entries_scanned || 0).toLocaleString()} requests scanned`;
            const blockCount = data.recommendations.filter(item => item.action === 'block_ip').length;
            const rangeCount = data.recommendations.filter(item => item.action === 'consider_range').length;
            const watchCount = data.recommendations.filter(item => item.action === 'watch').length;
            document.getElementById('securitySummary').innerHTML = `
                <button type="button" class="threat-stat threat-stat-danger" data-threat-filter="block_ip" aria-pressed="false" ${blockCount ? '' : 'disabled'}><strong>${blockCount}</strong><span>Block candidates</span></button>
                <button type="button" class="threat-stat threat-stat-range" data-threat-filter="consider_range" aria-pressed="false" ${rangeCount ? '' : 'disabled'}><strong>${rangeCount}</strong><span>Ranges to review</span></button>
                <button type="button" class="threat-stat threat-stat-watch" data-threat-filter="watch" aria-pressed="false" ${watchCount ? '' : 'disabled'}><strong>${watchCount}</strong><span>IPs to watch</span></button>`;
            document.querySelectorAll('[data-threat-filter]').forEach(button => {
                button.addEventListener('click', () => applyThreatFilter(button.dataset.threatFilter));
            });
            if (!data.recommendations.length) {
                document.getElementById('securitySummary').classList.add('all-clear');
                container.innerHTML = '<div class="security-empty">No clients currently meet the recommendation threshold.</div>';
                return;
            }
            document.getElementById('securitySummary').classList.remove('all-clear');
            container.innerHTML = data.recommendations.map(item => {
                const paths = item.suspicious_paths.length
                    ? `<div class="recommendation-paths"><div><strong>Flagged URLs</strong><span>Requests matching common scanner targets</span></div><div class="flagged-url-list">${item.suspicious_paths.map(path => `<code>${escapeHtml(path)}</code>`).join('')}</div></div>`
                    : '';
                const members = item.member_ips
                    ? `<div class="recommendation-members"><strong>Member IPs:</strong> ${item.member_ips.map(escapeHtml).join(', ')}</div>`
                    : '';
                const severity = item.score >= 75 ? 'Critical' : item.score >= 50 ? 'High' : 'Review';
                return `<details class="recommendation-card recommendation-${item.action}" data-action="${item.action}" data-target="${escapeHtml(item.target)}" ${expandedTargets.has(item.target) ? 'open' : ''}>
                    <summary class="recommendation-row">
                        <span class="recommendation-action">${recommendationLabel(item.action)}</span>
                        <code class="recommendation-target">${escapeHtml(item.target)}</code>
                        <span class="recommendation-primary-reason">${escapeHtml(item.reasons[0] || 'Suspicious behavior')}</span>
                        <span class="recommendation-quick-stats">${item.requests} req · ${item.client_errors} errors</span>
                        <span class="risk-pill risk-${severity.toLowerCase()}">${severity} ${item.score}</span>
                        <span class="recommendation-chevron">⌄</span>
                    </summary>
                    <div class="recommendation-evidence">
                        <div class="evidence-metrics">
                            <div><strong>${item.requests}</strong><span>Requests</span></div>
                            <div><strong>${item.client_errors}</strong><span>Client errors</span></div>
                            ${item.peak_requests_per_minute != null ? `<div><strong>${item.peak_requests_per_minute}</strong><span>Peak requests/min</span></div>` : ''}
                            <div><strong>${escapeHtml(item.confidence)}</strong><span>Confidence</span></div>
                        </div>
                        <div class="evidence-columns ${item.suspicious_paths.length ? '' : 'evidence-columns-single'}">
                            <section class="evidence-section">
                                <h4>Why this appeared</h4>
                                <ul class="recommendation-reasons">${item.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>
                                ${members}
                            </section>
                            ${paths}
                        </div>
                        <div class="rule-actions">
                            ${item.target_type === 'ip' ? `<button type="button" class="investigate-button" data-security-query="${encodeURIComponent(item.target)}">View IP requests →</button>` : ''}
                        </div>
                        <details class="rule-disclosure">
                            <summary>Suggested blocking rules</summary>
                            <p>Review these rules before using them. They are never applied automatically.</p>
                            <div><strong>Apache</strong><button type="button" class="secondary-button" data-rule="${encodeURIComponent(item.rules.apache)}">Copy Apache rule</button></div>
                            <pre><code>${escapeHtml(item.rules.apache)}</code></pre>
                            <div><strong>UFW</strong><button type="button" class="secondary-button" data-rule="${encodeURIComponent(item.rules.ufw)}">Copy UFW rule</button></div>
                            <pre><code>${escapeHtml(item.rules.ufw)}</code></pre>
                        </details>
                    </div>
                </details>`;
            }).join('');
            container.querySelectorAll('[data-rule]').forEach(button => {
                button.addEventListener('click', () => copyRule(button, decodeURIComponent(button.dataset.rule)));
            });
            container.querySelectorAll('[data-security-query]').forEach(button => {
                button.addEventListener('click', () => openLogExplorer('access', decodeURIComponent(button.dataset.securityQuery)));
            });
            if (activeThreatFilter !== 'all') {
                const selected = document.querySelector(`[data-threat-filter="${activeThreatFilter}"]`);
                activeThreatFilter = 'all';
                if (selected) applyThreatFilter(selected.dataset.threatFilter);
            }
        })
        .catch(error => {
            console.error('Error fetching block recommendations:', error);
            document.getElementById('blockRecommendations').innerHTML =
                '<div class="security-empty security-error">Unable to analyze blocking recommendations.</div>';
        });
}

// Load analytics on page load
fetchAccessStats();
fetchBlockRecommendations();
fetchMonitoringHealth();
fetchActionItems();

// Analytics uses one time range and one request for all three charts.
const charts = {};
const chartConfigs = {};
const chartKeys = ['traffic', 'status', 'visitors'];
const analyticsTimeSelect = document.getElementById('analyticsTimeRange');
const savedAnalyticsRange = localStorage.getItem('analyticsTimeRange') || localStorage.getItem('trafficTimeRange');
if (Array.from(analyticsTimeSelect.options).some(option => option.value === savedAnalyticsRange)) {
    analyticsTimeSelect.value = savedAnalyticsRange;
}
let analyticsRequest = null;

function buildLabels(data, resolution) {
    return data.map(item => {
        if (resolution === 'daily') {
            const [year, month, day] = item.hour.split('-').map(Number);
            return new Date(year, month - 1, day).toLocaleDateString(undefined, {month:'short', day:'numeric'});
        }
        return new Date(item.hour).toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
    });
}

function makeChartConfig(key, labels, data) {
    const datasets = {
        traffic: [{label:'Requests', data:data.map(item => item.requests), borderColor:'#4f6bed', backgroundColor:'rgba(79,107,237,.08)', tension:.3, fill:true, pointRadius:0}],
        status: [
            {label:'Success', data:data.map(item => item.status_success), backgroundColor:'#329879'},
            {label:'Redirects', data:data.map(item => item.status_redirects), backgroundColor:'#6b8dc4'},
            {label:'Client errors', data:data.map(item => item.status_client_errors), backgroundColor:'#d3a044'},
            {label:'Server errors', data:data.map(item => item.status_server_errors), backgroundColor:'#cc6370'}
        ],
        visitors: [{label:'Unique visitors', data:data.map(item => item.unique_ips), backgroundColor:'#8a80bc', borderRadius:3}]
    };
    const config = {
        type:key === 'traffic' ? 'line' : 'bar',
        data:{labels, datasets:datasets[key]},
        options:{
            responsive:true, maintainAspectRatio:false,
            plugins:{legend:{display:key === 'status', position:'bottom', labels:{usePointStyle:true, boxWidth:8, padding:16}}},
            scales:{
                x:{stacked:key === 'status', grid:{display:false}, ticks:{maxTicksLimit:6, maxRotation:0}},
                y:{stacked:key === 'status', beginAtZero:true, border:{display:false}, grid:{color:'#eef0f4'}, ticks:{precision:0}}
            }
        }
    };
    if (key === 'status') {
        config.options.onClick = (event, elements) => {
            if (!elements.length) return;
            closeChartModal();
            openLogExplorer('access', '', String(elements[0].datasetIndex + 2));
        };
        config.options.onHover = (event, elements) => {
            if (event.native) event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
        };
    }
    applyChartTheme(config, key);
    return config;
}

function applyChartTheme(config, key) {
    const styles = getComputedStyle(document.documentElement);
    const color = name => styles.getPropertyValue(name).trim();
    config.options.plugins.legend.labels.color = color('--muted');
    config.options.plugins.tooltip = {
        backgroundColor: color('--surface-hover'), titleColor: color('--ink'),
        bodyColor: color('--ink'), borderColor: color('--line-strong'), borderWidth: 1
    };
    config.options.scales.x.ticks.color = color('--muted');
    config.options.scales.y.ticks.color = color('--muted');
    config.options.scales.x.border = {color: color('--line')};
    config.options.scales.y.grid.color = color('--line');
    if (key === 'traffic') {
        config.data.datasets[0].borderColor = color('--accent');
        config.data.datasets[0].backgroundColor = color('--chart-fill');
    } else if (key === 'status') {
        ['--chart-success', '--chart-info', '--chart-warning', '--chart-danger'].forEach((name, index) => {
            config.data.datasets[index].backgroundColor = color(name);
        });
    } else if (key === 'visitors') {
        config.data.datasets[0].backgroundColor = color('--chart-purple');
    }
}

async function fetchAnalytics() {
    if (analyticsRequest) analyticsRequest.abort();
    const request = new AbortController();
    analyticsRequest = request;
    const hours = analyticsTimeSelect.value === 'all' ? '10000' : analyticsTimeSelect.value;
    chartKeys.forEach(key => {
        const empty = document.getElementById(`${key}ChartEmpty`);
        empty.textContent = 'Loading history…';
        empty.hidden = false;
        document.getElementById(`${key}Chart`).hidden = true;
        document.querySelector(`[data-chart-key="${key}"]`).disabled = true;
    });
    try {
        const response = await fetch(`/api/traffic-chart?hours=${hours}`, {signal:request.signal});
        if (!response.ok) throw new Error('Unable to load history');
        const result = await response.json();
        if (request.signal.aborted) return;
        const data = result.data || [];
        const labels = buildLabels(data, result.resolution);
        chartKeys.forEach(key => {
            if (charts[key]) { charts[key].destroy(); delete charts[key]; }
            delete chartConfigs[key];
            const empty = document.getElementById(`${key}ChartEmpty`);
            const canvas = document.getElementById(`${key}Chart`);
            const canRender = data.length > 0 && typeof Chart !== 'undefined';
            empty.textContent = data.length ? 'Charts could not load. Refresh to try again.' : 'No history in this time range. Data appears as monitoring runs.';
            empty.hidden = canRender;
            canvas.hidden = !canRender;
            document.querySelector(`[data-chart-key="${key}"]`).disabled = !canRender;
            if (canRender) {
                chartConfigs[key] = makeChartConfig(key, labels, data);
                charts[key] = new Chart(canvas, makeChartConfig(key, labels, data));
            }
        });
    } catch (error) {
        if (error.name === 'AbortError') return;
        chartKeys.forEach(key => {
            document.getElementById(`${key}ChartEmpty`).textContent = 'Unable to load history. Change the time range to try again.';
        });
    }
}

analyticsTimeSelect.addEventListener('change', () => {
    localStorage.setItem('analyticsTimeRange', analyticsTimeSelect.value);
    fetchAnalytics();
});
fetchAnalytics();

// ── Auto-refresh ──────────────────────────────────────────────────────

let autoRefreshTimer = null;

function barClass(pct) {
    return 'bar-fill ' + (pct > 90 ? 'bad' : pct > 70 ? 'warn' : 'good');
}

function refreshMetrics() {
    fetch('/api/metrics')
        .then(readJSON)
        .then(m => {
            document.getElementById('cpu-value').textContent = m.cpu_percent + '%';
            const cpuBar = document.getElementById('cpu-bar');
            cpuBar.style.width = m.cpu_percent + '%';
            cpuBar.className = barClass(m.cpu_percent);

            document.getElementById('mem-value').textContent = m.memory.percent + '%';
            document.getElementById('mem-sub').textContent = m.memory.used_gb + ' GB / ' + m.memory.total_gb + ' GB';
            const memBar = document.getElementById('mem-bar');
            memBar.style.width = m.memory.percent + '%';
            memBar.className = barClass(m.memory.percent);

            document.getElementById('disk-value').textContent = m.disk.percent + '%';
            document.getElementById('disk-sub').textContent = m.disk.used_gb + ' GB / ' + m.disk.total_gb + ' GB';
            const diskBar = document.getElementById('disk-bar');
            diskBar.style.width = m.disk.percent + '%';
            diskBar.className = barClass(m.disk.percent);

            const now = new Date();
            document.getElementById('last-updated').textContent =
                'Updated ' + now.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
        })
        .catch(() => {
            document.getElementById('last-updated').textContent = 'Unable to refresh';
        });
}

function refreshAlerts() {
    return fetchActionItems();
}

function startAutoRefresh(seconds) {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
    if (seconds > 0) {
        autoRefreshTimer = setInterval(() => {
            refreshMetrics();
            refreshAlerts();
            fetchMonitoringHealth();
            const visibleView = document.querySelector('[data-view]:not([hidden])').dataset.view;
            if (visibleView === 'security') fetchBlockRecommendations();
            if (visibleView === 'analytics' && !chartDialog.open) {
                fetchAnalytics();
                fetchAccessStats();
            }
        }, seconds * 1000);
    }
}

const autoRefreshSelect = document.getElementById('autoRefreshSelect');
const savedRefresh = localStorage.getItem('autoRefresh');
if (Array.from(autoRefreshSelect.options).some(option => option.value === savedRefresh)) autoRefreshSelect.value = savedRefresh;
autoRefreshSelect.addEventListener('change', function() {
    localStorage.setItem('autoRefresh', this.value);
    startAutoRefresh(parseInt(this.value));
});
startAutoRefresh(parseInt(autoRefreshSelect.value));

// Native dialogs provide focus management, Escape, and keyboard containment.
let modalChartInstance = null;
let modalChartKey = null;
const chartDialog = document.getElementById('chart-modal');

function openChartModal(key, title) {
    const config = chartConfigs[key];
    if (!config) return;
    document.getElementById('modal-chart-title').textContent = title;
    document.getElementById('modalChart').setAttribute('aria-label', title);
    chartDialog.showModal();
    modalChartKey = key;
    // Clone the configuration without discarding the status chart's drill-down handlers.
    const expanded = { ...config, data:{...config.data, datasets:config.data.datasets.map(dataset => ({...dataset}))}, options:{...config.options} };
    modalChartInstance = new Chart(document.getElementById('modalChart'), expanded);
}

function closeChartModal() {
    if (chartDialog.open) chartDialog.close();
}

chartDialog.addEventListener('close', () => {
    if (modalChartInstance) { modalChartInstance.destroy(); modalChartInstance = null; }
    modalChartKey = null;
});
document.getElementById('closeChartModal').addEventListener('click', closeChartModal);
document.querySelectorAll('[data-chart-key]').forEach(button => {
    button.addEventListener('click', () => openChartModal(button.dataset.chartKey, button.dataset.chartTitle));
});

// Appearance and refresh preferences share one small settings panel.
const settingsDialog = document.getElementById('settingsDialog');
document.getElementById('openSettings').addEventListener('click', () => settingsDialog.showModal());

function syncThemeChoices() {
    const preference = window.ApacheWatchTheme.getPreference();
    document.querySelectorAll('[data-theme-choice]').forEach(button => {
        button.setAttribute('aria-pressed', String(button.dataset.themeChoice === preference));
    });
}
document.querySelectorAll('[data-theme-choice]').forEach(button => {
    button.addEventListener('click', () => {
        window.ApacheWatchTheme.setPreference(button.dataset.themeChoice);
        document.getElementById('settingsSaved').textContent = 'Appearance saved in this browser.';
    });
});
autoRefreshSelect.addEventListener('change', () => {
    document.getElementById('settingsSaved').textContent = 'Refresh preference saved in this browser.';
});
document.addEventListener('apachewatch:themechange', () => {
    syncThemeChoices();
    Object.entries(charts).forEach(([key, chart]) => {
        applyChartTheme(chart.config, key);
        applyChartTheme(chartConfigs[key], key);
        chart.update('none');
    });
    if (modalChartInstance) {
        applyChartTheme(modalChartInstance.config, modalChartKey);
        modalChartInstance.update('none');
    }
});
syncThemeChoices();
syncViewFromHash();
