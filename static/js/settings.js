// Browser preferences and server settings live in three focused sections.
const settingsDialog = document.getElementById('settingsDialog');
document.getElementById('openSettings').addEventListener('click', () => {
    settingsDialog.showModal();
    fetchThresholdSettings();
    fetchEmailStatus();
    if (emailStatusTimer) clearInterval(emailStatusTimer);
    emailStatusTimer = setInterval(fetchEmailStatus, 5000);
});
let emailStatusTimer = null;
let emailSaving = false;
let emailStatusRequestId = 0;
let emailTestSending = false;
let queuedTestId = null;
let currentEmailRecipients = null;
const emailEnabled = document.getElementById('emailNotificationsEnabled');
const emailSeverity = document.getElementById('emailSeverity');
const testEmailButton = document.getElementById('sendTestEmail');
const recipientInput = document.getElementById('emailRecipientInput');
const addRecipientButton = document.getElementById('addEmailRecipient');
settingsDialog.addEventListener('close', () => {
    if (emailStatusTimer) clearInterval(emailStatusTimer);
    emailStatusTimer = null;
});

function renderEmailStatus(status) {
    const recipients = status.recipients || [];
    document.getElementById('emailRecipient').textContent = recipients.length ? `${recipients.length} recipient${recipients.length === 1 ? '' : 's'}${recipients.length >= 20 ? ' · Maximum reached' : ''}` : 'Add someone to receive alerts when email delivery is connected.';
    if (JSON.stringify(currentEmailRecipients) !== JSON.stringify(recipients)) {
        currentEmailRecipients = recipients;
        const list = document.getElementById('emailRecipientList');
        list.replaceChildren();
        recipients.forEach((address, index) => {
            const row = document.createElement('li');
            const text = document.createElement('span');
            text.textContent = address;
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'text-button';
            remove.textContent = 'Remove';
            remove.setAttribute('aria-label', `Remove ${address}`);
            remove.addEventListener('click', () => saveEmailPreferences({recipients:currentEmailRecipients.filter((_, position) => position !== index)}));
            row.append(text, remove);
            list.append(row);
        });
    }
    recipientInput.disabled = recipients.length >= 20;
    addRecipientButton.disabled = recipients.length >= 20;
    document.querySelectorAll('#emailRecipientList button').forEach(button => button.disabled = false);
    emailEnabled.checked = Boolean(status.enabled);
    emailEnabled.disabled = false;
    emailSeverity.value = status.severity || 'critical';
    emailSeverity.disabled = false;
    testEmailButton.disabled = !status.configured || !status.monitoring_active || emailTestSending || Boolean(queuedTestId);
    let message;
    if (!status.configured) message = 'Sender not connected. Email delivery needs a sending service.';
    else if (status.monitor_error) message = status.monitor_error;
    else if (!status.monitoring_active) message = 'Background checks are not running. Start the monitoring worker to send email.';
    else if (status.delivery_error) message = 'Delivery failed. Check the sender connection; unsuccessful emails are retried.';
    else message = status.enabled ? `Email alerts enabled. Background checks run every ${status.interval_seconds} seconds.` : 'Email alerts are off.';
    if (status.last_sent_at) message += ` Last email: ${new Date(status.last_sent_at).toLocaleString()}.`;
    document.getElementById('emailDeliveryStatus').textContent = message;
    if (queuedTestId && status.test && status.test.id === queuedTestId) {
        const notice = document.getElementById('emailNotificationMessage');
        if (status.test.status === 'sent') {
            notice.textContent = 'Test email sent. Check the recipient’s inbox.';
            notice.hidden = false;
            queuedTestId = null;
            testEmailButton.disabled = !status.configured || !status.monitoring_active;
        } else if (status.test.status === 'failed') {
            notice.textContent = 'Test email could not be delivered. Check the sender connection.';
            notice.hidden = false;
            queuedTestId = null;
            testEmailButton.disabled = !status.configured || !status.monitoring_active;
        }
    }
}

function fetchEmailStatus() {
    if (emailSaving) return;
    const requestId = ++emailStatusRequestId;
    fetch('/api/notifications/email').then(readSettingsJSON).then(status => {
        if (!emailSaving && requestId === emailStatusRequestId) renderEmailStatus(status);
    }).catch(() => {
        if (emailSaving || requestId !== emailStatusRequestId) return;
        document.getElementById('emailDeliveryStatus').textContent = 'Unable to check email delivery. Reopen Settings to try again.';
        emailEnabled.disabled = true;
        emailSeverity.disabled = true;
        testEmailButton.disabled = true;
        recipientInput.disabled = true;
        addRecipientButton.disabled = true;
        document.querySelectorAll('#emailRecipientList button').forEach(button => button.disabled = true);
    });
}

function saveEmailPreferences(changes = {enabled:emailEnabled.checked, severity:emailSeverity.value}) {
    if (emailSaving) return Promise.resolve(false);
    emailSaving = true;
    ++emailStatusRequestId;
    emailEnabled.disabled = true;
    emailSeverity.disabled = true;
    recipientInput.disabled = true;
    addRecipientButton.disabled = true;
    testEmailButton.disabled = true;
    document.querySelectorAll('#emailRecipientList button').forEach(button => button.disabled = true);
    const notice = document.getElementById('emailNotificationMessage');
    return fetch('/api/notifications/email', {
        method:'PATCH', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(changes)
    }).then(readSettingsJSON).then(status => {
        renderEmailStatus(status);
        notice.classList.remove('settings-error');
        notice.textContent = changes.recipients ? 'Recipients saved for this server.' : 'Email preferences saved for this server.';
        notice.hidden = false;
        return true;
    }).catch(error => {
        notice.classList.add('settings-error');
        notice.textContent = error.message || 'Unable to save email preferences. Please try again.';
        notice.hidden = false;
        return false;
    }).finally(() => {
        emailSaving = false;
        fetchEmailStatus();
    });
}
emailEnabled.addEventListener('change', () => saveEmailPreferences());
emailSeverity.addEventListener('change', () => saveEmailPreferences());
document.getElementById('emailRecipientForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (emailSaving || currentEmailRecipients === null) return;
    const address = recipientInput.value.trim();
    if (currentEmailRecipients.some(value => value.toLowerCase() === address.toLowerCase())) {
        const notice = document.getElementById('emailNotificationMessage');
        notice.textContent = 'That recipient is already listed.';
        notice.classList.add('settings-error');
        notice.hidden = false;
        return;
    }
    if (await saveEmailPreferences({recipients:[...currentEmailRecipients, address]})) recipientInput.value = '';
});
testEmailButton.addEventListener('click', () => {
    emailTestSending = true;
    testEmailButton.disabled = true;
    const notice = document.getElementById('emailNotificationMessage');
    fetch('/api/notifications/email/test', {
        method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'
    }).then(async response => {
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Unable to queue a test email.');
        queuedTestId = result.id;
        notice.textContent = 'Test email queued. Delivery may take up to a minute.';
        notice.hidden = false;
    }).catch(error => {
        notice.textContent = error.message;
        notice.hidden = false;
    }).finally(() => {
        emailTestSending = false;
        fetchEmailStatus();
    });
});

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

async function readSettingsJSON(response) {
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to save settings. Please try again.');
    return result;
}

const settingsTabs = Array.from(document.querySelectorAll('[data-settings-tab]'));
function showSettingsTab(name) {
    settingsTabs.forEach(tab => {
        const selected = tab.dataset.settingsTab === name;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
    });
    document.querySelectorAll('[data-settings-panel]').forEach(panel => panel.hidden = panel.dataset.settingsPanel !== name);
}
settingsTabs.forEach((tab, index) => {
    tab.addEventListener('click', () => showSettingsTab(tab.dataset.settingsTab));
    tab.addEventListener('keydown', event => {
        const indexByKey = {ArrowRight:(index + 1) % settingsTabs.length, ArrowLeft:(index + settingsTabs.length - 1) % settingsTabs.length, Home:0, End:settingsTabs.length - 1};
        if (!(event.key in indexByKey)) return;
        event.preventDefault();
        const next = settingsTabs[indexByKey[event.key]];
        showSettingsTab(next.dataset.settingsTab);
        next.focus();
    });
});

const thresholdForm = document.getElementById('thresholdSettingsForm');
let thresholdsSaving = false;
let thresholdRequestId = 0;

function setThresholdControls(disabled) {
    thresholdForm.querySelectorAll('input, button').forEach(control => control.disabled = disabled);
}

function displayThresholds(result) {
    Object.entries(result.thresholds).forEach(([name, value]) => {
        if (thresholdForm.elements.namedItem(name)) thresholdForm.elements.namedItem(name).value = value;
    });
}

async function fetchThresholdSettings() {
    if (thresholdsSaving) return;
    const requestId = ++thresholdRequestId;
    const message = document.getElementById('thresholdSettingsMessage');
    setThresholdControls(true);
    message.textContent = 'Loading thresholds…';
    message.classList.remove('settings-error');
    try {
        const result = await fetch('/api/settings/thresholds').then(readSettingsJSON);
        if (requestId !== thresholdRequestId) return;
        displayThresholds(result);
        setThresholdControls(false);
        message.textContent = '';
    } catch (_) {
        if (requestId !== thresholdRequestId) return;
        message.textContent = 'Unable to load thresholds. Reopen Settings to try again.';
        message.classList.add('settings-error');
    }
}

thresholdForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (thresholdsSaving) return;
    thresholdsSaving = true;
    ++thresholdRequestId;
    const thresholds = Object.fromEntries(Array.from(thresholdForm.querySelectorAll('input')).map(input => [input.name, input.valueAsNumber]));
    const message = document.getElementById('thresholdSettingsMessage');
    setThresholdControls(true);
    message.classList.remove('settings-error');
    message.textContent = 'Saving thresholds…';
    try {
        const result = await fetch('/api/settings/thresholds', {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({thresholds})}).then(readSettingsJSON);
        displayThresholds(result);
        message.textContent = 'Thresholds saved for this server.';
        fetchActionItems();
    } catch (error) {
        message.classList.add('settings-error');
        message.textContent = error.message;
    } finally {
        thresholdsSaving = false;
        setThresholdControls(false);
    }
});
