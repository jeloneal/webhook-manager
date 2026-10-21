const API_BASE = '/api';

let webhooks = [];
const filters = { search: '', tag: null, sort: 'name' };

const $ = (id) => document.getElementById(id);

// DOM-Helfer: baut Elemente ohne innerHTML (Texte werden immer als Text eingefügt)
function h(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
        else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of children.flat()) {
        if (child !== null && child !== undefined && child !== false) node.append(child);
    }
    return node;
}

// API-Aufruf; bei abgelaufener Sitzung zurück zum Login
async function api(path, { method = 'GET', body } = {}) {
    const options = { method, credentials: 'include', headers: {} };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }
    const response = await fetch(`${API_BASE}${path}`, options);
    if (response.status === 401 && path !== '/login') {
        showLoginScreen();
        throw new Error('Sitzung abgelaufen, bitte neu anmelden');
    }
    return response;
}

async function errorMessage(response, fallback) {
    try {
        return (await response.json()).error || fallback;
    } catch {
        return fallback;
    }
}

// --- Anmeldung -------------------------------------------------------------

async function checkAuth() {
    try {
        const data = await (await api('/status')).json();
        if (data.authenticated) {
            showMainScreen();
            loadWebhooks();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

async function login(event) {
    event.preventDefault();
    try {
        const response = await api('/login', { method: 'POST', body: { password: $('passwordInput').value } });
        if (response.ok) {
            $('passwordInput').value = '';
            showMainScreen();
            loadWebhooks();
        } else {
            showAlert('loginAlert', await errorMessage(response, 'Login fehlgeschlagen'), 'error');
        }
    } catch {
        showAlert('loginAlert', 'Verbindungsfehler', 'error');
    }
}

async function logout() {
    try {
        await api('/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }
    showLoginScreen();
}

function showLoginScreen() {
    closeAllDialogs();
    $('mainScreen').style.display = 'none';
    $('loginScreen').style.display = 'block';
    $('passwordInput').value = '';
}

function showMainScreen() {
    $('loginScreen').style.display = 'none';
    $('mainScreen').style.display = 'block';
}

function closeAllDialogs() {
    document.querySelectorAll('dialog[open]').forEach((dialog) => dialog.close());
}

// --- Liste -----------------------------------------------------------------

async function loadWebhooks() {
    try {
        const response = await api('/webhooks');
        if (!response.ok) throw new Error('Failed to load webhooks');
        webhooks = await response.json();
        renderTagFilter();
        renderWebhooks();
    } catch (error) {
        if (!$('webhookList').querySelector('.webhook-grid')) {
            $('webhookList').replaceChildren(h('div', { class: 'empty-state' }, 'Fehler beim Laden der Webhooks'));
        }
    }
}

function relativeTime(iso) {
    const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (seconds < 60) return 'gerade eben';
    if (seconds < 3600) return `vor ${Math.floor(seconds / 60)} Min.`;
    if (seconds < 86400) return `vor ${Math.floor(seconds / 3600)} Std.`;
    if (seconds < 86400 * 30) return `vor ${Math.floor(seconds / 86400)} Tag(en)`;
    return new Date(iso).toLocaleDateString('de-DE');
}

function absoluteTime(iso) {
    return new Date(iso).toLocaleString('de-DE');
}

function visibleWebhooks() {
    const needle = filters.search.trim().toLowerCase();
    const matches = webhooks.filter((w) => {
        if (filters.tag && !w.tags.includes(filters.tag)) return false;
        if (!needle) return true;
        return [w.name, w.url, w.description, ...w.tags].some((text) => (text || '').toLowerCase().includes(needle));
    });
    const sorters = {
        name: (a, b) => a.name.localeCompare(b.name, 'de', { sensitivity: 'base' }),
        recent: (a, b) => (b.last_triggered_at || '').localeCompare(a.last_triggered_at || ''),
        created: (a, b) => b.id - a.id,
    };
    return matches.sort(sorters[filters.sort] || sorters.name);
}

function renderTagFilter() {
    const tags = [...new Set(webhooks.flatMap((w) => w.tags))].sort((a, b) => a.localeCompare(b, 'de'));
    if (filters.tag && !tags.includes(filters.tag)) filters.tag = null;
    $('tagFilter').replaceChildren(...tags.map((tag) => h('button', {
        type: 'button',
        class: `tag${filters.tag === tag ? ' active' : ''}`,
        'aria-pressed': String(filters.tag === tag),
        onclick: () => {
            filters.tag = filters.tag === tag ? null : tag;
            renderTagFilter();
            renderWebhooks();
        },
    }, tag)));
}

function lastRunLine(webhook) {
    if (!webhook.last_triggered_at) return h('div', { class: 'last-run' }, 'Noch nie ausgelöst');
    const ok = webhook.last_success;
    const status = webhook.last_status_code ? ` (HTTP ${webhook.last_status_code})` : '';
    return h('div', {
        class: `last-run ${ok ? 'ok' : 'fail'}`,
        title: absoluteTime(webhook.last_triggered_at),
    }, `${ok ? '✅' : '❌'} Zuletzt ${relativeTime(webhook.last_triggered_at)}${status}`);
}

function renderWebhooks() {
    const container = $('webhookList');

    if (webhooks.length === 0) {
        container.replaceChildren(h('div', { class: 'empty-state' },
            h('div', { class: 'empty-state-icon' }, '📭'),
            h('h3', {}, 'Keine Webhooks vorhanden'),
            h('p', {}, 'Klicke auf "Neu anlegen" um deinen ersten Webhook zu erstellen')));
        return;
    }

    const items = visibleWebhooks();
    if (items.length === 0) {
        container.replaceChildren(h('div', { class: 'empty-state' }, h('p', {}, 'Keine Treffer für die aktuelle Suche')));
        return;
    }

    const grid = h('div', { class: 'webhook-grid' }, items.map((webhook) => h('div', { class: 'webhook-card' },
        h('div', { class: 'webhook-top' },
            h('div', { class: 'webhook-method' }, webhook.method),
            webhook.verify_tls ? null : h('span', { class: 'tag', title: 'TLS-Zertifikat wird nicht geprüft' }, 'TLS aus')),
        h('div', { class: 'webhook-name' }, webhook.name),
        h('div', { class: 'webhook-url' }, webhook.url),
        h('div', { class: 'webhook-description' }, webhook.description),
        webhook.tags.length ? h('div', { class: 'webhook-tags' }, webhook.tags.map((tag) => h('span', { class: 'tag' }, tag))) : null,
        lastRunLine(webhook),
        h('div', { class: 'webhook-actions' },
            h('button', { class: 'btn-trigger', 'data-action': 'trigger', 'data-id': webhook.id }, '▶️ Auslösen'),
            h('button', { class: 'btn-history', 'data-action': 'history', 'data-id': webhook.id, title: 'Verlauf', 'aria-label': 'Verlauf' }, '📜'),
            h('button', { class: 'btn-edit', 'data-action': 'edit', 'data-id': webhook.id, title: 'Bearbeiten', 'aria-label': 'Bearbeiten' }, '✏️'),
            h('button', { class: 'btn-delete', 'data-action': 'delete', 'data-id': webhook.id, title: 'Löschen', 'aria-label': 'Löschen' }, '🗑️')))));
    container.replaceChildren(grid);
}

// --- Dialoge ---------------------------------------------------------------

function confirmDialog(title, message, okLabel = 'OK') {
    return new Promise((resolve) => {
        const dialog = $('confirmDialog');
        $('confirmTitle').textContent = title;
        $('confirmMessage').textContent = message;
        $('confirmOk').textContent = okLabel;
        dialog.returnValue = '';
        dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), { once: true });
        dialog.showModal();
        $('confirmCancel').focus();
    });
}

function headersToText(headers) {
    return Object.entries(headers || {}).map(([name, value]) => `${name}: ${value}`).join('\n');
}

function textToHeaders(text) {
    const headers = {};
    for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        const index = line.indexOf(':');
        if (index < 1) throw new Error(`Ungültige Header-Zeile: "${line.trim().slice(0, 40)}" (erwartet "Name: Wert")`);
        headers[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
    return headers;
}

function openWebhookDialog(webhook) {
    $('webhookForm').reset();
    $('formError').classList.add('hidden');
    $('modalTitle').textContent = webhook ? 'Webhook bearbeiten' : 'Neuer Webhook';
    $('webhookId').value = webhook ? webhook.id : '';
    if (webhook) {
        $('webhookName').value = webhook.name;
        $('webhookUrl').value = webhook.url;
        $('webhookMethod').value = webhook.method;
        $('webhookDescription').value = webhook.description || '';
        $('webhookTags').value = webhook.tags.join(', ');
        $('webhookHeaders').value = headersToText(webhook.headers);
        $('webhookBody').value = webhook.body || '';
        $('webhookTimeout').value = webhook.timeout;
        $('webhookRetries').value = webhook.retries;
        $('webhookVerifyTls').checked = webhook.verify_tls;
    }
    // Erweiterte Einstellungen aufklappen, wenn dort etwas vom Standard abweicht
    $('advancedDetails').open = Boolean(webhook && (
        Object.keys(webhook.headers).length || webhook.body || webhook.timeout !== 30 || webhook.retries !== 0 || !webhook.verify_tls));
    $('webhookDialog').showModal();
}

function showFormError(message) {
    $('formError').textContent = message;
    $('formError').classList.remove('hidden');
}

async function saveWebhook(event) {
    event.preventDefault();
    const id = $('webhookId').value;

    let headers;
    try {
        headers = textToHeaders($('webhookHeaders').value);
    } catch (error) {
        $('advancedDetails').open = true;
        showFormError(error.message);
        return;
    }

    const data = {
        name: $('webhookName').value,
        url: $('webhookUrl').value,
        method: $('webhookMethod').value,
        description: $('webhookDescription').value,
        tags: $('webhookTags').value,
        headers,
        body: $('webhookBody').value,
        timeout: $('webhookTimeout').value,
        retries: $('webhookRetries').value,
        verify_tls: $('webhookVerifyTls').checked,
    };

    try {
        const response = await api(id ? `/webhooks/${id}` : '/webhooks', { method: id ? 'PUT' : 'POST', body: data });
        if (response.ok) {
            $('webhookDialog').close();
            showAlert('mainAlert', 'Webhook erfolgreich gespeichert', 'success');
            loadWebhooks();
        } else {
            showFormError(await errorMessage(response, 'Fehler beim Speichern'));
        }
    } catch (error) {
        showFormError(error.message || 'Verbindungsfehler beim Speichern');
    }
}

async function deleteWebhook(id) {
    const webhook = webhooks.find((w) => w.id === id);
    if (!webhook) return;
    if (!await confirmDialog('Webhook löschen', `„${webhook.name}" wirklich löschen? Der Verlauf dazu wird ebenfalls gelöscht.`, 'Löschen')) return;

    try {
        const response = await api(`/webhooks/${id}`, { method: 'DELETE' });
        if (response.ok) {
            showAlert('mainAlert', 'Webhook erfolgreich gelöscht', 'success');
            loadWebhooks();
        } else {
            showAlert('mainAlert', await errorMessage(response, 'Fehler beim Löschen'), 'error');
        }
    } catch (error) {
        showAlert('mainAlert', error.message || 'Verbindungsfehler beim Löschen', 'error');
    }
}

async function triggerWebhook(id, button) {
    const webhook = webhooks.find((w) => w.id === id);
    if (!webhook) return;
    if (!await confirmDialog('Webhook auslösen', `„${webhook.name}" jetzt auslösen?\n${webhook.method} ${webhook.url}`, 'Auslösen')) return;

    const label = button.textContent;
    button.disabled = true;
    button.textContent = '⏳ läuft…';
    try {
        const response = await api(`/webhooks/${id}/trigger`, { method: 'POST' });
        const result = await response.json().catch(() => ({}));
        if (response.ok) {
            const retries = result.attempts > 1 ? `, ${result.attempts} Versuche` : '';
            showAlert('mainAlert', `✅ „${webhook.name}" ausgelöst (HTTP ${result.status_code}, ${result.duration_ms} ms${retries})`, 'success');
        } else {
            const status = result.status_code ? ` (HTTP ${result.status_code})` : '';
            showAlert('mainAlert', `❌ „${webhook.name}": ${result.error || 'Fehler'}${status}`, 'error', 10000);
        }
    } catch (error) {
        showAlert('mainAlert', `❌ ${error.message || 'Verbindungsfehler beim Auslösen'}`, 'error', 10000);
    } finally {
        button.disabled = false;
        button.textContent = label;
        loadWebhooks();
    }
}

// --- Verlauf ---------------------------------------------------------------

async function showHistory(webhookId) {
    const webhook = webhooks.find((w) => w.id === webhookId);
    $('historyTitle').textContent = webhook ? `Verlauf: ${webhook.name}` : 'Verlauf aller Webhooks';
    $('clearHistoryButton').classList.toggle('hidden', Boolean(webhook));
    $('historyBody').replaceChildren(h('div', { class: 'loading' }, 'Lade Verlauf...'));
    $('historyDialog').showModal();

    try {
        const response = await api(webhook ? `/webhooks/${webhookId}/history?limit=100` : '/history?limit=100');
        if (!response.ok) throw new Error(await errorMessage(response, 'Verlauf konnte nicht geladen werden'));
        const rows = await response.json();
        if (rows.length === 0) {
            $('historyBody').replaceChildren(h('div', { class: 'empty-state' }, 'Noch keine Auslösungen'));
            return;
        }
        $('historyBody').replaceChildren(h('div', { class: 'history-wrap' }, h('table', { class: 'history-table' },
            h('thead', {}, h('tr', {}, ['Zeitpunkt', webhook ? null : 'Webhook', 'Ergebnis', 'Dauer', 'Versuche', 'Fehler']
                .map((title) => (title ? h('th', {}, title) : null)))),
            h('tbody', {}, rows.map((row) => h('tr', {},
                h('td', { title: absoluteTime(row.triggered_at) }, absoluteTime(row.triggered_at)),
                webhook ? null : h('td', {}, row.webhook_name),
                h('td', { class: row.success ? 'ok' : 'fail' }, `${row.success ? '✅ OK' : '❌ Fehler'}${row.status_code ? ` (HTTP ${row.status_code})` : ''}`),
                h('td', {}, row.duration_ms === null ? '–' : `${row.duration_ms} ms`),
                h('td', {}, String(row.attempts)),
                h('td', {}, row.error || '')))))));
    } catch (error) {
        $('historyBody').replaceChildren(h('div', { class: 'alert alert-error' }, error.message));
    }
}

async function clearHistory() {
    if (!await confirmDialog('Verlauf löschen', 'Den gesamten Verlauf aller Webhooks löschen?', 'Löschen')) return;
    try {
        const response = await api('/history', { method: 'DELETE' });
        if (!response.ok) throw new Error(await errorMessage(response, 'Verlauf konnte nicht gelöscht werden'));
        $('historyDialog').close();
        showAlert('mainAlert', 'Verlauf gelöscht', 'success');
        loadWebhooks();
    } catch (error) {
        showAlert('mainAlert', error.message, 'error');
    }
}

// --- Export / Import -------------------------------------------------------

async function exportWebhooks() {
    if (!await confirmDialog('Export', 'Der Export enthält die Header-Werte (z. B. API-Tokens) im Klartext. Datei sicher aufbewahren.', 'Exportieren')) return;
    try {
        const response = await api('/export');
        if (!response.ok) throw new Error(await errorMessage(response, 'Export fehlgeschlagen'));
        const match = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '');
        const url = URL.createObjectURL(await response.blob());
        const link = h('a', { href: url, download: match ? match[1] : 'webhooks.json' });
        document.body.append(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
    } catch (error) {
        showAlert('mainAlert', error.message, 'error');
    }
}

async function importWebhooks(event) {
    const input = event.target;
    const file = input.files[0];
    input.value = '';
    if (!file) return;

    let data;
    try {
        data = JSON.parse(await file.text());
    } catch {
        showAlert('mainAlert', 'Die Datei ist kein gültiges JSON', 'error');
        return;
    }
    const count = Array.isArray(data.webhooks) ? data.webhooks.length : 0;
    if (!count) {
        showAlert('mainAlert', 'Die Datei enthält keine Webhooks', 'error');
        return;
    }
    if (!await confirmDialog('Import', `${count} Webhook(s) aus „${file.name}" importieren? Bereits vorhandene (gleicher Name, URL und Methode) werden übersprungen.`, 'Importieren')) return;

    try {
        const response = await api('/import', { method: 'POST', body: data });
        if (!response.ok) throw new Error(await errorMessage(response, 'Import fehlgeschlagen'));
        const result = await response.json();
        let message = `${result.imported} importiert, ${result.skipped} übersprungen`;
        if (result.errors.length) {
            message += `, ${result.errors.length} fehlerhaft (z. B. Eintrag ${result.errors[0].index + 1}: ${result.errors[0].error})`;
        }
        showAlert('mainAlert', message, result.errors.length ? 'error' : 'success', result.errors.length ? 10000 : 5000);
        loadWebhooks();
    } catch (error) {
        showAlert('mainAlert', error.message, 'error');
    }
}

// --- Hilfsfunktionen -------------------------------------------------------

const alertTimers = {};

function showAlert(containerId, message, type, duration = 5000) {
    const container = $(containerId);
    clearTimeout(alertTimers[containerId]);
    container.replaceChildren(h('div', { class: `alert alert-${type}` }, message));
    alertTimers[containerId] = setTimeout(() => container.replaceChildren(), duration);
}

// --- Event-Handler (keine Inline-Handler wegen Content-Security-Policy) ----

// Klick auf den Hintergrund schließt einen Dialog; Escape funktioniert nativ
document.querySelectorAll('dialog').forEach((dialog) => {
    dialog.addEventListener('click', (e) => {
        if (e.target === dialog) dialog.close();
    });
});

$('loginForm').addEventListener('submit', login);
$('webhookForm').addEventListener('submit', saveWebhook);
$('createButton').addEventListener('click', () => openWebhookDialog(null));
$('logoutButton').addEventListener('click', logout);
$('historyButton').addEventListener('click', () => showHistory(null));
$('exportButton').addEventListener('click', exportWebhooks);
$('importButton').addEventListener('click', () => $('importFile').click());
$('importFile').addEventListener('change', importWebhooks);
$('cancelButton').addEventListener('click', () => $('webhookDialog').close());
$('closeHistoryButton').addEventListener('click', () => $('historyDialog').close());
$('clearHistoryButton').addEventListener('click', clearHistory);
$('confirmOk').addEventListener('click', () => $('confirmDialog').close('ok'));
$('confirmCancel').addEventListener('click', () => $('confirmDialog').close('cancel'));

$('searchInput').addEventListener('input', (e) => {
    filters.search = e.target.value;
    renderWebhooks();
});
$('sortSelect').addEventListener('change', (e) => {
    filters.sort = e.target.value;
    renderWebhooks();
});

const webhookActions = {
    trigger: (id, button) => triggerWebhook(id, button),
    history: (id) => showHistory(id),
    edit: (id) => openWebhookDialog(webhooks.find((w) => w.id === id)),
    delete: (id) => deleteWebhook(id),
};
$('webhookList').addEventListener('click', (e) => {
    const button = e.target.closest('button[data-action]');
    const action = button && webhookActions[button.dataset.action];
    if (action) action(Number(button.dataset.id), button);
});

checkAuth();
