const API_BASE = '/api';
let webhooks = [];

// Check authentication status on load
async function checkAuth() {
    try {
        const response = await fetch(`${API_BASE}/status`, {
            credentials: 'include'
        });
        const data = await response.json();

        if (data.authenticated) {
            showMainScreen();
            loadWebhooks();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

// Login
async function login(event) {
    event.preventDefault();
    const password = document.getElementById('passwordInput').value;

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({ password })
        });

        if (response.ok) {
            showMainScreen();
            loadWebhooks();
        } else {
            const data = await response.json();
            showAlert('loginAlert', data.error || 'Login fehlgeschlagen', 'error');
        }
    } catch (error) {
        showAlert('loginAlert', 'Verbindungsfehler', 'error');
    }
}

// Logout
async function logout() {
    try {
        await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            credentials: 'include'
        });
    } catch (error) {
        console.error('Logout error:', error);
    }

    document.getElementById('mainScreen').style.display = 'none';
    document.getElementById('loginScreen').style.display = 'block';
    document.getElementById('passwordInput').value = '';
}

// Show main screen
function showMainScreen() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('mainScreen').style.display = 'block';
}

// Load webhooks
async function loadWebhooks() {
    try {
        const response = await fetch(`${API_BASE}/webhooks`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to load webhooks');
        }

        webhooks = await response.json();
        renderWebhooks();
    } catch (error) {
        document.getElementById('webhookList').innerHTML = 
            '<div class="empty-state">Fehler beim Laden der Webhooks</div>';
    }
}

// Render webhooks
function renderWebhooks() {
    const container = document.getElementById('webhookList');

    if (webhooks.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📭</div>
                <h3>Keine Webhooks vorhanden</h3>
                <p>Klicke auf "Neu anlegen" um deinen ersten Webhook zu erstellen</p>
            </div>
        `;
        return;
    }

    container.innerHTML = '<div class="webhook-grid"></div>';
    const grid = container.querySelector('.webhook-grid');

    webhooks.forEach(webhook => {
        const card = document.createElement('div');
        card.className = 'webhook-card';
        card.innerHTML = `
            <div class="webhook-method">${escapeHtml(webhook.method)}</div>
            <div class="webhook-name">${escapeHtml(webhook.name)}</div>
            <div class="webhook-url">${escapeHtml(webhook.url)}</div>
            <div class="webhook-description">${escapeHtml(webhook.description || '')}</div>
            <div class="webhook-actions">
                <button class="btn-trigger" data-action="triggerWebhook" data-id="${webhook.id}">
                    ▶️ Auslösen
                </button>
                <button class="btn-edit" data-action="editWebhook" data-id="${webhook.id}">
                    ✏️
                </button>
                <button class="btn-delete" data-action="deleteWebhook" data-id="${webhook.id}">
                    🗑️
                </button>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Show create modal
function showCreateModal() {
    document.getElementById('modalTitle').textContent = 'Neuer Webhook';
    document.getElementById('webhookForm').reset();
    document.getElementById('webhookId').value = '';
    document.getElementById('webhookModal').classList.add('active');
}

// Edit webhook
function editWebhook(id) {
    const webhook = webhooks.find(w => w.id === id);
    if (!webhook) return;

    document.getElementById('modalTitle').textContent = 'Webhook bearbeiten';
    document.getElementById('webhookId').value = webhook.id;
    document.getElementById('webhookName').value = webhook.name;
    document.getElementById('webhookUrl').value = webhook.url;
    document.getElementById('webhookMethod').value = webhook.method;
    document.getElementById('webhookDescription').value = webhook.description || '';
    document.getElementById('webhookModal').classList.add('active');
}

// Close modal
function closeModal() {
    document.getElementById('webhookModal').classList.remove('active');
    document.getElementById('webhookForm').reset();
}

// Save webhook
async function saveWebhook(event) {
    event.preventDefault();

    const id = document.getElementById('webhookId').value;
    const data = {
        name: document.getElementById('webhookName').value,
        url: document.getElementById('webhookUrl').value,
        method: document.getElementById('webhookMethod').value,
        description: document.getElementById('webhookDescription').value
    };

    try {
        const url = id ? `${API_BASE}/webhooks/${id}` : `${API_BASE}/webhooks`;
        const method = id ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method,
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify(data)
        });

        if (response.ok) {
            closeModal();
            showAlert('mainAlert', 'Webhook erfolgreich gespeichert', 'success');
            loadWebhooks();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Speichern');
        }
    } catch (error) {
        alert('Verbindungsfehler beim Speichern');
    }
}

// Delete webhook
async function deleteWebhook(id) {
    if (!confirm('Webhook wirklich löschen?')) return;

    try {
        const response = await fetch(`${API_BASE}/webhooks/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        if (response.ok) {
            showAlert('mainAlert', 'Webhook erfolgreich gelöscht', 'success');
            loadWebhooks();
        } else {
            const error = await response.json();
            alert(error.error || 'Fehler beim Löschen');
        }
    } catch (error) {
        alert('Verbindungsfehler beim Löschen');
    }
}

// Trigger webhook
async function triggerWebhook(id) {
    const webhook = webhooks.find(w => w.id === id);
    if (!webhook) return;

    if (!confirm(`Webhook "${webhook.name}" jetzt auslösen?`)) return;

    try {
        const response = await fetch(`${API_BASE}/webhooks/${id}/trigger`, {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            const result = await response.json();
            showAlert('mainAlert', 
                `✅ Webhook erfolgreich ausgelöst (Status: ${result.status_code})`, 
                'success'
            );
        } else {
            const error = await response.json();
            showAlert('mainAlert', 
                `❌ Fehler: ${error.error}`, 
                'error'
            );
        }
    } catch (error) {
        showAlert('mainAlert', '❌ Verbindungsfehler beim Auslösen', 'error');
    }
}

// Show alert
function showAlert(containerId, message, type) {
    const container = document.getElementById(containerId);
    container.innerHTML = `
        <div class="alert alert-${type}">
            ${escapeHtml(message)}
        </div>
    `;

    setTimeout(() => {
        container.innerHTML = '';
    }, 5000);
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal on outside click
document.getElementById('webhookModal').addEventListener('click', (e) => {
    if (e.target.id === 'webhookModal') {
        closeModal();
    }
});

// Event-Handler (keine Inline-Handler wegen Content-Security-Policy)
document.getElementById('loginForm').addEventListener('submit', login);
document.getElementById('webhookForm').addEventListener('submit', saveWebhook);
document.getElementById('createButton').addEventListener('click', showCreateModal);
document.getElementById('logoutButton').addEventListener('click', logout);
document.getElementById('cancelButton').addEventListener('click', closeModal);

const webhookActions = { triggerWebhook, editWebhook, deleteWebhook };
document.getElementById('webhookList').addEventListener('click', (e) => {
    const button = e.target.closest('button[data-action]');
    const action = button && webhookActions[button.dataset.action];
    if (action) {
        action(Number(button.dataset.id));
    }
});

// Initialize
checkAuth();
