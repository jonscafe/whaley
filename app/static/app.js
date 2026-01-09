// CTF Instancer Frontend Application

const API_BASE = '';

// State
let currentUser = null;
let challenges = [];
let instances = [];
let timerIntervals = {};
let authToken = null;
let authMode = 'none';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    init();
});

async function init() {
    // Check for saved token
    // Note: Using sessionStorage instead of localStorage for better security
    // sessionStorage clears when browser/tab is closed, reducing token exposure
    authToken = sessionStorage.getItem('ctfd_token');
    
    await checkHealth();
    await checkAuthMode();
    
    if (authMode === 'none') {
        // No auth mode - show main content directly
        showMainContent();
        await loadUserInfo();
        await loadChallenges();
        await loadInstances();
    } else if (authToken) {
        // CTFd mode with saved token - try to authenticate
        const success = await loadUserInfo();
        if (success) {
            showMainContent();
            await loadChallenges();
            await loadInstances();
        } else {
            // Token invalid, show auth form
            showAuthForm();
        }
    } else {
        // CTFd mode without token - show auth form
        showAuthForm();
    }
    
    // Refresh instances every 10 seconds
    setInterval(() => {
        if (currentUser) {
            loadInstances();
        }
    }, 10000);
}

function showAuthForm() {
    document.getElementById('auth-section').classList.remove('hidden');
    document.getElementById('main-content').classList.add('hidden');
}

function showMainContent() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('main-content').classList.remove('hidden');
}

async function checkAuthMode() {
    try {
        const data = await fetch(`${API_BASE}/api`).then(r => r.json());
        authMode = data.auth_mode || 'none';
        
        // Update auth section link based on CTFd URL
        if (authMode === 'ctfd') {
            // The link is already set in HTML, but we could update it dynamically if needed
        }
    } catch (error) {
        console.error('Failed to check auth mode:', error);
    }
}

async function authenticate() {
    const tokenInput = document.getElementById('ctfd-token');
    const token = tokenInput.value.trim();
    
    if (!token) {
        showToast('Please enter your CTFd access token', 'error');
        return;
    }
    
    // Save token temporarily
    authToken = token;
    
    // Try to authenticate
    const success = await loadUserInfo();
    
    if (success) {
        // Save token to sessionStorage (more secure than localStorage)
        // Token will be cleared when browser/tab is closed
        sessionStorage.setItem('ctfd_token', token);
        showToast(`Welcome, ${currentUser.username}!`, 'success');
        showMainContent();
        await loadChallenges();
        await loadInstances();
    } else {
        authToken = null;
        showToast('Invalid token. Please check and try again.', 'error');
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    sessionStorage.removeItem('ctfd_token');
    
    // Clear instances
    instances = [];
    Object.keys(timerIntervals).forEach(id => {
        clearInterval(timerIntervals[id]);
        delete timerIntervals[id];
    });
    
    // Clear token input
    document.getElementById('ctfd-token').value = '';
    
    showToast('Logged out successfully', 'info');
    showAuthForm();
}

// API Functions
async function api(endpoint, options = {}) {
    try {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        // Add auth token if available
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers,
            ...options
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'API Error');
        }
        
        return data;
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        throw error;
    }
}

// Health Check
async function checkHealth() {
    const statusEl = document.getElementById('status-health');
    try {
        const data = await api('/health');
        statusEl.innerHTML = `
            <span class="status-dot online"></span>
            <span>${data.challenges_loaded} challenges • ${data.active_instances} active</span>
        `;
    } catch (error) {
        statusEl.innerHTML = `
            <span class="status-dot offline"></span>
            <span>Offline</span>
        `;
    }
}

// User Info
async function loadUserInfo() {
    try {
        const data = await api('/me');
        currentUser = data.user;
        
        document.getElementById('user-name').textContent = currentUser.username;
        document.getElementById('user-id').textContent = currentUser.user_id;
        document.getElementById('user-instances').textContent = 
            `${data.instances} / ${data.max_instances}`;
        
        // Display team info if in team mode
        const teamNameItem = document.getElementById('team-name-item');
        const teamNameEl = document.getElementById('team-name');
        const instancesLabel = document.getElementById('instances-label');
        
        if (data.team_mode && currentUser.team_id) {
            // Show team name inline
            if (teamNameItem && teamNameEl) {
                teamNameEl.textContent = currentUser.team_name || 'No Team';
                teamNameItem.classList.remove('hidden');
            }
            
            // Update label for instances
            if (instancesLabel) {
                instancesLabel.textContent = 'Team Instances';
            }
            
            // Load team members
            await loadTeamMembers();
        } else {
            // Hide team info
            if (teamNameItem) {
                teamNameItem.classList.add('hidden');
            }
            if (instancesLabel) {
                instancesLabel.textContent = 'Instances';
            }
            // Hide team members section
            const teamMembersEl = document.getElementById('team-members');
            if (teamMembersEl) {
                teamMembersEl.classList.add('hidden');
            }
        }
        
        return true;
    } catch (error) {
        console.error('Failed to load user info:', error);
        return false;
    }
}

// Load Team Members
async function loadTeamMembers() {
    const container = document.getElementById('team-members');
    if (!container) return;
    
    try {
        const data = await api('/me/team');
        
        if (!data.team_mode || !data.members || data.members.length === 0) {
            container.classList.add('hidden');
            return;
        }
        
        container.classList.remove('hidden');
        
        const membersList = data.members.map(member => {
            const isCurrentUser = String(member.id) === String(data.current_user_id);
            return `<span class="team-member ${isCurrentUser ? 'current-user' : ''}">${escapeHtml(member.name)}${isCurrentUser ? ' (you)' : ''}</span>`;
        }).join('');
        
        container.innerHTML = `
            <div class="info-item team-members-list">
                <span class="label">Team Members</span>
                <span class="value">${membersList}</span>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load team members:', error);
        container.classList.add('hidden');
    }
}

// Challenges
async function loadChallenges() {
    const container = document.getElementById('challenges-list');
    container.innerHTML = '<div class="loading">Loading challenges...</div>';
    
    try {
        const data = await api('/challenges');
        challenges = data.challenges;
        
        if (challenges.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">🎯</span>
                    <p>No challenges available</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = challenges.map(challenge => `
            <div class="challenge-card" data-id="${challenge.id}">
                <div class="challenge-header">
                    <span class="challenge-name">${escapeHtml(challenge.name)}</span>
                    <span class="challenge-category category-${challenge.category}">${challenge.category}</span>
                </div>
                <p class="challenge-description">${escapeHtml(challenge.description || 'No description')}</p>
                <div class="challenge-meta">
                    <span>🔌 ${challenge.ports.length} port${challenge.ports.length !== 1 ? 's' : ''}</span>
                </div>
                <div class="challenge-actions">
                    <button class="btn btn-primary" onclick="spawnInstance('${challenge.id}')">
                        <span class="btn-icon">🚀</span> Spawn
                    </button>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">❌</span>
                <p>Failed to load challenges</p>
                <button class="btn btn-secondary" onclick="loadChallenges()">Retry</button>
            </div>
        `;
    }
}

// Instances
async function loadInstances() {
    const container = document.getElementById('instances-list');
    
    try {
        const data = await api('/instances');
        instances = data.instances;
        
        // Update user instance count
        document.getElementById('user-instances').textContent = 
            `${instances.length} / ${currentUser ? 3 : '-'}`;
        
        if (instances.length === 0) {
            // Clear any existing timers
            Object.keys(timerIntervals).forEach(id => {
                clearInterval(timerIntervals[id]);
                delete timerIntervals[id];
            });
            
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">📦</span>
                    <p>No active instances</p>
                    <p class="empty-hint">Spawn a challenge above to get started!</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = instances.map(instance => {
            // Generate URLs for all ports
            const publicUrls = instance.public_urls || {};
            let portsHtml;
            
            if (Object.keys(publicUrls).length > 0) {
                // Multi-port display with labels
                portsHtml = Object.entries(publicUrls)
                    .map(([internalPort, url]) => `
                        <span class="instance-url" onclick="copyToClipboard('${url}')" title="Port ${internalPort} - Click to copy">
                            <span class="port-label">:${internalPort}</span> ${url}
                        </span>
                    `).join('');
            } else {
                // Fallback to single URL
                const url = instance.public_url || 'N/A';
                portsHtml = `
                    <span class="instance-url" onclick="copyToClipboard('${url}')" title="Click to copy">
                        ${url}
                    </span>
                `;
            }
            
            // Show error message if present
            const errorHtml = instance.error_message ? `
                <div class="instance-error">
                    <span class="error-icon">⚠️</span>
                    <span class="error-msg">${escapeHtml(instance.error_message)}</span>
                </div>
            ` : '';
            
            // Show spawned by info in team mode (if spawned by different user)
            const spawnedByHtml = (instance.team_id && instance.username && instance.username !== currentUser?.username) ? 
                `<span class="spawned-by">(spawned by ${escapeHtml(instance.username)})</span>` : '';
            
            return `
                <div class="instance-card ${instance.status === 'error' ? 'instance-error-card' : ''}" data-id="${instance.instance_id}">
                    <div class="instance-info">
                        <div class="instance-header">
                            <span class="instance-name">${escapeHtml(instance.challenge_id)}</span>
                            <span class="instance-status status-${instance.status}">${instance.status}</span>
                            ${spawnedByHtml}
                        </div>
                        ${errorHtml}
                        <div class="instance-details">
                            <div class="instance-detail">
                                <span class="label">Connect:</span>
                                <div class="instance-urls">
                                    ${portsHtml}
                                </div>
                            </div>
                            <div class="instance-detail">
                                <span class="label">Expires:</span>
                                <span class="instance-timer" id="timer-${instance.instance_id}">
                                    ${formatTimeRemaining(instance.expires_at)}
                                </span>
                            </div>
                        </div>
                    </div>
                    <div class="instance-actions">
                        <button class="btn btn-warning btn-sm" onclick="extendInstance('${instance.instance_id}')" title="Extend 30 min">
                            <span class="btn-icon">⏰</span> Extend
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="stopInstance('${instance.instance_id}')">
                            <span class="btn-icon">🛑</span> Stop
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
        // Setup timers
        instances.forEach(instance => {
            setupTimer(instance.instance_id, instance.expires_at);
        });
        
    } catch (error) {
        console.error('Failed to load instances:', error);
    }
}

// Spawn Instance
async function spawnInstance(challengeId) {
    const btn = event.target.closest('button');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-icon">⏳</span> Spawning...';
    
    try {
        const data = await api('/instances/spawn', {
            method: 'POST',
            body: JSON.stringify({ challenge_id: challengeId })
        });
        
        if (data.success) {
            // Build URLs message for multi-port challenges
            let urlsMsg = '';
            const publicUrls = data.instance.public_urls || {};
            if (Object.keys(publicUrls).length > 1) {
                urlsMsg = Object.entries(publicUrls)
                    .map(([port, url]) => `Port ${port}: ${url}`)
                    .join(', ');
            } else {
                urlsMsg = data.instance.public_url;
            }
            showToast(`Instance spawned! Connect at: ${urlsMsg}`, 'success');
            await loadInstances();
            await loadUserInfo();
        } else {
            showToast(data.message, 'error');
        }
    } catch (error) {
        showToast(error.message || 'Failed to spawn instance', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">🚀</span> Spawn';
    }
}

// Stop Instance
async function stopInstance(instanceId) {
    if (!confirm('Are you sure you want to stop this instance?')) {
        return;
    }
    
    try {
        await api(`/instances/${instanceId}`, {
            method: 'DELETE'
        });
        
        showToast('Instance stopped', 'success');
        await loadInstances();
        await loadUserInfo();
    } catch (error) {
        showToast(error.message || 'Failed to stop instance', 'error');
    }
}

// Extend Instance
async function extendInstance(instanceId) {
    try {
        const data = await api(`/instances/${instanceId}/extend`, {
            method: 'POST'
        });
        
        showToast('Instance extended by 30 minutes', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message || 'Failed to extend instance', 'error');
    }
}

// Timer Functions
function setupTimer(instanceId, expiresAt) {
    // Clear existing timer
    if (timerIntervals[instanceId]) {
        clearInterval(timerIntervals[instanceId]);
    }
    
    const updateTimer = () => {
        const timerEl = document.getElementById(`timer-${instanceId}`);
        if (timerEl) {
            timerEl.textContent = formatTimeRemaining(expiresAt);
        }
    };
    
    updateTimer();
    timerIntervals[instanceId] = setInterval(updateTimer, 1000);
}

function formatTimeRemaining(expiresAt) {
    const now = new Date();
    
    // Parse expires_at - handle both ISO format and add 'Z' if missing (for UTC)
    let expiresStr = expiresAt;
    if (expiresStr && !expiresStr.endsWith('Z') && !expiresStr.includes('+')) {
        expiresStr = expiresStr + 'Z';  // Assume UTC if no timezone specified
    }
    const expires = new Date(expiresStr);
    
    // Check if date is valid
    if (isNaN(expires.getTime())) {
        return 'Invalid date';
    }
    
    const diff = expires - now;
    
    if (diff <= 0) {
        return 'Expired';
    }
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    } else {
        return `${seconds}s`;
    }
}

// Toast Notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <span>${icons[type] || icons.info}</span>
        <span>${escapeHtml(message)}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Modal Functions
function openModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
}

// Utility Functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied: ${text}`, 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast(`Copied: ${text}`, 'success');
    });
}
