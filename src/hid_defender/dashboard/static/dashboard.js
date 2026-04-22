/**
 * HID Defender Dashboard - Dynamic Update Engine
 * Handles real-time updates, auto-refresh, filtering, UI animations, and test execution
 */

class DashboardUpdater {
    constructor() {
        this.updateCount = 0;
        this.eventFilter = '';
        this.resultFilter = '';
        this.allEvents = [];
        this.testsLoaded = false;
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.updateClock();
        this.refreshAll();
        this.pollNewAlerts();   // start real-time threat polling
        setInterval(() => this.updateClock(), 1000);
        setInterval(() => this.refreshAll(), 15000);   // full refresh every 15s
        setInterval(() => this.pollNewAlerts(), 5000); // threat check every 5s
    }

    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        const sections = document.querySelectorAll('.section');

        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = item.getAttribute('data-section');
                
                // Update nav items
                navItems.forEach(nav => nav.classList.remove('active'));
                item.classList.add('active');
                
                // Update sections
                sections.forEach(sec => sec.classList.remove('active'));
                const targetSection = document.getElementById(targetId);
                if (targetSection) {
                    targetSection.classList.add('active');
                }
                
                // Load tests if we navigate to the tests section
                if (targetId === 'tests' && !this.testsLoaded) {
                    this.loadTests();
                }
            });
        });
    }

    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                refreshBtn.classList.add('spinning');
                const originalText = refreshBtn.innerHTML;
                refreshBtn.innerHTML = '⌛ Refreshing...';
                
                this.refreshAll().then(() => {
                    setTimeout(() => {
                        refreshBtn.classList.remove('spinning');
                        refreshBtn.innerHTML = originalText;
                    }, 500);
                });
            });
        }

        // Simulate Attack button
        const simulateBtn = document.getElementById('simulate-attack-btn');
        if (simulateBtn) {
            simulateBtn.addEventListener('click', () => this.simulateAttack(simulateBtn));
        }

        // Settings - Add Trusted Form
        const addTrustedForm = document.getElementById('add-trusted-form');
        if (addTrustedForm) {
            addTrustedForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.addTrustedDevice();
            });
        }

        // Settings - Clear Logs
        const clearLogsBtn = document.getElementById('clear-logs-btn');
        if (clearLogsBtn) {
            clearLogsBtn.addEventListener('click', () => {
                if (confirm('Are you sure you want to clear all security logs? This action cannot be undone.')) {
                    this.clearLogs();
                }
            });
        }

        // Event filter
        const eventFilter = document.getElementById('event-filter');
        if (eventFilter) {
            eventFilter.addEventListener('input', (e) => {
                this.eventFilter = e.target.value.toLowerCase();
                this.filterEvents();
            });
        }

        // Result filter
        const resultFilter = document.getElementById('result-filter');
        if (resultFilter) {
            resultFilter.addEventListener('change', (e) => {
                this.resultFilter = e.target.value.toLowerCase();
                this.filterEvents();
            });
        }
    }

    simulateAttack(btnElement) {
        const modal = document.getElementById('simulation-modal');
        const modalBody = document.getElementById('simulation-body');
        const closeBtn = document.getElementById('close-simulation-btn');
        
        if (!modal || !modalBody) return;
        
        // Setup Modal UI
        modal.classList.remove('hidden');
        modalBody.innerHTML = '<p style="text-align: center; color: var(--text-muted);">Initializing attack vectors...</p>';
        closeBtn.classList.add('hidden');
        
        // Reset button
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = '⏳ Simulating...';
        btnElement.disabled = true;

        fetch('/api/simulate_attack', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success && data.attacks) {
                    modalBody.innerHTML = ''; // Clear initializing text
                    let delay = 0;
                    
                    data.attacks.forEach((attack, index) => {
                        setTimeout(() => {
                            // Show attack coming in
                            const eventDiv = document.createElement('div');
                            eventDiv.className = 'sim-event';
                            eventDiv.innerHTML = `
                                <div class="sim-event-title">🔥 Attack Vector: ${attack.Device}</div>
                                <div class="sim-event-detail">Target: ${attack.Event} | ID: ${attack.ID}</div>
                                <div class="sim-event-detail" style="color: var(--warning);">Status: Analyzing threat...</div>
                            `;
                            modalBody.appendChild(eventDiv);
                            modalBody.scrollTop = modalBody.scrollHeight;
                            
                            // Simulate Defense response after a short delay
                            setTimeout(() => {
                                const actionColor = attack.Action === 'BLOCKED' ? 'danger' : 'warning';
                                eventDiv.innerHTML = `
                                    <div class="sim-event-title">🔥 Attack Vector: ${attack.Device}</div>
                                    <div class="sim-event-detail">Target: ${attack.Event} | ID: ${attack.ID}</div>
                                    <div class="sim-event-defense ${actionColor}">
                                        🛡️ System Defense: ${attack.Action} - ${attack.Reason}
                                    </div>
                                `;
                            }, 800);
                            
                        }, delay);
                        delay += 1500; // Stagger each attack
                    });
                    
                    // After all attacks have run
                    setTimeout(() => {
                        this.refreshAll();
                        closeBtn.classList.remove('hidden');
                        closeBtn.textContent = 'View Defense Logs →';
                        closeBtn.onclick = () => {
                            modal.classList.add('hidden');
                            document.querySelector('[data-section="logs"]').click();
                        };
                        
                        btnElement.innerHTML = '✓ Simulation Complete';
                        btnElement.style.background = 'var(--success)';
                        setTimeout(() => {
                            btnElement.innerHTML = originalText;
                            btnElement.disabled = false;
                            btnElement.style.background = 'var(--danger)';
                        }, 3000);
                        
                    }, delay + 500);
                    
                } else {
                    modalBody.innerHTML = `<p style="color: var(--danger); text-align: center;">Error: ${data.error}</p>`;
                    closeBtn.classList.remove('hidden');
                    closeBtn.textContent = 'Close';
                    closeBtn.onclick = () => modal.classList.add('hidden');
                    btnElement.innerHTML = '❌ Error';
                }
            })
            .catch(err => {
                modalBody.innerHTML = `<p style="color: var(--danger); text-align: center;">Fetch Error: ${err}</p>`;
                closeBtn.classList.remove('hidden');
                closeBtn.textContent = 'Close';
                closeBtn.onclick = () => modal.classList.add('hidden');
                btnElement.innerHTML = '❌ Error';
                console.error("Fetch error:", err);
            });
    }

    refreshAll() {
        return Promise.all([
            this.updateStats(),
            this.updateAlerts(),
            this.updateActivity(),
            this.updateDevices(),
            this.updateEvents(),
            this.updateTrustedDevices()
        ]).catch(err => console.error('Update error:', err));
    }

    updateClock() {
        const statusEl = document.getElementById('status-time');
        if (!statusEl) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString();
        statusEl.innerHTML = `<span class="status-active"></span>Active | Updates: <span id="update-count">${this.updateCount}</span> | Last refresh: ${timeStr} <span class="monitor-indicator"><span class="monitor-dot"></span>USB Monitor ON</span>`;
    }

    updateStats() {
        return fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                this.updateStatCard('stat-total', data.total_events);
                this.updateStatCard('stat-trusted', data.trusted_count);
                this.updateStatCard('stat-untrusted', data.untrusted_count);
                this.updateStatCard('stat-blocked', data.blocked_count);
                this.updateStatCard('stat-disabled', data.disabled_count);

                // Also update the unique devices text if it exists
                const trustedBox = document.getElementById('stat-trusted');
                if (trustedBox) {
                    const mutedText = trustedBox.querySelector('p[style*="font-size:0.72rem"]');
                    if (mutedText) {
                        mutedText.textContent = `${data.unique_devices} unique device(s) registered`;
                    }
                }

                this.updateCount++;
                this.updateClock();
            });
    }

    updateStatCard(elementId, value) {
        const el = document.getElementById(elementId);
        if (el) {
            const numberEl = el.querySelector('.stat-number');
            if (numberEl) {
                const oldValue = parseInt(numberEl.textContent);
                if (oldValue !== value) {
                    numberEl.textContent = value;
                    this.animateUpdate(numberEl);
                }
            }
        }
    }

    updateAlerts() {
        return fetch('/api/alerts')
            .then(res => res.json())
            .then(data => {
                const alertsList = document.getElementById('alerts-list');
                const alertsFullList = document.getElementById('alerts-full-list');
                const alertCount = document.getElementById('alert-count');
                
                if (alertCount) {
                    alertCount.textContent = data.total;
                }

                if (!alertsList && !alertsFullList) return;

                const html = data.alerts.length === 0 ? 
                    '<p class="no-data">✓ No alerts detected</p>' : 
                    data.alerts.map(alert => `
                        <div class="alert-item fade-in">
                            <p class="alert-time">${new Date(alert.time).toLocaleTimeString()}</p>
                            <p class="alert-title">${alert.reason}</p>
                            <p class="alert-device">${alert.vendor || 'Unknown'} - ${alert.device || 'Unknown'}</p>
                        </div>
                    `).join('');

                if (alertsList) alertsList.innerHTML = html;
                if (alertsFullList) alertsFullList.innerHTML = html;
            });
    }

    updateActivity() {
        return fetch('/api/activity')
            .then(res => res.json())
            .then(data => {
                const activityList = document.getElementById('activity-list');
                if (!activityList) return;

                if (data.activity.length === 0) {
                    activityList.innerHTML = '<p class="no-data">No activity yet</p>';
                    return;
                }

                activityList.innerHTML = data.activity.map(log => {
                    let logClass = 'safe';
                    if (log.result === 'UNTRUSTED') logClass = 'danger';
                    else if (log.result === 'TRUSTED') logClass = 'trusted';
                    
                    return `
                    <div class="log-item ${logClass} fade-in">
                        <p class="log-time">${new Date(log.time).toLocaleTimeString()}</p>
                        <p class="log-content"><strong>${log.action}</strong>: ${log.device || 'Unknown Device'}</p>
                    </div>
                `}).join('');
            });
    }

    updateDevices() {
        return fetch('/api/devices')
            .then(res => res.json())
            .then(data => {
                const devicesGrid = document.getElementById('devices-grid');
                if (!devicesGrid) return;

                if (data.devices.length === 0) {
                    devicesGrid.innerHTML = '<p class="no-data">No devices detected</p>';
                    return;
                }

                devicesGrid.innerHTML = data.devices.map((device, idx) => {
                    const statusClass = device.status.toLowerCase();
                    return `
                        <div class="stat-box fade-in">
                            <h4 style="color: #fff; margin-bottom: 0.8rem; font-size: 1.1rem;">Device: <code>${device.id}</code></h4>
                            <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Type:</strong> ${device.type || 'Unknown'}</p>
                            <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Vendor:</strong> ${device.vendor || 'Unknown'}</p>
                            <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Product:</strong> ${device.product || 'Unknown'}</p>
                            <p class="device-status" style="margin-top: 1rem; margin-bottom: 0.5rem;">
                                <span class="badge ${statusClass}">${device.status}</span>
                            </p>
                            <p style="color: var(--text-muted); font-size: 0.85rem;">Events: ${device.event_count}</p>
                            <p class="last-activity" style="margin-top: 0.5rem;">
                                Last Activity: ${device.last_activity ? new Date(device.last_activity).toLocaleTimeString() : 'N/A'}
                            </p>
                        </div>
                    `;
                }).join('');
            });
    }

    updateEvents() {
        return fetch('/api/events')
            .then(res => res.json())
            .then(data => {
                this.allEvents = data.events;
                this.filterEvents();
            });
    }

    filterEvents() {
        if (!this.allEvents) return;

        const tbody = document.getElementById('events-tbody');
        if (!tbody) return;

        let filtered = this.allEvents;

        // Filter by search text
        if (this.eventFilter) {
            filtered = filtered.filter(event => {
                const searchText = this.eventFilter;
                return (
                    (event.device || '').toLowerCase().includes(searchText) ||
                    (event.vendor || '').toLowerCase().includes(searchText) ||
                    (event.action || '').toLowerCase().includes(searchText) ||
                    (event.reason || '').toLowerCase().includes(searchText)
                );
            });
        }

        // Filter by result
        if (this.resultFilter) {
            filtered = filtered.filter(event => 
                (event.result || '').toLowerCase() === this.resultFilter
            );
        }

        // Render filtered events
        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="no-data" style="text-align: center;">No events match filters</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(event => {
            const resultClass = (event.result || '').toLowerCase();
            const timeStr = new Date(event.time).toLocaleTimeString();
            return `
                <tr class="${resultClass}">
                    <td>${timeStr}</td>
                    <td>${event.device || '-'}</td>
                    <td>${event.vendor || '-'}</td>
                    <td>${event.product || '-'}</td>
                    <td><code>${event.id || '-'}</code></td>
                    <td><span class="badge ${resultClass}">${event.result || '-'}</span></td>
                    <td>${event.action || '-'}</td>
                    <td>${event.reason || '-'}</td>
                </tr>
            `;
        }).join('');
    }

    loadTests() {
        const testsList = document.getElementById('tests-list');
        if (!testsList) return;

        testsList.innerHTML = '<p class="no-data">Fetching tests...</p>';

        fetch('/api/tests')
            .then(res => res.json())
            .then(data => {
                this.testsLoaded = true;
                
                if (data.tests.length === 0) {
                    testsList.innerHTML = '<p class="no-data">No test cases found</p>';
                    return;
                }

                testsList.innerHTML = data.tests.map(test => `
                    <div class="test-item fade-in">
                        <div class="test-info">
                            <h4>${test.name}</h4>
                            <p>${test.file}</p>
                        </div>
                        <button class="button run-test-btn" data-testid="${test.id}">
                            ▶ Execute
                        </button>
                    </div>
                `).join('');

                // Add listeners to new buttons
                document.querySelectorAll('.run-test-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const testId = e.currentTarget.getAttribute('data-testid');
                        this.executeTest(testId, e.currentTarget);
                    });
                });
            })
            .catch(err => {
                testsList.innerHTML = `<p class="no-data" style="color: var(--danger)">Error loading tests: ${err.message}</p>`;
            });
    }

    executeTest(testId, btnElement) {
        const resultsBox = document.getElementById('test-execution-results');
        if (!resultsBox) return;

        // Visual feedback on button
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = '⌛ Running...';
        btnElement.disabled = true;
        btnElement.style.opacity = '0.7';

        // Set up results box
        const testName = testId.split('::').pop();
        resultsBox.innerHTML = `
            <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                <h3 style="margin: 0;">Running: ${testName}</h3>
                <span class="test-badge" style="background: rgba(255, 255, 255, 0.1); color: #fff;">In Progress</span>
            </div>
            <div class="test-output">Executing test suite...</div>
        `;

        fetch('/api/tests/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ test_id: testId })
        })
        .then(res => res.json())
        .then(data => {
            const passed = data.result.passed;
            const rawOutput = data.result.stdout + '\n' + data.result.stderr;
            
            let cleanOutput = "";
            if (passed) {
                cleanOutput = "The test executed successfully. All system checks and assertions passed.";
            } else {
                // Extract error lines without showing file paths
                const lines = rawOutput.split('\n');
                const errorLines = lines.filter(line => 
                    line.startsWith('E ') || 
                    line.includes('AssertionError') || 
                    line.includes('Exception:') ||
                    (line.includes('FAILED') && !line.includes('='))
                );
                
                if (errorLines.length > 0) {
                    cleanOutput = "The test failed due to the following errors:\n\n" + 
                        errorLines.map(l => "• " + l.replace(/^E\s+/, '').replace(/^.*\.py:\d+:\s*/, '')).join('\n');
                } else {
                    cleanOutput = "The test failed during execution. Please review the system logs for detailed information.";
                }
            }
            
            const badgeClass = passed ? 'passed' : 'failed';
            const badgeText = passed ? '✓ Passed' : '✗ Failed';
            
            resultsBox.innerHTML = `
                <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                    <h3 style="margin: 0;">${testName}</h3>
                    <span class="test-badge ${badgeClass}">${badgeText}</span>
                </div>
                <div class="test-output ${passed ? '' : 'error'}">${this.escapeHtml(cleanOutput)}</div>
            `;
        })
        .catch(err => {
            resultsBox.innerHTML = `
                <h3 style="color: var(--danger); margin-bottom: 1rem;">Error Running Test</h3>
                <div class="test-output error">${err.message}</div>
            `;
        })
        .finally(() => {
            // Restore button
            btnElement.innerHTML = originalText;
            btnElement.disabled = false;
            btnElement.style.opacity = '1';
        });
    }

    updateTrustedDevices() {
        return fetch('/api/whitelist')
            .then(res => res.json())
            .then(data => {
                const trustedList = document.getElementById('trusted-devices-list');
                const trustedBadge = document.getElementById('trusted-count-badge');
                
                if (trustedBadge) {
                    trustedBadge.textContent = `${data.total || 0} Devices`;
                }

                if (!trustedList) return;

                if (!data.whitelist || data.whitelist.length === 0) {
                    trustedList.innerHTML = '<p class="no-data">No trusted devices registered</p>';
                    return;
                }

                trustedList.innerHTML = data.whitelist.map(device => `
                    <div class="stat-box trusted-card fade-in">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <h4 style="color: #fff; margin-bottom: 0.8rem; font-size: 1.1rem;"><code>${device.id}</code></h4>
                            <button class="delete-trusted-btn" data-id="${device.id}" title="Remove from Whitelist">✕</button>
                        </div>
                        <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Device:</strong> ${device.device || 'N/A'}</p>
                        <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Vendor:</strong> ${device.vendor || 'N/A'}</p>
                        <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Product:</strong> ${device.product || 'N/A'}</p>
                        <p style="color: var(--text-muted); font-size: 0.75rem; margin-top: 1rem;">Added: ${device.added || 'N/A'}</p>
                    </div>
                `).join('');

                // Add delete listeners
                document.querySelectorAll('.delete-trusted-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-id');
                        if (confirm(`Remove device ${id} from trusted list?`)) {
                            this.deleteTrustedDevice(id);
                        }
                    });
                });
            });
    }

    addTrustedDevice() {
        const form = document.getElementById('add-trusted-form');
        const messageEl = document.getElementById('form-message');
        const submitBtn = form.querySelector('button[type="submit"]');

        const data = {
            id: document.getElementById('device-hw-id').value,
            device: document.getElementById('device-name').value,
            vendor: document.getElementById('device-vendor').value,
            product: document.getElementById('device-product').value
        };

        submitBtn.disabled = true;
        submitBtn.textContent = '⌛ Saving...';

        fetch('/api/whitelist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                messageEl.innerHTML = `<span style="color: var(--success)">${data.message}</span>`;
                form.reset();
                this.updateTrustedDevices();
                setTimeout(() => messageEl.innerHTML = '', 3000);
            } else {
                messageEl.innerHTML = `<span style="color: var(--danger)">${data.error}</span>`;
            }
        })
        .catch(err => {
            messageEl.innerHTML = `<span style="color: var(--danger)">Error: ${err.message}</span>`;
        })
        .finally(() => {
            submitBtn.disabled = false;
            submitBtn.textContent = '➕ Add to Whitelist';
        });
    }

    deleteTrustedDevice(id) {
        fetch('/api/whitelist/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                this.updateTrustedDevices();
            } else {
                alert('Error: ' + data.error);
            }
        });
    }

    clearLogs() {
        fetch('/api/logs/clear', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    this.refreshAll();
                    alert('Security logs cleared successfully.');
                } else {
                    alert('Error clearing logs: ' + data.error);
                }
            });
    }

    pollNewAlerts() {
        fetch('/api/monitor/new-alerts')
            .then(res => res.json())
            .then(data => {
                if (data.alerts && data.alerts.length > 0) {
                    data.alerts.forEach(alert => this.showThreatToast(alert));
                    // Refresh dashboard data so new events appear
                    this.refreshAll();
                }
            })
            .catch(() => {});  // silent fail — monitor may not be available
    }

    showThreatToast(alert) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        // Play alert sound
        try {
            const beep = document.getElementById('alert-beep');
            if (beep) { beep.currentTime = 0; beep.play().catch(() => {}); }
        } catch(e) {}

        // Build toast element
        const toast = document.createElement('div');
        toast.className = 'toast-alert';
        const time = new Date(alert.time).toLocaleTimeString();
        toast.innerHTML = `
            <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
            <div class="toast-title">🚨 UNTRUSTED USB DETECTED</div>
            <div class="toast-device">📟 ${alert.device || 'Unknown Device'} — ${alert.vendor || ''}</div>
            <div class="toast-device" style="font-family:monospace;font-size:0.72rem;color:#6366f1">${alert.id || ''}</div>
            <div class="toast-reason">⚠ ${alert.reason}</div>
            <div style="font-size:0.72rem;color:#475569;margin-top:0.4rem">${time} · Action: ${alert.action}</div>
        `;

        container.appendChild(toast);

        // Auto-dismiss after 6 seconds
        setTimeout(() => {
            toast.style.animation = 'toastOut 0.35s ease forwards';
            setTimeout(() => toast.remove(), 380);
        }, 6000);

        // Flash the page title
        const originalTitle = document.title;
        let blink = 0;
        const titleInterval = setInterval(() => {
            document.title = blink % 2 === 0 ? '🚨 THREAT DETECTED!' : originalTitle;
            if (++blink >= 8) { clearInterval(titleInterval); document.title = originalTitle; }
        }, 600);
    }

    animateUpdate(element) {
        element.style.color = 'var(--accent-blue)';
        setTimeout(() => element.style.color = '', 600);
    }
    
    escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DashboardUpdater();
    console.log('✓ Premium Dashboard initialized');
});
