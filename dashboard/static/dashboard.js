/**
 * HID Defender Dashboard - Dynamic Update Engine
 * Handles real-time updates, auto-refresh, filtering, and UI animations
 */

class DashboardUpdater {
    constructor() {
        this.updateCount = 0;
        this.autoRefreshEnabled = true;
        this.refreshInterval = 3000; // 3 seconds
        this.eventFilter = '';
        this.resultFilter = '';
        this.lastUpdateTime = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startAutoRefresh();
        this.updateClock();
        setInterval(() => this.updateClock(), 1000);
    }

    setupEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshAll());
        }

        // Auto-refresh toggle
        const autoToggle = document.getElementById('auto-refresh-toggle');
        if (autoToggle) {
            autoToggle.addEventListener('click', () => this.toggleAutoRefresh(autoToggle));
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

    startAutoRefresh() {
        this.refreshAll();
        this.autoRefreshInterval = setInterval(() => {
            if (this.autoRefreshEnabled) {
                this.refreshAll();
            }
        }, this.refreshInterval);
    }

    toggleAutoRefresh(btn) {
        this.autoRefreshEnabled = !this.autoRefreshEnabled;
        if (btn) {
            btn.textContent = this.autoRefreshEnabled ? '⏸ Auto-Refresh ON' : '▶ Auto-Refresh OFF';
            btn.classList.toggle('button-active', this.autoRefreshEnabled);
        }
    }

    refreshAll() {
        Promise.all([
            this.updateStats(),
            this.updateAlerts(),
            this.updateActivity(),
            this.updateDevices(),
            this.updateEvents()
        ]).catch(err => console.error('Update error:', err));
    }

    updateClock() {
        const statusEl = document.getElementById('status-time');
        if (!statusEl) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString();
        const updateCountEl = document.getElementById('update-count');
        
        statusEl.innerHTML = `Status: <span class="status-active">Active</span> | Time: ${timeStr} | Updates: <span id="update-count">${this.updateCount}</span>`;
    }

    updateStats() {
        return fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                this.updateStatCard('stat-total', data.total_events);
                this.updateStatCard('stat-trusted', data.trusted);
                this.updateStatCard('stat-safe', data.safe);
                this.updateStatCard('stat-untrusted', data.untrusted);
                this.updateStatCard('stat-blocked', data.blocked);
                this.updateStatCard('stat-disabled', data.disabled);

                // Update timing stats
                const lastEventEl = document.getElementById('last-event-time');
                if (lastEventEl) {
                    lastEventEl.textContent = data.last_event ? new Date(data.last_event).toLocaleTimeString() : 'N/A';
                }

                const uniqueEl = document.getElementById('unique-devices');
                if (uniqueEl) {
                    uniqueEl.textContent = data.unique_devices;
                }

                const avgEl = document.getElementById('avg-interval');
                if (avgEl) {
                    avgEl.textContent = data.average_interval ? `${data.average_interval.toFixed(1)}s` : 'N/A';
                }

                // Update top reasons
                const reasonsList = document.getElementById('top-reasons');
                if (reasonsList && data.top_reasons) {
                    reasonsList.innerHTML = data.top_reasons
                        .map(r => `<li>${r.reason} — <strong>${r.count}</strong></li>`)
                        .join('');
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
                const alertCount = document.getElementById('alert-count');
                
                if (alertCount) {
                    alertCount.textContent = data.total;
                }

                if (!alertsList) return;

                if (data.alerts.length === 0) {
                    alertsList.innerHTML = '<p class="no-data">✓ No alerts detected</p>';
                    return;
                }

                alertsList.innerHTML = data.alerts.map(alert => `
                    <div class="alert-item pulse">
                        <p class="alert-time">${new Date(alert.time).toLocaleTimeString()}</p>
                        <p class="alert-title">${alert.reason}</p>
                        <p class="alert-device">${alert.vendor || 'Unknown'} - ${alert.device || 'Unknown'}</p>
                    </div>
                `).join('');
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

                activityList.innerHTML = data.activity.map(log => `
                    <div class="log-item fade-in">
                        <p class="log-time">${new Date(log.time).toLocaleTimeString()}</p>
                        <p class="log-content"><strong>${log.action}</strong>: ${log.device}</p>
                    </div>
                `).join('');
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
                        <div class="device-card bounce">
                            <h4>Device ${idx + 1}</h4>
                            <p><strong>Type:</strong> ${device.type || 'Unknown'}</p>
                            <p><strong>Vendor:</strong> ${device.vendor || 'Unknown'}</p>
                            <p><strong>Product:</strong> ${device.product || 'Unknown'}</p>
                            <p class="device-status">
                                Status: <span class="status-badge ${statusClass}">${device.status}</span>
                            </p>
                            <p><strong>Events:</strong> ${device.event_count}</p>
                            <p class="last-activity">
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
            tbody.innerHTML = '<tr><td colspan="8" class="no-data">No events match filters</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(event => {
            const resultClass = (event.result || '').toLowerCase();
            const timeStr = new Date(event.time).toLocaleTimeString();
            return `
                <tr class="${resultClass} fade-in">
                    <td>${timeStr}</td>
                    <td>${event.device || '-'}</td>
                    <td>${event.vendor || '-'}</td>
                    <td>${event.product || '-'}</td>
                    <td><code>${event.id || '-'}</code></td>
                    <td><strong>${event.result || '-'}</strong></td>
                    <td>${event.action || '-'}</td>
                    <td>${event.reason || '-'}</td>
                </tr>
            `;
        }).join('');
    }

    animateUpdate(element) {
        element.classList.add('highlight');
        setTimeout(() => element.classList.remove('highlight'), 600);
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DashboardUpdater();
    console.log('✓ Dashboard initialized');
});
