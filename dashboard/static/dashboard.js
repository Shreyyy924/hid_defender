/**
 * HIDGuard Dashboard - Modern Cybersecurity UI
 * Real-time monitoring, charts, and interactive components
 */

class DashboardController {
    constructor() {
        this.charts = {};
        this.currentSection = 'dashboard';
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupClock();
        this.initializeCharts();
        this.setupEventListeners();
        this.loadInitialData();
        this.startRealtimeUpdates();
    }

    /**
     * Setup sidebar navigation
     */
    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        const sections = document.querySelectorAll('.section');

        // Ensure dashboard is active on load
        const dashboardNav = document.querySelector('[data-section="dashboard"]');
        const dashboardSection = document.getElementById('dashboard');
        if (dashboardNav && dashboardSection) {
            dashboardNav.classList.add('active');
            dashboardSection.classList.add('active');
        }

        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                const targetId = item.getAttribute('data-section');
                console.log('Navigating to:', targetId);
                
                // Remove active from all navItems and sections
                navItems.forEach(nav => nav.classList.remove('active'));
                sections.forEach(sec => sec.classList.remove('active'));
                
                // Add active to clicked item
                item.classList.add('active');
                
                // Show target section
                const targetSection = document.getElementById(targetId);
                if (targetSection) {
                    targetSection.classList.add('active');
                    this.currentSection = targetId;
                    
                    // Trigger data load for this section
                    this.loadSectionData(targetId);
                    
                    // Scroll to top
                    window.scrollTo(0, 0);
                } else {
                    console.warn('Section not found:', targetId);
                }
            });
        });
    }

    navigateToSection(sectionId) {
        const targetNav = document.querySelector(`[data-section="${sectionId}"]`);
        if (targetNav) {
            targetNav.click();
        }
    }

    /**
     * Load data specific to each section
     */
    loadSectionData(sectionId) {
        switch (sectionId) {
            case 'devices':
                this.loadDevices();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'logs':
                this.loadEvents();
                break;
            case 'trusted':
                this.loadTrustedDevices();
                break;
            case 'tests':
                this.loadTests();
                break;
            case 'dashboard':
            default:
                this.updateStats();
                break;
        }
    }

    /**
     * Update clock in header
     */
    setupClock() {
        const updateTime = () => {
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            const timeElement = document.getElementById('current-time');
            if (timeElement) {
                timeElement.textContent = timeString;
            }
        };

        updateTime();
        setInterval(updateTime, 1000);
    }

    /**
     * Initialize Chart.js charts
     */
    initializeCharts() {
        this.createActivityChart();
        this.createThreatPieChart();
    }

    /**
     * Create Activity Timeline Chart
     */
    createActivityChart() {
        const ctx = document.getElementById('activity-chart');
        if (!ctx) return;

        this.charts.activity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'USB Connections',
                        data: [],
                        borderColor: '#58a6ff',
                        backgroundColor: 'rgba(88, 166, 255, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 4,
                        pointBackgroundColor: '#58a6ff',
                        pointBorderColor: '#0d1117',
                        pointBorderWidth: 2,
                    },
                    {
                        label: 'Suspicious Events',
                        data: [],
                        borderColor: '#f85149',
                        backgroundColor: 'rgba(248, 81, 73, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 4,
                        pointBackgroundColor: '#f85149',
                        pointBorderColor: '#0d1117',
                        pointBorderWidth: 2,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#c9d1d9',
                            font: { size: 12, weight: 600 },
                            padding: 15,
                            usePointStyle: true,
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(13, 17, 23, 0.9)',
                        titleColor: '#c9d1d9',
                        bodyColor: '#8b949e',
                        borderColor: '#30363d',
                        borderWidth: 1,
                    }
                },
                scales: {
                    y: {
                        display: true,
                        grid: {
                            color: 'rgba(48, 54, 61, 0.3)',
                            drawBorder: false,
                        },
                        ticks: {
                            color: '#8b949e',
                            font: { size: 11 },
                        }
                    },
                    x: {
                        display: true,
                        grid: {
                            display: false,
                        },
                        ticks: {
                            color: '#8b949e',
                            font: { size: 11 },
                        }
                    }
                }
            }
        });
    }

    /**
     * Create Threats by Detection Type Pie Chart
     */
    createThreatPieChart() {
        const ctx = document.getElementById('threat-pie-chart');
        if (!ctx) return;

        this.charts.threatPie = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#d29922',  // Yellow - Unknown HID Device
                        '#f85149',  // Red - Fast Typing
                        '#ff7b72',  // Light Red - Suspicious Commands
                        '#fb8500',  // Orange - Rapid Input
                    ],
                    borderColor: '#161b22',
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false,
                    },
                    tooltip: {
                        backgroundColor: 'rgba(13, 17, 23, 0.9)',
                        titleColor: '#c9d1d9',
                        bodyColor: '#8b949e',
                        borderColor: '#30363d',
                        borderWidth: 1,
                    }
                }
            }
        });
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Search in header
        const headerSearch = document.querySelector('.header-search input');
        if (headerSearch) {
            let searchTimeout;
            headerSearch.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.handleGlobalSearch(e.target.value);
                }, 500);
            });
        }

        // Log search
        const logSearch = document.getElementById('log-search');
        if (logSearch) {
            let searchTimeout;
            logSearch.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.filterLogs(e.target.value);
                }, 300);
            });
        }

        // Event search
        const eventSearch = document.getElementById('event-search');
        if (eventSearch) {
            let searchTimeout;
            eventSearch.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.filterEvents();
                }, 300);
            });
        }

        // Alert filter
        const alertFilter = document.getElementById('alert-filter');
        if (alertFilter) {
            alertFilter.addEventListener('change', (e) => {
                this.filterAlerts(e.target.value);
            });
        }

        // Event filter
        const eventFilter = document.getElementById('event-filter');
        if (eventFilter) {
            eventFilter.addEventListener('change', () => {
                this.filterEvents();
            });
        }

        // Device search
        const deviceSearch = document.querySelector('#devices .search-small');
        if (deviceSearch) {
            let searchTimeout;
            deviceSearch.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.filterDevices(e.target.value);
                }, 300);
            });
        }

        // Settings toggle switches
        const toggles = document.querySelectorAll('.toggle input');
        toggles.forEach(toggle => {
            toggle.addEventListener('change', (e) => {
                const label = e.target.closest('.setting-item').querySelector('.setting-label p').textContent;
                console.log(`${label}: ${e.target.checked ? 'Enabled' : 'Disabled'}`);
            });
        });

        const openAddDeviceButton = document.getElementById('open-add-device-modal');
        if (openAddDeviceButton) {
            openAddDeviceButton.addEventListener('click', () => {
                this.openModal('device-modal');
                this.loadWhitelistCandidates();
            });
        }

        const manualWhitelistForm = document.getElementById('manual-whitelist-form');
        if (manualWhitelistForm) {
            manualWhitelistForm.addEventListener('submit', (event) => {
                event.preventDefault();
                this.handleManualWhitelistSubmit();
            });
        }

        const simulateAttacksButton = document.getElementById('simulate-attacks-btn');
        if (simulateAttacksButton) {
            simulateAttacksButton.addEventListener('click', () => this.runAttackSimulation());
        }

        const refreshTestsButton = document.getElementById('refresh-tests-btn');
        if (refreshTestsButton) {
            refreshTestsButton.addEventListener('click', () => this.loadTests());
        }

        const openLogsButton = document.getElementById('attack-open-logs');
        if (openLogsButton) {
            openLogsButton.addEventListener('click', () => {
                this.closeModal('attack-modal');
                this.navigateToSection('logs');
            });
        }

        document.querySelectorAll('[data-close-modal]').forEach(button => {
            button.addEventListener('click', () => {
                this.closeModal(button.getAttribute('data-close-modal'));
            });
        });

        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (event) => {
                if (event.target === overlay) {
                    this.closeModal(overlay.id);
                }
            });
        });
    }

    /**
     * Load initial data
     */
    async loadInitialData() {
        try {
            // Show loading states
            this.showLoadingState(true);
            
            await Promise.all([
                this.updateStats(),
                this.loadActivityChart(),
                this.loadThreatsChart(),
                this.loadDevices(),
                this.loadAlerts(),
                this.loadActivityLog(),
                this.loadEvents(),
                this.loadTrustedDevices()
            ]);
            
            this.showLoadingState(false);
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showLoadingState(false);
        }
    }

    /**
     * Show/hide loading state
     */
    showLoadingState(show) {
        const elements = [
            'devices-grid',
            'alerts-full-list',
            'logs-tbody',
            'events-tbody',
            'trusted-devices-list',
            'tests-list'
        ];

        elements.forEach(id => {
            const el = document.getElementById(id);
            if (el && show) {
                if (id.endsWith('-tbody')) {
                    const colspan = id === 'logs-tbody' ? 7 : 7;
                    el.innerHTML = `<tr><td colspan="${colspan}" class="no-data">Loading...</td></tr>`;
                } else {
                    el.innerHTML = '<div style="padding: 2rem; text-align: center; color: #8b949e;">Loading...</div>';
                }
            }
        });
    }

    /**
     * Update statistics cards from API
     */
    async updateStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();

            const elements = {
                'total-devices': data.unique_devices || 0,
                'trusted-count': data.trusted || 0,
                'suspicious-count': data.untrusted || 0,
                'activity-rate': data.blocked ? `${Math.round((data.blocked / data.total_events * 100) || 0)}%` : '0%',
                'threat-level': this.getThreatLevel(data)
            };

            Object.entries(elements).forEach(([id, value]) => {
                const el = document.getElementById(id);
                if (el) {
                    el.textContent = value;
                }
            });

            // Update threat level color in stat card
            const threatCard = document.querySelector('.stat-card:last-child');
            if (threatCard) {
                const level = this.getThreatLevel(data);
                threatCard.style.borderLeftColor = this.getThreatColor(level);
            }

            this.updateThreatGauge(data);
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    }

    /**
     * Load activity data for chart
     */
    async loadActivityChart() {
        try {
            const response = await fetch('/api/activity');
            const data = await response.json();
            
            if (this.charts.activity && data.activity) {
                // Group activities by hour for timeline
                const hourlyData = this.groupByHour(data.activity);
                
                this.charts.activity.data.labels = hourlyData.labels;
                this.charts.activity.data.datasets[0].data = hourlyData.connections;
                this.charts.activity.data.datasets[1].data = hourlyData.suspicious;
                this.charts.activity.update('none');
            }

            const timeRange = document.getElementById('activity-time-range');
            if (timeRange) {
                timeRange.textContent = data.activity?.length ? 'Recent activity' : 'No activity yet';
            }
        } catch (error) {
            console.error('Error loading activity chart:', error);
        }
    }

    /**
     * Load threats data for pie chart
     */
    async loadThreatsChart() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            if (this.charts.threatPie && data.top_reasons) {
                const labels = data.top_reasons.map(r => r.reason).slice(0, 4);
                const counts = data.top_reasons.map(r => r.count).slice(0, 4);

                this.charts.threatPie.data.labels = labels;
                this.charts.threatPie.data.datasets[0].data = counts;
                this.charts.threatPie.update('none');
                this.renderThreatLegend(labels, counts);
            }
        } catch (error) {
            console.error('Error loading threats chart:', error);
        }
    }

    /**
     * Load devices from API
     */
    async loadDevices() {
        try {
            const response = await fetch('/api/devices');
            const data = await response.json();
            
            const devicesGrid = document.getElementById('devices-grid');
            if (!devicesGrid) return;

            if (data.devices.length === 0) {
                devicesGrid.innerHTML = '<p class="no-data">No devices detected</p>';
                this.renderDeviceRiskPanel([]);
                return;
            }

            devicesGrid.innerHTML = data.devices.map(device => {
                const status = device.status.toLowerCase().includes('untrusted') ? 'threat' : 'trusted';
                const trustAction = device.is_trusted
                    ? '<span class="device-action-label">Already trusted</span>'
                    : `<button class="device-action-button" data-device-id="${device.id}" data-device-vendor="${this.escapeHtml(device.vendor || '')}" data-device-product="${this.escapeHtml(device.product || device.type || '')}" data-device-name="${this.escapeHtml(device.type || device.product || '')}">Trust Device</button>`;
                
                return `
                    <div class="device-card ${status}">
                        <div class="device-name">${device.type || 'Unknown Device'}</div>
                        <div class="device-info">Vendor: <strong>${device.vendor || device.id || 'N/A'}</strong></div>
                        <div class="device-info">Events: <strong>${device.event_count}</strong></div>
                        <div class="device-status">
                            <span class="device-status-badge ${status}">
                                ${status === 'threat' ? '⚠ THREAT' : '✓ SAFE'}
                            </span>
                            ${trustAction}
                        </div>
                    </div>
                `;
            }).join('');
            devicesGrid.querySelectorAll('.device-action-button').forEach(button => {
                button.addEventListener('click', () => {
                    this.addTrustedDevice(button.dataset.deviceId, {
                        vendor: button.dataset.deviceVendor,
                        product: button.dataset.deviceProduct,
                        name: button.dataset.deviceName,
                    });
                });
            });
            this.renderDeviceRiskPanel(data.devices);
        } catch (error) {
            console.error('Error loading devices:', error);
            const devicesGrid = document.getElementById('devices-grid');
            if (devicesGrid) {
                devicesGrid.innerHTML = '<p class="no-data">Error loading devices</p>';
            }
            this.renderDeviceRiskPanel([]);
        }
    }

    /**
     * Load alerts from API
     */
    async loadAlerts() {
        try {
            const response = await fetch('/api/alerts');
            const data = await response.json();
            
            const alertsContainer = document.getElementById('alerts-full-list');
            const alertBadge = document.getElementById('alert-badge');
            
            if (alertsContainer) {
                if (data.alerts.length === 0) {
                    alertsContainer.innerHTML = '<p class="no-data">No active alerts</p>';
                } else {
                    alertsContainer.innerHTML = data.alerts.map((alert, idx) => {
                        const level = idx < 2 ? 'high' : idx < 4 ? 'medium' : 'low';
                        const timeAgo = this.getTimeAgo(new Date(alert.time));
                        
                        return `
                            <div class="alert-item ${level}">
                                <div class="alert-header">
                                    <span class="alert-title">${alert.reason}</span>
                                    <span class="alert-time">${timeAgo}</span>
                                </div>
                                <div class="alert-message">${alert.device || 'Unknown Device'} detected</div>
                                <div class="alert-details">Vendor: ${alert.vendor || 'Unknown'} | ID: ${alert.id || 'N/A'}</div>
                            </div>
                        `;
                    }).join('');
                }
            }

            if (alertBadge) {
                alertBadge.textContent = data.total || 0;
            }

            const activeAlertCount = document.getElementById('active-alert-count');
            if (activeAlertCount) {
                activeAlertCount.textContent = data.total || 0;
            }
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }

    /**
     * Load activity log from API
     */
    async loadActivityLog() {
        try {
            const response = await fetch('/api/events');
            const data = await response.json();
            
            const tbody = document.getElementById('logs-tbody');
            if (!tbody) return;

            if (data.events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">No events recorded</td></tr>';
                return;
            }

            tbody.innerHTML = data.events.slice(0, 4).map(event => {
                const timeAgo = this.getTimeAgo(new Date(event.time));
                const statusClass = event.result === 'UNTRUSTED' ? 'high-risk' : event.result === 'SAFE' ? 'trusted' : 'medium-risk';
                
                return `
                    <tr>
                        <td>${timeAgo}</td>
                        <td class="device-name">${event.device || 'Unknown'}</td>
                        <td>${event.vendor || 'N/A'}</td>
                        <td>${event.product || 'N/A'}</td>
                        <td><span class="badge-detection ${event.action?.toLowerCase() || 'normal'}">${event.reason || 'Event'}</span></td>
                        <td>${event.action || 'Logged'}</td>
                        <td><span class="status-badge ${statusClass}">${event.result || 'Pending'}</span></td>
                    </tr>
                `;
            }).join('');
        } catch (error) {
            console.error('Error loading activity log:', error);
        }
    }

    /**
     * Load full event log for the logs section
     */
    async loadEvents() {
        try {
            const response = await fetch('/api/events');
            const data = await response.json();

            const tbody = document.getElementById('events-tbody');
            if (!tbody) return;

            if (!data.events || data.events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">No events recorded</td></tr>';
                return;
            }

            tbody.innerHTML = data.events.map(event => {
                const result = (event.result || '').toUpperCase();
                const badgeClass =
                    result === 'UNTRUSTED' ? 'high-risk' :
                    result === 'TRUSTED' ? 'trusted' :
                    'medium-risk';

                return `
                    <tr data-result="${result.toLowerCase()}" data-search="${[
                        event.device,
                        event.vendor,
                        event.product,
                        event.action,
                        event.reason,
                        event.id,
                    ].filter(Boolean).join(' ').toLowerCase()}">
                        <td>${this.getTimeAgo(new Date(event.time))}</td>
                        <td>${event.device || '-'}</td>
                        <td>${event.vendor || '-'}</td>
                        <td>${event.product || '-'}</td>
                        <td><span class="status-badge ${badgeClass}">${result || 'UNKNOWN'}</span></td>
                        <td>${event.action || '-'}</td>
                        <td>${event.reason || '-'}</td>
                    </tr>
                `;
            }).join('');

            this.filterEvents();
        } catch (error) {
            console.error('Error loading events:', error);
            const tbody = document.getElementById('events-tbody');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">Error loading events</td></tr>';
            }
        }
    }

    /**
     * Load trusted devices from API
     */
    async loadTrustedDevices() {
        try {
            const response = await fetch('/api/trusted-devices');
            const data = await response.json();
            
            const trustedList = document.getElementById('trusted-devices-list');
            if (!trustedList) return;

            if (data.trusted_devices.length === 0) {
                trustedList.innerHTML = '<p class="no-data">No trusted devices yet</p>';
                return;
            }

            trustedList.innerHTML = data.trusted_devices.map(device => `
                <div class="device-card trusted">
                    <div class="device-name">${device.product || 'Trusted Device'}</div>
                    <div class="device-info">Vendor: <strong>${device.vendor || device.id || 'N/A'}</strong></div>
                    <div class="device-info">ID: <strong>${device.id}</strong></div>
                    <div class="device-info">Added: <strong>${device.added_at ? new Date(device.added_at).toLocaleDateString() : 'Unknown'}</strong></div>
                    <div class="device-status">
                        <span class="device-status-badge trusted">✓ TRUSTED</span>
                        <button class="device-action-button ghost" data-remove-device-id="${device.id}">Remove</button>
                    </div>
                </div>
            `).join('');
            trustedList.querySelectorAll('[data-remove-device-id]').forEach(button => {
                button.addEventListener('click', () => {
                    this.removeTrustedDevice(button.dataset.removeDeviceId);
                });
            });
        } catch (error) {
            console.error('Error loading trusted devices:', error);
        }
    }

    async loadWhitelistCandidates() {
        const candidateList = document.getElementById('whitelist-candidates');
        if (!candidateList) return;

        candidateList.innerHTML = '<p class="no-data">Loading candidates...</p>';
        try {
            const response = await fetch('/api/whitelist/candidates');
            const data = await response.json();

            if (!data.candidates || data.candidates.length === 0) {
                candidateList.innerHTML = '<p class="no-data">No recent devices available to trust</p>';
                return;
            }

            candidateList.innerHTML = data.candidates.map(device => `
                <div class="modal-list-item">
                    <div>
                        <p class="modal-item-title">${device.name || device.product || device.id}</p>
                        <p class="modal-item-subtitle">${device.vendor || 'Unknown'} • ${device.id}</p>
                    </div>
                    <button
                        class="device-action-button"
                        data-candidate-device-id="${device.id}"
                        data-candidate-device-vendor="${this.escapeHtml(device.vendor || '')}"
                        data-candidate-device-product="${this.escapeHtml(device.product || '')}"
                        data-candidate-device-name="${this.escapeHtml(device.name || '')}"
                    >
                        Trust
                    </button>
                </div>
            `).join('');

            candidateList.querySelectorAll('[data-candidate-device-id]').forEach(button => {
                button.addEventListener('click', () => {
                    this.addTrustedDevice(button.dataset.candidateDeviceId, {
                        vendor: button.dataset.candidateDeviceVendor,
                        product: button.dataset.candidateDeviceProduct,
                        name: button.dataset.candidateDeviceName,
                    });
                });
            });
        } catch (error) {
            candidateList.innerHTML = '<p class="no-data">Failed to load whitelist candidates</p>';
            console.error('Error loading whitelist candidates:', error);
        }
    }

    async loadTests() {
        const testsList = document.getElementById('tests-list');
        if (!testsList) return;

        testsList.innerHTML = '<p class="no-data">Loading tests...</p>';
        try {
            const response = await fetch('/api/tests');
            const data = await response.json();

            if (!data.tests || data.tests.length === 0) {
                testsList.innerHTML = '<p class="no-data">No test cases found</p>';
                return;
            }

            testsList.innerHTML = data.tests.map(test => `
                <div class="test-item">
                    <div class="test-meta">
                        <p class="test-name">${this.escapeHtml(test.name)}</p>
                        <p class="test-file">${this.escapeHtml(test.file)}</p>
                    </div>
                    <button class="device-action-button" data-run-test-id="${this.escapeHtml(test.id)}" data-run-test-name="${this.escapeHtml(test.name)}">
                        Execute
                    </button>
                </div>
            `).join('');

            testsList.querySelectorAll('[data-run-test-id]').forEach(button => {
                button.addEventListener('click', () => {
                    this.runTestCase(button.dataset.runTestId, button.dataset.runTestName, button);
                });
            });
        } catch (error) {
            testsList.innerHTML = '<p class="no-data">Failed to load tests</p>';
            console.error('Error loading tests:', error);
        }
    }

    async runTestCase(testId, testName, triggerButton) {
        const progressContainer = document.getElementById('test-run-progress');
        const outputContainer = document.getElementById('test-run-output');
        const title = document.getElementById('test-run-title');

        if (!progressContainer || !outputContainer || !title) {
            return;
        }

        this.openModal('test-run-modal');
        title.textContent = `Running ${testName || 'Test Case'}`;
        outputContainer.textContent = 'Preparing test execution...';
        progressContainer.innerHTML = '';

        const phases = [
            'Preparing test environment',
            'Launching pytest runner',
            'Collecting test output',
        ];

        let phaseIndex = 0;
        const renderPhase = (status = 'running') => {
            progressContainer.innerHTML = phases.map((phase, index) => {
                const state = index < phaseIndex ? 'done' : index === phaseIndex ? status : 'pending';
                return `
                    <div class="attack-step ${state}">
                        <div class="attack-step-header">
                            <span class="attack-step-title">${phase}</span>
                            <span class="attack-step-status">${state === 'done' ? 'DONE' : state === 'running' ? 'RUNNING' : 'PENDING'}</span>
                        </div>
                    </div>
                `;
            }).join('');
        };

        renderPhase();
        const progressTimer = setInterval(() => {
            phaseIndex = Math.min(phaseIndex + 1, phases.length - 1);
            renderPhase();
        }, 700);

        if (triggerButton) {
            triggerButton.disabled = true;
            triggerButton.textContent = 'Running...';
        }

        try {
            const response = await fetch('/api/tests/run', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ test_id: testId }),
            });
            const data = await response.json();

            clearInterval(progressTimer);
            phaseIndex = phases.length;
            renderPhase(data.result?.passed ? 'done' : 'running');

            const combinedOutput = [
                data.result?.stdout || '',
                data.result?.stderr || '',
            ].filter(Boolean).join('\n').trim();

            outputContainer.textContent = this.formatTestRunOutput(
                data.result,
                testName,
                combinedOutput,
            );

            progressContainer.innerHTML += `
                <div class="attack-step ${data.result?.passed ? 'done' : 'blocked'}">
                    <div class="attack-step-header">
                        <span class="attack-step-title">Execution Result</span>
                        <span class="attack-step-status">${data.result?.passed ? 'PASSED' : 'FAILED'}</span>
                    </div>
                </div>
            `;
        } catch (error) {
            clearInterval(progressTimer);
            progressContainer.innerHTML += `
                <div class="attack-step blocked">
                    <div class="attack-step-header">
                        <span class="attack-step-title">Execution Result</span>
                        <span class="attack-step-status">ERROR</span>
                    </div>
                </div>
            `;
            outputContainer.textContent = `Failed to run test: ${error.message}`;
            console.error('Error running test case:', error);
        } finally {
            if (triggerButton) {
                triggerButton.disabled = false;
                triggerButton.textContent = 'Execute';
            }
        }
    }

    formatTestRunOutput(result, fallbackTestName, combinedOutput) {
        if (!result) {
            return 'No test result was returned.';
        }

        const output = combinedOutput || '';
        const collectedMatch = output.match(/collected\s+(\d+)\s+items?(?:\s+\/\s+(\d+)\s+deselected)?/i);
        const finalSummaryMatch = output.match(/=+\s+(.+?)\s+in\s+[\d.]+s\s+=+/i);
        const selectedTestMatch = output.match(/^(tests\/.+?)\s+(PASSED|FAILED|ERROR|SKIPPED)/m);
        const failureLineMatch = output.match(/(?:AssertionError|E\s+.+|FAILED\s+.+)/m);

        const collectedCount = collectedMatch ? Number(collectedMatch[1]) : null;
        const deselectedCount = collectedMatch && collectedMatch[2] ? Number(collectedMatch[2]) : 0;
        const executedCount = collectedCount !== null ? Math.max(collectedCount - deselectedCount, 0) : null;
        const selectedTest = selectedTestMatch ? selectedTestMatch[1] : fallbackTestName || 'Selected test';
        const finalSummary = finalSummaryMatch ? finalSummaryMatch[1] : '';

        const lines = [];
        lines.push(result.passed ? 'Test result: Passed' : 'Test result: Failed');
        lines.push(`Test case: ${selectedTest}`);

        if (executedCount !== null) {
            lines.push(`Tests executed: ${executedCount}`);
        }

        if (deselectedCount) {
            lines.push(`Other tests skipped: ${deselectedCount} because only the selected test was run`);
        }

        if (result.passed) {
            lines.push('');
            lines.push('What happened:');
            lines.push('- Pytest started successfully');
            lines.push(`- ${selectedTest} completed without errors`);
            if (finalSummary) {
                lines.push(`- Runner summary: ${finalSummary}`);
            }
            lines.push('- Coverage report was updated after the run');
            return lines.join('\n');
        }

        lines.push('');
        lines.push('What happened:');
        if (failureLineMatch) {
            lines.push(`- ${failureLineMatch[0].replace(/^E\s+/, '').trim()}`);
        } else if (finalSummary) {
            lines.push(`- ${finalSummary}`);
        } else {
            lines.push('- The test runner reported a failure');
        }

        const interestingLines = output
            .split('\n')
            .map(line => line.trim())
            .filter(line => line)
            .filter(line =>
                line.startsWith('E ') ||
                line.includes('AssertionError') ||
                line.includes('FAILED') ||
                line.includes('ERROR')
            )
            .slice(0, 5);

        if (interestingLines.length) {
            lines.push('');
            lines.push('Important details:');
            interestingLines.forEach(line => {
                lines.push(`- ${line.replace(/^E\s+/, '')}`);
            });
        }

        return lines.join('\n');
    }

    async handleManualWhitelistSubmit() {
        const deviceId = document.getElementById('manual-device-id')?.value?.trim();
        const vendor = document.getElementById('manual-device-vendor')?.value?.trim();
        const product = document.getElementById('manual-device-product')?.value?.trim();

        if (!deviceId) {
            this.setDeviceModalFeedback('Device ID is required.', true);
            return;
        }

        await this.addTrustedDevice(deviceId, { vendor, product, name: product });
    }

    async addTrustedDevice(deviceId, deviceInfo = {}) {
        try {
            const response = await fetch('/api/whitelist/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    device_id: deviceId,
                    device_info: deviceInfo,
                }),
            });
            const data = await response.json();

            if (!response.ok) {
                this.setDeviceModalFeedback(data.error || 'Failed to add trusted device.', true);
                return;
            }

            this.setDeviceModalFeedback(data.message || 'Trusted device saved.', false);
            const manualWhitelistForm = document.getElementById('manual-whitelist-form');
            if (manualWhitelistForm) {
                manualWhitelistForm.reset();
            }
            await Promise.all([
                this.loadTrustedDevices(),
                this.loadDevices(),
                this.loadWhitelistCandidates(),
                this.updateStats(),
            ]);
        } catch (error) {
            this.setDeviceModalFeedback('Failed to add trusted device.', true);
            console.error('Error adding trusted device:', error);
        }
    }

    async removeTrustedDevice(deviceId) {
        try {
            const response = await fetch(`/api/whitelist/remove/${encodeURIComponent(deviceId)}`, {
                method: 'DELETE',
            });
            const data = await response.json();
            if (!response.ok) {
                console.error('Failed to remove trusted device:', data.error);
                return;
            }

            await Promise.all([
                this.loadTrustedDevices(),
                this.loadDevices(),
                this.loadWhitelistCandidates(),
                this.updateStats(),
            ]);
        } catch (error) {
            console.error('Error removing trusted device:', error);
        }
    }

    setDeviceModalFeedback(message, isError) {
        const feedback = document.getElementById('device-modal-feedback');
        if (!feedback) return;
        feedback.textContent = message;
        feedback.classList.toggle('error', Boolean(isError));
        feedback.classList.toggle('success', !isError);
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    async runAttackSimulation() {
        const flowContainer = document.getElementById('attack-flow');
        const openLogsButton = document.getElementById('attack-open-logs');
        const triggerButton = document.getElementById('simulate-attacks-btn');

        if (!flowContainer || !openLogsButton || !triggerButton) {
            return;
        }

        this.openModal('attack-modal');
        openLogsButton.classList.add('hidden');
        flowContainer.innerHTML = '<p class="no-data">Preparing attack simulation...</p>';
        triggerButton.disabled = true;
        triggerButton.textContent = 'Running Demo...';

        try {
            const response = await fetch('/api/simulate_attack', {
                method: 'POST',
            });
            const data = await response.json();

            if (!response.ok || !data.success) {
                flowContainer.innerHTML = `<p class="no-data">${this.escapeHtml(data.error || 'Simulation failed')}</p>`;
                return;
            }

            flowContainer.innerHTML = '';
            for (const step of data.steps || []) {
                const item = document.createElement('div');
                item.className = `attack-step ${step.status === 'DISABLED' ? 'disabled' : 'blocked'}`;
                item.innerHTML = `
                    <div class="attack-step-header">
                        <span class="attack-step-title">${this.escapeHtml(step.title)}</span>
                        <span class="attack-step-status">${this.escapeHtml(step.status)}</span>
                    </div>
                    <p class="attack-step-device">${this.escapeHtml(step.device)}</p>
                    <p class="attack-step-reason">${this.escapeHtml(step.reason)}</p>
                `;
                flowContainer.appendChild(item);
                flowContainer.scrollTop = flowContainer.scrollHeight;
                // eslint-disable-next-line no-await-in-loop
                await new Promise(resolve => setTimeout(resolve, step.delay_ms || 800));
            }

            openLogsButton.classList.remove('hidden');
            await Promise.all([
                this.updateStats(),
                this.loadActivityChart(),
                this.loadThreatsChart(),
                this.loadActivityLog(),
                this.loadEvents(),
                this.loadDevices(),
                this.loadAlerts(),
            ]);
        } catch (error) {
            flowContainer.innerHTML = '<p class="no-data">Simulation failed to execute.</p>';
            console.error('Error running attack simulation:', error);
        } finally {
            triggerButton.disabled = false;
            triggerButton.textContent = 'Run Demo Attack Flow';
        }
    }

    /**
     * Filter logs by search query
     */
    filterLogs(query) {
        const rows = document.querySelectorAll('#logs-tbody tr');
        const searchLower = query.toLowerCase();
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchLower) ? '' : 'none';
        });
    }

    /**
     * Filter alerts by severity level
     */
    filterAlerts(level) {
        const alerts = document.querySelectorAll('.alert-item');
        alerts.forEach(alert => {
            if (level === '') {
                alert.style.display = '';
            } else {
                alert.style.display = alert.classList.contains(level) ? '' : 'none';
            }
        });
    }

    /**
     * Filter events by type
     */
    filterEvents(type) {
        const rows = document.querySelectorAll('#events-tbody tr');
        const searchQuery = (document.getElementById('event-search')?.value || '').trim().toLowerCase();
        const selectedType = typeof type === 'string'
            ? type
            : (document.getElementById('event-filter')?.value || '');

        rows.forEach(row => {
            const rowText = (row.dataset.search || row.textContent || '').toLowerCase();
            const rowResult = row.dataset.result || '';
            const matchesSearch = !searchQuery || rowText.includes(searchQuery);
            const matchesType =
                !selectedType ||
                (selectedType === 'threat' && rowResult === 'untrusted') ||
                (selectedType === 'trusted' && rowResult === 'trusted') ||
                (selectedType === 'warning' && rowResult === 'safe');

            row.style.display = matchesSearch && matchesType ? '' : 'none';
        });
    }

    /**
     * Filter devices by name or vendor
     */
    filterDevices(query) {
        const cards = document.querySelectorAll('#devices .device-card');
        const searchLower = query.toLowerCase();
        
        cards.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = text.includes(searchLower) ? '' : 'none';
        });
    }

    /**
     * Handle global search across all sections
     */
    handleGlobalSearch(query) {
        if (!query.trim()) {
            // Show all items if search is empty
            this.filterLogs('');
            this.filterDevices('');
            return;
        }

        // Search in current section
        if (this.currentSection === 'dashboard' || this.currentSection === 'logs') {
            this.filterLogs(query);
            this.filterEvents();
        } else if (this.currentSection === 'devices') {
            this.filterDevices(query);
        } else if (this.currentSection === 'alerts') {
            this.filterAlerts('');
        }

        console.log('Searching for:', query);
    }

    /**
     * Update data periodically (real-time simulation)
     */
    startRealtimeUpdates() {
        // Refresh data every 5 seconds for near real-time updates
        setInterval(() => {
            this.updateStats();
            this.loadActivityChart();
            this.loadThreatsChart();
            this.loadActivityLog();
            this.loadEvents();
            this.loadDevices();
            this.loadAlerts();
            this.loadTrustedDevices();
        }, 5000);
    }

    getThreatLevel(stats) {
        if (!stats || !stats.total_events) {
            return 'NONE';
        }
        if (stats.untrusted > 0 || stats.blocked > 0 || stats.disabled > 0) {
            return 'HIGH';
        }
        if (stats.safe > 0) {
            return 'MEDIUM';
        }
        return 'LOW';
    }

    getThreatColor(level) {
        switch (level) {
            case 'HIGH':
                return '#f85149';
            case 'MEDIUM':
                return '#d29922';
            case 'LOW':
                return '#2ea043';
            default:
                return '#8b949e';
        }
    }

    updateThreatGauge(stats) {
        const gaugeFill = document.getElementById('threat-gauge-fill');
        const gaugeValue = document.getElementById('threat-gauge-value');
        const gaugeLabel = document.getElementById('threat-gauge-label');

        if (!gaugeFill || !gaugeValue || !gaugeLabel) {
            return;
        }

        const total = stats?.total_events || 0;
        const threatScore = total
            ? Math.min(
                100,
                Math.round(
                    (
                        ((stats.untrusted || 0) * 100) +
                        ((stats.blocked || 0) * 80) +
                        ((stats.disabled || 0) * 100) +
                        ((stats.safe || 0) * 25)
                    ) / total
                )
            )
            : 0;

        const level = this.getThreatLevel(stats);
        const dashOffset = 200 - (threatScore / 100) * 200;

        gaugeFill.style.strokeDashoffset = `${dashOffset}`;
        gaugeFill.style.stroke = this.getThreatColor(level);
        gaugeValue.textContent = total ? `${threatScore}%` : '--';
        gaugeLabel.textContent = total ? `${level} RISK` : 'NO DATA';
    }

    renderThreatLegend(labels, counts) {
        const legend = document.getElementById('threat-legend');
        if (!legend) return;

        if (!labels.length || !counts.some(count => count > 0)) {
            legend.innerHTML = '<p class="no-data">No detection data yet</p>';
            return;
        }

        const colors = this.charts.threatPie?.data?.datasets?.[0]?.backgroundColor || [];
        legend.innerHTML = labels.map((label, index) => `
            <div class="legend-item">
                <span class="legend-color" style="background-color: ${colors[index] || '#8b949e'}"></span>
                <span>${label} (${counts[index] || 0})</span>
            </div>
        `).join('');
    }

    renderDeviceRiskPanel(devices) {
        const riskList = document.getElementById('device-risk-list');
        if (!riskList) return;

        if (!devices.length) {
            riskList.innerHTML = '<p class="no-data">No device risk data yet</p>';
            return;
        }

        const rankedDevices = [...devices]
            .map(device => {
                const isThreat = (device.status || '').toLowerCase().includes('untrusted');
                const baseRisk = isThreat ? 70 : 15;
                const activityBonus = Math.min(25, (device.event_count || 0) * 5);
                const risk = Math.min(100, baseRisk + activityBonus);
                return {
                    name: device.type || device.product || device.id || 'Unknown Device',
                    risk,
                };
            })
            .sort((a, b) => b.risk - a.risk)
            .slice(0, 5);

        riskList.innerHTML = rankedDevices.map(device => {
            const riskClass = device.risk >= 70 ? 'high' : device.risk >= 40 ? 'medium' : 'low';
            return `
                <div class="risk-item ${riskClass}">
                    <div class="risk-info">
                        <p class="risk-name">${device.name}</p>
                        <p class="risk-percent">${device.risk}%</p>
                    </div>
                    <div class="risk-indicator">
                        <div class="risk-progress ${riskClass}" style="width: ${device.risk}%"></div>
                    </div>
                </div>
            `;
        }).join('');
    }

    /**
     * Group activities by hour
     */
    groupByHour(activities) {
        const now = new Date();
        const labels = [];
        const connections = [];
        const suspicious = [];

        // Create 7 hourly buckets
        for (let i = 6; i >= 0; i--) {
            const hour = new Date(now);
            hour.setHours(hour.getHours() - i);
            const hourStr = hour.getHours().toString().padStart(2, '0') + ':00';
            labels.push(hourStr);
            
            // Count activities in this hour
            const hourActivities = activities.filter(a => {
                const time = new Date(a.time);
                return time.getHours() === hour.getHours();
            });

            connections.push(hourActivities.length);
            suspicious.push(hourActivities.filter(a => a.result === 'UNTRUSTED').length);
        }

        return { labels, connections, suspicious };
    }

    /**
     * Get human-readable time ago
     */
    getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        
        if (seconds < 60) return 'Just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
        if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
        return Math.floor(seconds / 86400) + ' days ago';
    }

    escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new DashboardController();
    
    // Add gradient to gauge SVG
    const svg = document.querySelector('.gauge-svg');
    if (svg) {
        const defs = document.createElement('defs');
        const gradient = document.createElement('linearGradient');
        gradient.id = 'gaugeGradient';
        gradient.setAttribute('x1', '0%');
        gradient.setAttribute('y1', '0%');
        gradient.setAttribute('x2', '100%');
        gradient.setAttribute('y2', '100%');
        
        const stop1 = document.createElement('stop');
        stop1.setAttribute('offset', '0%');
        stop1.setAttribute('stop-color', '#f85149');
        
        const stop2 = document.createElement('stop');
        stop2.setAttribute('offset', '100%');
        stop2.setAttribute('stop-color', '#ff7b72');
        
        gradient.appendChild(stop1);
        gradient.appendChild(stop2);
        defs.appendChild(gradient);
        svg.insertBefore(defs, svg.firstChild);
    }
    
    console.log('✓ HIDGuard Dashboard initialized');
});

/**
 * Utility: Format timestamp
 */
function formatTime(date) {
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * Utility: Generate random color from palette
 */
function getRandomColor() {
    const colors = ['#58a6ff', '#2ea043', '#d29922', '#f85149'];
    return colors[Math.floor(Math.random() * colors.length)];
}
