/**
 * BullyMail V2 — Next-Gen Cyber Threat Intelligence Platform Controller
 * Mission Control Posture • Digital Forensics Matrix • Live SOC Stream • Sliding Drawer
 * Security: Strict HTML entity escaping for untrusted email content & evidence
 */

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

document.addEventListener('DOMContentLoaded', () => {
    window.activeInstitutionId = 1;
    window.cachedInstitutions = [];
    initNavigation();
    initSidebarToggle();
    initDropzones();
    initCharCounter();
    initDrawer();
    loadInstitutions();
    loadDashboardStats();
    loadAnalysisHistory();
    loadModelStatus();
    loadAvailableDatasets();
    loadPendingRegistrations();
    initForms();
    
    // Auto-refresh stats and live stream every 25s
    setInterval(() => {
        loadDashboardStats();
    }, 25000);

    // Listen for theme changes to adapt charts
    window.addEventListener('socThemeChanged', () => {
        renderCharts();
    });
});

/* ==========================================================================
   1. Navigation & Layout Controls
   ========================================================================== */
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link-v2, .nav-link-sub');
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = link.getAttribute('data-tab');
            if (!targetTab) return;
            
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            document.querySelectorAll('.tab-content-pane').forEach(pane => {
                pane.style.display = 'none';
            });
            
            const activePane = document.getElementById(targetTab);
            if (activePane) {
                activePane.style.display = 'block';
                if (targetTab === 'tab-dashboard') renderCharts();
                if (targetTab === 'tab-email') loadSecureMailboxes();
                if (targetTab === 'tab-pending-approvals') loadPendingRegistrations();
            }

            // Close mobile sidebar if open
            document.querySelector('.sidebar-v2')?.classList.remove('mobile-open');
        });
    });
}

function initSidebarToggle() {
    const sidebar = document.querySelector('.sidebar-v2');
    const toggleBtn = document.getElementById('sidebarToggleBtn');
    const mobileToggleBtn = document.getElementById('mobileMenuBtn');
    const brandLogo = document.querySelector('.brand-logo');

    // Restore state from localStorage
    const savedState = localStorage.getItem('bullymail_sidebar_collapsed');
    if (savedState === 'true' && sidebar && window.innerWidth > 992) {
        sidebar.classList.add('collapsed');
        if (toggleBtn) {
            toggleBtn.innerHTML = '<i class="fas fa-angles-right"></i>';
            toggleBtn.setAttribute('title', 'Expand Navigation Rail');
        }
    }

    const performToggle = () => {
        if (!sidebar) return;
        const willCollapse = !sidebar.classList.contains('collapsed');
        sidebar.classList.toggle('collapsed', willCollapse);
        localStorage.setItem('bullymail_sidebar_collapsed', willCollapse ? 'true' : 'false');
        
        if (toggleBtn) {
            toggleBtn.innerHTML = willCollapse ? '<i class="fas fa-angles-right"></i>' : '<i class="fas fa-angles-left"></i>';
            toggleBtn.setAttribute('title', willCollapse ? 'Expand Navigation Rail' : 'Collapse Navigation Rail');
        }

        // Trigger window resize so Chart.js charts automatically reflow to the new layout
        setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
        }, 260);
    };

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            performToggle();
        });
    }

    if (brandLogo && sidebar) {
        brandLogo.addEventListener('click', () => {
            if (sidebar.classList.contains('collapsed')) {
                performToggle();
            }
        });
    }

    if (mobileToggleBtn && sidebar) {
        mobileToggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('mobile-open');
        });
    }
}

function initCharCounter() {
    const textarea = document.getElementById('inputEmailText');
    const charCountEl = document.getElementById('charCountDisplay');
    if (textarea && charCountEl) {
        const updateCount = () => {
            const text = textarea.value || '';
            const words = text.trim() ? text.trim().split(/\s+/).length : 0;
            charCountEl.textContent = `${text.length} chars • ${words} words`;
        };
        textarea.addEventListener('input', updateCount);
        updateCount();
    }
}

/* ==========================================================================
   2. Contextual Sliding Investigation Drawer (.soc-drawer)
   ========================================================================== */
function initDrawer() {
    const overlay = document.getElementById('socDrawerOverlay');
    const closeBtn = document.getElementById('socDrawerCloseBtn');
    
    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                closeIncidentDrawer();
            }
        });
    }
    if (closeBtn) {
        closeBtn.addEventListener('click', closeIncidentDrawer);
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeIncidentDrawer();
        }
    });
}

async function openIncidentDrawer(id) {
    const overlay = document.getElementById('socDrawerOverlay');
    const drawer = document.getElementById('socDrawer');
    const body = document.getElementById('socDrawerBody');
    const title = document.getElementById('socDrawerTitle');
    const pdfBtn = document.getElementById('socDrawerAuditPdfBtn');
    
    if (!drawer || !body) return;

    if (title) title.innerHTML = `<i class="fas fa-shield-alt text-accent me-2"></i>Incident Case #BM-${escapeHtml(id)}`;

    if (pdfBtn) {
        pdfBtn.href = `/api/reports/view/${encodeURIComponent(id)}`;
        pdfBtn.classList.remove('d-none');
    }

    body.innerHTML = `
        <div class="p-5 text-center text-muted">
            <i class="fas fa-spinner fa-spin fa-2x text-accent mb-3"></i>
            <div class="small">Retrieving multi-vector forensic telemetry...</div>
        </div>
    `;
    
    document.body.style.overflow = 'hidden';
    overlay?.classList.add('active');
    drawer.classList.add('active');
    
    try {
        const res = await fetch(`/api/analysis/${id}`);
        const data = await res.json();
        if (data.success) {
            renderSecurityReport(data.analysis, body);
        } else {
            body.innerHTML = `<div class="alert alert-danger font-mono small p-3">${escapeHtml(data.error || 'Failed to load case.')}</div>`;
        }
    } catch (e) {
        body.innerHTML = `<div class="alert alert-danger font-mono small p-3">Error: ${escapeHtml(e.message)}</div>`;
    }
}

function closeIncidentDrawer() {
    document.getElementById('socDrawerOverlay')?.classList.remove('active');
    document.getElementById('socDrawer')?.classList.remove('active');
    document.body.style.overflow = '';
}

/* ==========================================================================
   3. Mission Control Dashboard Telemetry & Visualizations
   ========================================================================== */
let threatTrendChart = null;
window.recentAnalysisHistory = [];

async function loadDashboardStats() {
    try {
        const res = await fetch('/api/system-stats');
        const data = await res.json();
        if (data.success) {
            const s = data.stats;
            const setVal = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = Number(val || 0).toLocaleString();
            };

            const vBullying = s.bullying_detected || 0;
            const vPhishing = s.phishing_detected || 0;
            const vUrls = s.suspicious_urls || 0;
            const vMalware = s.malware_detected || 0;
            const vSocialEng = s.social_eng_detected || 0;
            const totalThreats = vBullying + vPhishing + vUrls + vMalware + vSocialEng;

            const r = s.risk_distribution || {};
            const criticals = r.CRITICAL || 0;
            const highs = r.HIGH || 0;
            const meds = r.MEDIUM || 0;
            const lows = r.LOW || 0;

            const activeVectorCount = [vBullying, vPhishing, vUrls, vMalware, vSocialEng].filter(cnt => cnt > 0).length;

            // 1. Executive Security Summary Strip
            setVal('statTotalAnalyses', s.total_analyses);
            setVal('execThreatsDetected', totalThreats);
            setVal('execCriticalThreats', criticals);

            const execActiveEl = document.getElementById('execActiveVectors');
            if (execActiveEl) execActiveEl.textContent = `${activeVectorCount} / 5`;

            const execSyncEl = document.getElementById('execLastSync');
            if (execSyncEl) {
                const now = new Date();
                execSyncEl.textContent = now.toLocaleTimeString('en-US', { hour12: false });
            }

            // 2. Threat Posture Hero Card
            const postureScoreEl = document.getElementById('postureScoreNum');
            const postureVal = document.getElementById('postureThreatLevel');
            const posturePill = document.getElementById('postureLevelPill');
            const postureSub = document.getElementById('postureSubtext');
            const postureRatio = document.getElementById('postureMonitoredRatio');

            let postureTitle = 'LOW RISK POSTURE';
            let posturePillClass = 'soc-pill-safe';
            let postureScore = 96;
            let postureColor = 'var(--threat-safe, #10b981)';

            if (criticals > 0 || totalThreats > 25) {
                postureTitle = 'CRITICAL THREAT';
                posturePillClass = 'soc-pill-dominant';
                postureScore = Math.max(25, 60 - (criticals * 8));
                postureColor = 'var(--threat-critical, #ef4444)';
                if (postureSub) postureSub.textContent = `${criticals} critical incident(s) require immediate analyst intervention across monitored communications.`;
            } else if (highs > 0 || totalThreats > 10) {
                postureTitle = 'ELEVATED THREAT';
                posturePillClass = 'soc-pill-highest-share';
                postureScore = Math.max(55, 80 - (highs * 5));
                postureColor = 'var(--threat-high, #f97316)';
                if (postureSub) postureSub.textContent = `${highs} high-severity incident(s) flagged across monitored channels.`;
            } else if (totalThreats > 0) {
                postureTitle = 'MODERATE ACTIVITY';
                posturePillClass = 'soc-pill-active';
                postureScore = Math.max(75, 90 - (totalThreats * 2));
                postureColor = 'var(--threat-medium, #f59e0b)';
                if (postureSub) postureSub.textContent = `Low-level suspicious events detected; baseline communications remain stable.`;
            } else {
                postureTitle = 'LOW RISK POSTURE';
                posturePillClass = 'soc-pill-safe';
                postureScore = 98;
                postureColor = 'var(--threat-safe, #10b981)';
                if (postureSub) postureSub.textContent = `Environment currently shows healthy posture with zero unmitigated threat incidents.`;
            }

            if (postureScoreEl) postureScoreEl.innerHTML = `${postureScore}<span class="soc-score-pct">%</span>`;
            if (postureVal) {
                postureVal.textContent = postureTitle;
                postureVal.style.color = postureColor;
            }
            if (posturePill) {
                posturePill.className = posturePillClass;
                posturePill.textContent = postureTitle;
            }
            if (postureRatio) {
                postureRatio.textContent = `${activeVectorCount} Active / ${5 - activeVectorCount} Clear`;
            }

            // Dynamic 5-Vector Coverage Chips in Posture Card
            const quickVectors = [
                { label: 'Cyberbullying', count: vBullying, icon: 'fa-user-slash text-danger' },
                { label: 'Phishing', count: vPhishing, icon: 'fa-fish text-warning' },
                { label: 'Risky Links', count: vUrls, icon: 'fa-link text-info' },
                { label: 'Malware Risk', count: vMalware, icon: 'fa-bug text-danger' },
                { label: 'Social Eng.', count: vSocialEng, icon: 'fa-user-shield text-warning' }
            ];
            const vecContainer = document.getElementById('postureVectorsQuickState');
            if (vecContainer) {
                vecContainer.innerHTML = quickVectors.map(v => {
                    const isActive = v.count > 0;
                    const badgeClass = isActive ? 'soc-pill-active' : 'soc-pill-clear';
                    const badgeText = isActive ? `${v.count} ACTIVE` : 'CLEAR';
                    return `<div class="soc-posture-vector-chip font-mono">
                        <span class="text-truncate me-1"><i class="fas ${v.icon} me-1"></i>${escapeHtml(v.label)}</span>
                        <span class="${badgeClass} flex-shrink-0" style="font-size: 0.6rem; padding: 1px 5px; white-space: nowrap;">${badgeText}</span>
                    </div>`;
                }).join('');
            }

            // Severity Distribution Stacked Bar & Counts
            const totalSeverityCount = criticals + highs + meds + lows;
            setVal('sevNumCrit', criticals);
            setVal('sevNumHigh', highs);
            setVal('sevNumMed', meds);
            setVal('sevNumLow', lows);

            const sevTotalEl = document.getElementById('postureSeverityTotal');
            if (sevTotalEl) sevTotalEl.textContent = `${totalSeverityCount} Analyzed`;

            const calcPct = (cnt) => totalSeverityCount > 0 ? ((cnt / totalSeverityCount) * 100).toFixed(1) : 0;
            const critBar = document.getElementById('sevSegCrit');
            const highBar = document.getElementById('sevSegHigh');
            const medBar = document.getElementById('sevSegMed');
            const lowBar = document.getElementById('sevSegLow');

            if (critBar) critBar.style.width = `${calcPct(criticals)}%`;
            if (highBar) highBar.style.width = `${calcPct(highs)}%`;
            if (medBar) medBar.style.width = `${calcPct(meds)}%`;
            if (lowBar) lowBar.style.width = totalSeverityCount === 0 ? '100%' : `${calcPct(lows)}%`;

            window.dashboardStatsData = s;
            renderSeverityMatrix(s.risk_distribution || {});
            renderCharts();
        } else {
            console.error('Failed to load dashboard telemetry:', data.error);
            const postureVal = document.getElementById('postureThreatLevel');
            const postureSub = document.getElementById('postureSubtext');
            if (postureVal) postureVal.innerHTML = `<span class="text-danger">TELEMETRY ERROR</span>`;
            if (postureSub) postureSub.textContent = `Unable to load dashboard telemetry: ${data.error || 'Server error'}`;
            if (window.SOCToast) SOCToast.error(data.error || 'Failed to load telemetry', 'API Error');
        }
    } catch (e) {
        console.error('Error loading SOC telemetry stats:', e);
        const postureVal = document.getElementById('postureThreatLevel');
        const postureSub = document.getElementById('postureSubtext');
        if (postureVal) postureVal.innerHTML = `<span class="text-danger">TELEMETRY ERROR</span>`;
        if (postureSub) postureSub.textContent = `Unable to load dashboard telemetry: ${e.message}`;
        if (window.SOCToast) SOCToast.error(`Error loading stats: ${e.message}`, 'Network Error');
    }

    // Load live stream and pending registrations
    loadLiveThreatStream();
    loadPendingRegistrations();
}

window.pendingUsersRawData = [];

async function loadPendingRegistrations() {
    const container = document.getElementById('pendingRegistrationsContainer');
    const sidebarBadge = document.getElementById('sidebarPendingBadge');
    const dedicatedBadge = document.getElementById('dedicatedPendingBadge');
    const kpiPending = document.getElementById('kpiPendingCount');
    const kpiApproved = document.getElementById('kpiApprovedCount');
    const kpiRejected = document.getElementById('kpiRejectedCount');
    const kpiTotal = document.getElementById('kpiTotalCount');

    try {
        const res = await fetch('/api/admin/pending-registrations');
        const data = await res.json();
        const pendingUsers = (data.success && data.pending_users) ? data.pending_users : [];
        window.pendingUsersRawData = pendingUsers;
        const pendingCount = data.pending_count !== undefined ? data.pending_count : pendingUsers.length;

        // Update sidebar dynamic badge
        if (sidebarBadge) {
            if (pendingCount > 0) {
                sidebarBadge.textContent = pendingCount;
                sidebarBadge.classList.remove('d-none');
            } else {
                sidebarBadge.classList.add('d-none');
            }
        }

        // Update KPI summary cards with real database metrics
        if (kpiPending) kpiPending.textContent = pendingCount;
        if (kpiApproved) kpiApproved.textContent = data.approved_count !== undefined ? data.approved_count : '--';
        if (kpiRejected) kpiRejected.textContent = data.rejected_count !== undefined ? data.rejected_count : '--';
        if (kpiTotal) kpiTotal.textContent = data.total_count !== undefined ? data.total_count : pendingCount;
        if (dedicatedBadge) dedicatedBadge.textContent = `${pendingCount} PENDING REQUESTS`;

        // Populate Institution Filter options dynamically
        const instFilter = document.getElementById('pendingInstFilter');
        if (instFilter) {
            const currentVal = instFilter.value;
            const instSet = new Set();
            pendingUsers.forEach(u => {
                const instName = u.institution_name || u.institution_code || 'Default Workspace';
                if (instName) instSet.add(instName);
            });
            let optsHtml = '<option value="ALL">All Institutions</option>';
            instSet.forEach(inst => {
                const safeInst = escapeHtml(inst);
                optsHtml += `<option value="${safeInst}">${safeInst}</option>`;
            });
            instFilter.innerHTML = optsHtml;
            if (Array.from(instFilter.options).some(o => o.value === currentVal)) {
                instFilter.value = currentVal;
            }
        }

        // Apply current active search & filters
        applyPendingFilters();
    } catch (e) {
        console.error('Error loading pending registrations:', e);
        if (sidebarBadge) sidebarBadge.classList.add('d-none');
        if (container) {
            container.innerHTML = `
                <div class="py-4 px-4 text-center text-muted font-mono">
                    <i class="fas fa-check-circle text-success me-2 fa-2x mb-2 d-block"></i>
                    <div class="fw-semibold text-primary-soc font-mono">No pending registration requests</div>
                    <div class="small text-muted font-mono mt-1">All institutional registration requests have been reviewed.</div>
                </div>
            `;
        }
    }
}

function applyPendingFilters() {
    const container = document.getElementById('pendingRegistrationsContainer');
    if (!container) return;

    const rawUsers = window.pendingUsersRawData || [];
    const searchVal = (document.getElementById('pendingSearchInput')?.value || '').toLowerCase().trim();
    const statusVal = document.getElementById('pendingStatusFilter')?.value || 'ALL';
    const instVal = document.getElementById('pendingInstFilter')?.value || 'ALL';
    const roleVal = document.getElementById('pendingRoleFilter')?.value || 'ALL';

    const clearSearchBtn = document.getElementById('btnClearPendingSearch');
    if (clearSearchBtn) {
        if (searchVal.length > 0) clearSearchBtn.classList.remove('d-none');
        else clearSearchBtn.classList.add('d-none');
    }

    const filtered = rawUsers.filter(u => {
        const username = (u.username || '').toLowerCase();
        const email = (u.email || '').toLowerCase();
        const inst = (u.institution_name || u.institution_code || 'Default Workspace').toLowerCase();
        const role = (u.role || 'analyst').toLowerCase();
        const isVerified = Boolean(u.email_verified_at);

        // Search match across name, email, institution
        if (searchVal && !username.includes(searchVal) && !email.includes(searchVal) && !inst.includes(searchVal)) {
            return false;
        }

        // Status filter
        if (statusVal === 'VERIFIED' && !isVerified) return false;
        if (statusVal === 'UNVERIFIED' && isVerified) return false;

        // Institution filter
        if (instVal !== 'ALL' && instVal.toLowerCase() !== inst) return false;

        // Role filter
        if (roleVal !== 'ALL' && roleVal.toLowerCase() !== role) return false;

        return true;
    });

    // Update Result Count Text
    const countTextEl = document.getElementById('pendingResultCountText');
    if (countTextEl) {
        countTextEl.textContent = `Showing ${filtered.length} of ${rawUsers.length} requests`;
    }

    // Update Active Filter Chips
    updatePendingActiveFilterChips(searchVal, statusVal, instVal, roleVal);

    if (filtered.length > 0) {
        let html = `
            <div class="table-responsive">
                <table class="soc-table">
                    <thead>
                        <tr>
                            <th>USER / ACCOUNT</th>
                            <th>EMAIL</th>
                            <th>INSTITUTION</th>
                            <th>REQUESTED ROLE</th>
                            <th>REQUESTED DATE</th>
                            <th>STATUS</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        filtered.forEach(u => {
            const safeUser = escapeHtml(u.username);
            const safeEmail = escapeHtml(u.email || 'N/A');
            const safeInst = escapeHtml(u.institution_name || u.institution_code || 'Default Workspace');
            const safeRole = escapeHtml(u.role || 'analyst');
            const safeDate = u.created_at ? new Date(u.created_at).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'N/A';
            const isVerified = Boolean(u.email_verified_at);
            const verBadge = isVerified
                ? `<span class="badge bg-success font-mono" style="font-size: 0.68rem;"><i class="fas fa-check-circle me-1"></i>VERIFIED</span>`
                : `<span class="badge bg-warning text-dark font-mono" style="font-size: 0.68rem;"><i class="fas fa-clock me-1"></i>UNVERIFIED</span>`;

            html += `
                <tr>
                    <td><strong class="text-primary-soc font-mono">${safeUser}</strong></td>
                    <td class="font-mono text-muted small">${safeEmail}</td>
                    <td class="font-mono small text-accent"><i class="fas fa-building me-1"></i>${safeInst}</td>
                    <td><span class="badge bg-secondary font-mono">${safeRole}</span></td>
                    <td class="font-mono text-muted small">${safeDate}</td>
                    <td>${verBadge}</td>
                    <td>
                        <button class="btn-soc-primary btn-sm me-1 font-mono" onclick="handleUserApproval(${u.id}, 'approve', '${safeUser}')">
                            <i class="fas fa-user-check me-1"></i> Approve
                        </button>
                        <button class="btn-soc-danger btn-sm font-mono" onclick="confirmRejectUser(${u.id}, '${safeUser}')">
                            <i class="fas fa-user-times me-1"></i> Reject
                        </button>
                    </td>
                </tr>
            `;
        });
        html += `
                    </tbody>
                </table>
            </div>
        `;
        container.innerHTML = html;
    } else {
        container.innerHTML = `
            <div class="py-4 px-4 text-center text-muted font-mono">
                <i class="fas fa-check-circle text-success me-2 fa-2x mb-2 d-block"></i>
                <div class="fw-semibold text-primary-soc font-mono">No pending registration requests</div>
                <div class="small text-muted font-mono mt-1">All institutional registration requests have been reviewed and authorized.</div>
            </div>
        `;
    }
}

function updatePendingActiveFilterChips(search, status, inst, role) {
    const chipsContainer = document.getElementById('pendingActiveFilterChips');
    const resetBtn = document.getElementById('btnResetPendingFilters');
    if (!chipsContainer) return;

    let chips = [];
    if (search) chips.push({ label: `Search: "${search}"`, type: 'search' });
    if (status !== 'ALL') chips.push({ label: `Status: ${status}`, type: 'status' });
    if (inst !== 'ALL') chips.push({ label: `Inst: ${inst}`, type: 'inst' });
    if (role !== 'ALL') chips.push({ label: `Role: ${role}`, type: 'role' });

    if (resetBtn) {
        if (chips.length > 0) {
            resetBtn.classList.add('has-active');
            resetBtn.innerHTML = `<i class="fas fa-undo-alt me-1"></i> Clear (${chips.length})`;
        } else {
            resetBtn.classList.remove('has-active');
            resetBtn.innerHTML = `<i class="fas fa-undo-alt me-1"></i> Clear`;
        }
    }

    chipsContainer.innerHTML = chips.map(c => `
        <span class="soc-chip">
            ${escapeHtml(c.label)}
            <i class="fas fa-times chip-remove" onclick="clearSpecificPendingFilter('${c.type}')"></i>
        </span>
    `).join('');
}

function clearSpecificPendingFilter(type) {
    if (type === 'search') clearPendingSearch();
    if (type === 'status') {
        const el = document.getElementById('pendingStatusFilter');
        if (el) el.value = 'ALL';
    }
    if (type === 'inst') {
        const el = document.getElementById('pendingInstFilter');
        if (el) el.value = 'ALL';
    }
    if (type === 'role') {
        const el = document.getElementById('pendingRoleFilter');
        if (el) el.value = 'ALL';
    }
    applyPendingFilters();
}

function clearPendingSearch() {
    const input = document.getElementById('pendingSearchInput');
    if (input) input.value = '';
    applyPendingFilters();
}

function resetPendingFilters() {
    const searchInput = document.getElementById('pendingSearchInput');
    const statusSelect = document.getElementById('pendingStatusFilter');
    const instSelect = document.getElementById('pendingInstFilter');
    const roleSelect = document.getElementById('pendingRoleFilter');

    if (searchInput) searchInput.value = '';
    if (statusSelect) statusSelect.value = 'ALL';
    if (instSelect) instSelect.value = 'ALL';
    if (roleSelect) roleSelect.value = 'ALL';

    applyPendingFilters();
}

function openSecureMailboxTab(e) {
    if (e) e.preventDefault();
    const link = document.querySelector('[data-tab="tab-email"]');
    if (link) link.click();
}

function confirmRejectUser(userId, username) {
    const targetUserEl = document.getElementById('rejectModalTargetUser');
    const targetIdEl = document.getElementById('rejectModalUserId');
    if (targetUserEl) targetUserEl.textContent = username || `#${userId}`;
    if (targetIdEl) targetIdEl.value = userId;

    const modalEl = document.getElementById('rejectUserConfirmModal');
    if (modalEl && window.bootstrap) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    } else {
        if (confirm(`Are you sure you want to reject registration request for user '${username}'?`)) {
            executeRejectUserSubmit(userId);
        }
    }
}

async function executeRejectUserSubmit(forcedUserId) {
    const userId = forcedUserId || document.getElementById('rejectModalUserId')?.value;
    if (!userId) return;

    try {
        const res = await fetch('/api/admin/approve-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: parseInt(userId, 10), action: 'reject' })
        });
        const data = await res.json();

        const modalEl = document.getElementById('rejectUserConfirmModal');
        if (modalEl && window.bootstrap) {
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
        }

        if (data.success) {
            if (window.SOCToast) {
                SOCToast.success(data.message || '✓ Account registration request rejected.', 'Account Approvals');
            }
            loadPendingRegistrations();
            loadDashboardStats();
        } else {
            if (window.SOCToast) {
                SOCToast.error(data.error || 'Failed to reject registration request.', 'Admin Error');
            }
        }
    } catch (e) {
        console.error('Error rejecting user:', e);
        if (window.SOCToast) SOCToast.error(`Error: ${e.message}`, 'Admin Error');
    }
}

async function handleUserApproval(userId, action, username) {
    if (!userId || !action) return;

    if (action === 'reject') {
        confirmRejectUser(userId, username);
        return;
    }

    const payload = {
        user_id: userId,
        action: 'approve',
        provision_type: 'assign_existing',
        institution_id: 1,
        role: 'analyst'
    };

    try {
        const res = await fetch('/api/admin/approve-user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            if (window.SOCToast) {
                SOCToast.success(data.message || '✓ Account approved successfully.', 'Account Approvals');
            }
            loadPendingRegistrations();
            loadDashboardStats();
        } else {
            if (window.SOCToast) {
                SOCToast.error(data.error || 'Operation failed.', 'Admin Action Error');
            }
        }
    } catch (e) {
        if (window.SOCToast) {
            SOCToast.error(`Error: ${e.message}`, 'Admin Action Error');
        }
    }
}

function renderSeverityMatrix(dist) {
    const total = (dist.LOW || 0) + (dist.MEDIUM || 0) + (dist.HIGH || 0) + (dist.CRITICAL || 0) || 1;
    
    const updateBar = (tier, count) => {
        const pct = Math.round((count / total) * 100);
        const countEl = document.getElementById(`distCount_${tier}`);
        const barEl = document.getElementById(`distBar_${tier}`);
        if (countEl) countEl.textContent = `${count} (${pct}%)`;
        if (barEl) barEl.style.width = `${Math.max(4, pct)}%`;
    };

    updateBar('CRITICAL', dist.CRITICAL || 0);
    updateBar('HIGH', dist.HIGH || 0);
    updateBar('MEDIUM', dist.MEDIUM || 0);
    updateBar('LOW', dist.LOW || 0);
}

async function loadLiveThreatStream() {
    const container = document.getElementById('liveThreatStreamContainer');
    const countText = document.getElementById('liveStreamCountText');
    if (!container) return;

    try {
        const res = await fetch('/api/analysis-history?limit=15');
        const data = await res.json();
        if (data.success && data.history && data.history.length > 0) {
            window.recentAnalysisHistory = data.history;
            if (countText) countText.textContent = `Showing latest ${data.history.length} incident events`;

            let html = '';
            data.history.forEach(item => {
                const risk = escapeHtml(item.overall_risk_level || 'LOW');
                const isHighRisk = (risk === 'CRITICAL' || risk === 'HIGH' || item.is_bullying === 1);
                const timeStr = item.created_at ? escapeHtml(item.created_at.split(' ')[1] || item.created_at) : 'Just now';
                const confVal = Math.round((item.overall_confidence || item.confidence || item.ml_confidence || 0.85) * 100);

                let vLabel = 'Clean / Safe';
                let vIcon = 'fa-shield-halved text-success';
                let confClass = 'conf-low';

                if (item.is_bullying) {
                    vLabel = 'Cyberbullying';
                    vIcon = 'fa-user-slash text-danger';
                    confClass = 'conf-crit';
                } else if (item.phishing_risk_level && item.phishing_risk_level !== 'LOW') {
                    vLabel = 'Phishing';
                    vIcon = 'fa-fish text-warning';
                    confClass = 'conf-high';
                } else if (item.suspicious_urls_count > 0) {
                    vLabel = 'Risky Links';
                    vIcon = 'fa-link text-cyan';
                    confClass = 'conf-high';
                } else if (item.social_eng_risk_level && item.social_eng_risk_level !== 'LOW') {
                    vLabel = 'Social Eng.';
                    vIcon = 'fa-user-shield text-purple';
                    confClass = 'conf-med';
                } else if (item.malware_detected) {
                    vLabel = 'Malware';
                    vIcon = 'fa-bug text-pink';
                    confClass = 'conf-crit';
                }

                html += `
                    <div class="soc-stream-row ${isHighRisk ? 'is-high-risk' : ''}" onclick="openIncidentDrawer(${item.id})">
                        <div class="soc-stream-col-risk">
                            <span class="badge-risk ${risk}">${risk}</span>
                        </div>
                        <div class="soc-stream-col-vector">
                            <span class="soc-stream-vector-pill"><i class="fas ${vIcon} me-1"></i> ${escapeHtml(vLabel)}</span>
                        </div>
                        <div class="soc-stream-col-main">
                            <div class="soc-stream-subject">${escapeHtml(item.email_subject || 'Untitled Communication')}</div>
                            <div class="soc-stream-sender font-mono"><i class="fas fa-envelope me-1 text-muted"></i>${escapeHtml(item.email_from || 'Unknown')}</div>
                        </div>
                        <div class="soc-stream-col-conf">
                            <div class="soc-conf-bar-wrap" title="${confVal}% Confidence">
                                <div class="soc-conf-label font-mono">${confVal}%</div>
                                <div class="soc-conf-track"><div class="soc-conf-fill ${confClass}" style="width: ${confVal}%;"></div></div>
                            </div>
                        </div>
                        <div class="soc-stream-col-time">
                            <span class="soc-stream-time font-mono">${timeStr}</span>
                        </div>
                        <div class="soc-stream-col-action text-end">
                            <button type="button" class="btn-soc-outline btn-sm font-mono px-2 py-1" onclick="event.stopPropagation(); openIncidentDrawer(${item.id})">
                                <i class="fas fa-search me-1"></i> Inspect
                            </button>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
            renderThreatTrendChart(data.history);
        } else {
            window.recentAnalysisHistory = [];
            container.innerHTML = `
                <div class="p-4 text-center text-muted">
                    <i class="fas fa-satellite-dish fa-2x mb-2 text-dim"></i>
                    <div class="small font-mono">No threat incidents recorded in stream yet. System idle.</div>
                </div>
            `;
            renderThreatTrendChart([]);
        }
    } catch (e) {
        console.error('Error loading live threat stream:', e);
    }
}

function renderThreatTrendChart(historyData) {
    const canvas = document.getElementById('threatTrendCanvas');
    if (!canvas || typeof Chart === 'undefined') return;

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const isLight = currentTheme === 'light';

    const items = (historyData || []).slice().reverse();
    let labels = [];
    let totalSeries = [];
    let highRiskSeries = [];

    if (items.length === 0) {
        labels = ['T-4', 'T-3', 'T-2', 'T-1', 'Now'];
        totalSeries = [0, 0, 0, 0, 0];
        highRiskSeries = [0, 0, 0, 0, 0];
    } else {
        const count = Math.min(items.length, 10);
        const sliced = items.slice(-count);
        sliced.forEach((item, idx) => {
            let tLabel = item.created_at ? (item.created_at.split(' ')[1] || item.created_at) : `T-${count - idx}`;
            if (tLabel.length > 8) tLabel = tLabel.substring(0, 5);
            labels.push(tLabel);
            const isHigh = item.overall_risk_level === 'HIGH' || item.overall_risk_level === 'CRITICAL' || item.is_bullying === 1;
            totalSeries.push(1);
            highRiskSeries.push(isHigh ? 1 : 0);
        });
    }

    let cumTotal = [];
    let cumHigh = [];
    let runningTotal = 0;
    let runningHigh = 0;
    totalSeries.forEach((v, i) => {
        runningTotal += v;
        runningHigh += highRiskSeries[i];
        cumTotal.push(runningTotal);
        cumHigh.push(runningHigh);
    });

    const trendBadge = document.getElementById('threatTrendStatusBadge');
    if (trendBadge) {
        if (items.length === 0) {
            trendBadge.className = 'soc-pill-safe';
            trendBadge.textContent = 'STABLE POSTURE';
        } else {
            const recentHighCount = items.slice(-5).filter(x => x.overall_risk_level === 'HIGH' || x.overall_risk_level === 'CRITICAL' || x.is_bullying === 1).length;
            if (recentHighCount >= 3) {
                trendBadge.className = 'soc-pill-dominant';
                trendBadge.textContent = 'ELEVATED TREND';
            } else if (recentHighCount > 0) {
                trendBadge.className = 'soc-pill-highest-share';
                trendBadge.textContent = 'MODERATE ACTIVITY';
            } else {
                trendBadge.className = 'soc-pill-safe';
                trendBadge.textContent = 'STABLE POSTURE';
            }
        }
    }

    const gridColor = isLight ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.06)';
    const textColor = isLight ? '#64748b' : '#94a3b8';

    if (threatTrendChart) {
        threatTrendChart.destroy();
    }

    threatTrendChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Ingested',
                    data: cumTotal,
                    borderColor: isLight ? '#4f46e5' : '#818cf8',
                    backgroundColor: isLight ? 'rgba(79, 70, 229, 0.07)' : 'rgba(129, 140, 248, 0.12)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    pointBackgroundColor: isLight ? '#4f46e5' : '#818cf8'
                },
                {
                    label: 'High/Critical Threats',
                    data: cumHigh,
                    borderColor: isLight ? '#dc2626' : '#ef4444',
                    backgroundColor: isLight ? 'rgba(220, 38, 38, 0.07)' : 'rgba(239, 68, 68, 0.12)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                    pointBackgroundColor: isLight ? '#dc2626' : '#ef4444'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: textColor,
                        font: { family: 'JetBrains Mono', size: 10 },
                        boxWidth: 10,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: isLight ? 'rgba(255, 255, 255, 0.96)' : 'rgba(12, 18, 32, 0.96)',
                    titleColor: isLight ? '#0f172a' : '#f8fafc',
                    bodyColor: isLight ? '#334155' : '#cbd5e1',
                    borderColor: isLight ? '#cbd5e1' : 'rgba(255, 255, 255, 0.12)',
                    borderWidth: 1,
                    padding: 8,
                    titleFont: { family: 'JetBrains Mono', size: 11 },
                    bodyFont: { family: 'JetBrains Mono', size: 10 }
                }
            },
            scales: {
                x: {
                    grid: { color: gridColor },
                    ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 9 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: gridColor },
                    ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 9 }, precision: 0 }
                }
            }
        }
    });
}

function renderCharts() {
    const s = window.dashboardStatsData;
    if (!s) return;

    renderThreatIntelligenceCommandCenter(s);
}

function handleCommandCenterRefresh() {
    const btn = document.getElementById('btnRefreshCommandCenter');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Refreshing...';
    }

    loadDashboardStats();

    setTimeout(() => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt me-1"></i> Refresh';
        }
    }, 600);
}

function renderThreatIntelligenceCommandCenter(s) {
    const mainLandscape = document.getElementById('threatCenterLandscapeMain');
    const sideTelemetry = document.getElementById('threatCenterSideTelemetry');
    if (!mainLandscape || !sideTelemetry) return;

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const isLight = currentTheme === 'light';

    const textMainColor = isLight ? '#090d16' : '#f8fafc';
    const textSubColor = isLight ? '#1e293b' : '#cbd5e1';
    const textMuteColor = isLight ? '#52637f' : '#94a3b8';

    const vBullying = s.bullying_detected || 0;
    const vPhishing = s.phishing_detected || 0;
    const vUrls = s.suspicious_urls || 0;
    const vMalware = s.malware_detected || 0;
    const vSocialEng = s.social_eng_detected || 0;
    const totalThreats = vBullying + vPhishing + vUrls + vMalware + vSocialEng;

    const vectorColors = {
        cyberbullying: isLight ? '#dc2626' : '#ef4444',
        urls: isLight ? '#0284c7' : '#38bdf8',
        phishing: isLight ? '#c2410c' : '#f97316',
        social_eng: isLight ? '#d97706' : '#f59e0b',
        malware: isLight ? '#dc2626' : '#ef4444'
    };

    let vectorList = [
        { key: 'cyberbullying', label: 'Cyberbullying', icon: 'fa-user-slash', count: vBullying, color: vectorColors.cyberbullying },
        { key: 'urls', label: 'Risky Links', icon: 'fa-link', count: vUrls, color: vectorColors.urls },
        { key: 'phishing', label: 'Phishing', icon: 'fa-fish', count: vPhishing, color: vectorColors.phishing },
        { key: 'social_eng', label: 'Social Engineering', icon: 'fa-user-shield', count: vSocialEng, color: vectorColors.social_eng },
        { key: 'malware', label: 'Malware Risk', icon: 'fa-bug', count: vMalware, color: vectorColors.malware }
    ];

    // Sort vectors dynamically by incident count descending
    vectorList.sort((a, b) => b.count - a.count);

    let activeCount = 0;
    let clearCount = 0;
    let maxCount = vectorList[0] ? vectorList[0].count : 0;
    let dominantVector = (maxCount > 0) ? vectorList[0] : null;

    vectorList.forEach(v => {
        if (v.count > 0) activeCount++; else clearCount++;
    });

    // Render Left Section: Clean Ranked Multi-Vector Distribution
    let rowsHtml = '';
    vectorList.forEach((v, idx) => {
        const isActive = v.count > 0;
        const isDominant = dominantVector && dominantVector.key === v.key;
        const rankStr = `0${idx + 1}`;
        const pctShare = totalThreats > 0 ? Math.round((v.count / totalThreats) * 100) : 0;
        const trackPct = maxCount > 0 ? Math.max(isActive ? 6 : 0, Math.round((v.count / maxCount) * 100)) : 0;

        const badgeHtml = isDominant ?
            `<span class="soc-pill-dominant">DOMINANT</span>` :
            (isActive ?
                `<span class="soc-pill-active">ACTIVE</span>` :
                `<span class="soc-pill-clear">CLEAR</span>`);

        rowsHtml += `
            <div class="landscape-vector-row ${isDominant ? 'dominant-row' : ''}">
                <div class="vector-rank-col">${rankStr}</div>
                <div class="vector-name-col">
                    <i class="fas ${v.icon}" style="color: ${isActive ? v.color : textMuteColor}; font-size: 0.85rem;"></i>
                    <span>${escapeHtml(v.label)}</span>
                </div>
                <div class="vector-count-col font-mono" style="color: ${isActive ? v.color : textMuteColor};">
                    ${v.count}
                </div>
                <div class="vector-track-col" title="${escapeHtml(v.label)}: ${v.count} Incidents (${pctShare}% share)">
                    <div class="vector-track-bar">
                        <div class="vector-track-fill" style="width: ${trackPct}%; background-color: ${isActive ? v.color : 'transparent'};"></div>
                    </div>
                </div>
                <div class="vector-status-col text-end">
                    ${badgeHtml}
                </div>
            </div>
        `;
    });

    mainLandscape.innerHTML = `
        <div class="landscape-vector-list">
            ${rowsHtml}
        </div>
    `;

    // Render Right Section: Clean Analyst Intelligence Telemetry Panel
    const domLabel = dominantVector ? dominantVector.label : 'None (System Clean)';
    const domCount = dominantVector ? dominantVector.count : 0;
    const domColor = dominantVector ? dominantVector.color : (isLight ? '#15803d' : '#10b981');
    const domPct = (totalThreats > 0 && dominantVector) ? Math.round((domCount / totalThreats) * 100) : 0;

    const dist = s.risk_distribution || {};
    const critCount = dist.CRITICAL || 0;
    const highCount = dist.HIGH || 0;
    const medCount = dist.MEDIUM || 0;
    const lowCount = dist.LOW || 0;

    let summaryText = 'Environment currently exhibits healthy operational parameters with zero active threat vectors detected across analyzed communications.';
    if (totalThreats > 0 && dominantVector) {
        summaryText = `${escapeHtml(domLabel)} constitutes the primary attack surface (${domPct}% share). ${activeCount} of 5 monitored vector surfaces are currently showing activity.`;
    } else if (critCount > 0) {
        summaryText = 'Critical-severity security incidents detected. Immediate review and remediation in forensic drawer recommended.';
    }

    sideTelemetry.innerHTML = `
        <!-- Dominant Threat Hero Callout -->
        <div class="mb-3">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="soc-card-tag mb-0">DOMINANT VECTOR</span>
                <span class="${dominantVector ? 'soc-pill-highest-share' : 'soc-pill-safe'}">${dominantVector ? 'HIGHEST SHARE' : 'CLEAR'}</span>
            </div>
            <h5 class="fw-bold mb-1" style="color: ${domColor}; font-size: 1.05rem;">${escapeHtml(domLabel)}</h5>
            <div class="h4 fw-bold font-mono mb-0" style="color: ${textMainColor};">${domCount} <span class="fs-6 text-muted fw-normal">incidents (${domPct}% share)</span></div>
        </div>

        <div class="telemetry-section-divider"></div>

        <!-- Severity Profile Grid -->
        <div class="mb-3">
            <div class="soc-card-tag mb-2">SEVERITY BREAKDOWN</div>
            <div class="row g-2 small font-mono">
                <div class="col-6 d-flex justify-content-between">
                    <span class="text-danger"><i class="fas fa-circle me-1" style="font-size: 0.45rem;"></i>Critical:</span>
                    <strong class="text-danger">${critCount}</strong>
                </div>
                <div class="col-6 d-flex justify-content-between">
                    <span class="text-warning"><i class="fas fa-circle me-1" style="font-size: 0.45rem;"></i>High:</span>
                    <strong class="text-warning">${highCount}</strong>
                </div>
                <div class="col-6 d-flex justify-content-between">
                    <span class="text-info"><i class="fas fa-circle me-1" style="font-size: 0.45rem;"></i>Medium:</span>
                    <strong class="text-info">${medCount}</strong>
                </div>
                <div class="col-6 d-flex justify-content-between">
                    <span class="text-success"><i class="fas fa-circle me-1" style="font-size: 0.45rem;"></i>Low/Clean:</span>
                    <strong class="text-success">${lowCount}</strong>
                </div>
            </div>
        </div>

        <div class="telemetry-section-divider"></div>

        <!-- Dynamic Analyst Interpretation -->
        <div class="mb-3">
            <div class="soc-card-tag mb-1">ANALYST INTERPRETATION</div>
            <p class="small mb-0" style="font-size: 0.78rem; line-height: 1.45; color: ${textSubColor};">
                "${summaryText}"
            </p>
        </div>

        <div class="telemetry-section-divider"></div>

        <!-- Channel Status -->
        <div>
            <div class="soc-card-tag mb-1">CHANNEL STATUS</div>
            <div class="d-flex justify-content-between align-items-center small font-mono">
                <div>
                    <span class="text-muted">ACTIVE:</span>
                    <span class="fw-bold text-danger ms-1">${activeCount} / 5</span>
                </div>
                <div>
                    <span class="text-muted">CLEAR:</span>
                    <span class="fw-bold text-success ms-1">${clearCount} / 5</span>
                </div>
            </div>
        </div>
    `;
}

// Observe theme mutations on html[data-theme] to dynamically update chart colors
const themeObserver = new MutationObserver(() => {
    renderCharts();
    if (window.recentAnalysisHistory) {
        renderThreatTrendChart(window.recentAnalysisHistory);
    }
});
if (document.documentElement) {
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
}

/* ==========================================================================
   4. Drag-and-Drop Forensic File Intake Dropzones
   ========================================================================== */
function initDropzones() {
    setupDropzone('attachmentDropzone', 'inputAttachments', 'attachmentPreviewList');
    setupDropzone('imageDropzone', 'inputImages', 'imagePreviewList', true);
}

function setupDropzone(zoneId, inputId, listId, isImage = false) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const list = document.getElementById(listId);
    if (!zone || !input) return;

    zone.addEventListener('click', () => input.click());

    ['dragenter', 'dragover'].forEach(name => {
        zone.addEventListener(name, (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(name => {
        zone.addEventListener(name, (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
        });
    });

    zone.addEventListener('drop', (e) => {
        if (e.dataTransfer.files.length > 0) {
            input.files = e.dataTransfer.files;
            renderFileList(input.files, list, isImage);
        }
    });

    input.addEventListener('change', () => {
        renderFileList(input.files, list, isImage);
    });
}

function renderFileList(files, container, isImage = false) {
    if (!container) return;
    container.innerHTML = '';
    if (!files || files.length === 0) return;

    Array.from(files).forEach(file => {
        const item = document.createElement('div');
        item.className = 'file-preview-item';
        const sizeStr = (file.size / 1024).toFixed(1) + ' KB';
        const safeName = escapeHtml(file.name);
        item.innerHTML = `
            <span><i class="fas ${isImage ? 'fa-image text-cyan' : 'fa-paperclip text-accent'} me-2"></i><strong class="text-primary-soc">${safeName}</strong> (${sizeStr})</span>
            <span class="badge-risk SAFE" style="font-size: 0.65rem;">STAGE READY</span>
        `;
        container.appendChild(item);
    });
}

/* ==========================================================================
   5. Threat Analyzer Form & Inspection Pipeline
   ========================================================================== */
function initForms() {
    const analyzeForm = document.getElementById('formAnalyzeEmail');
    if (analyzeForm) {
        analyzeForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnSubmitAnalysis');
            const resultBox = document.getElementById('analysisResultContainer');
            
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-radar fa-spin me-2"></i> EXECUTING MULTI-VECTOR SCAN...';
            
            resultBox.innerHTML = `
                <div class="soc-panel p-5 text-center mt-4">
                    <div class="mb-3">
                        <i class="fas fa-shield-alt fa-3x text-accent" style="animation: criticalPulse 1.5s infinite;"></i>
                    </div>
                    <h5 class="text-primary-soc mb-2">Executing Forensic Pipeline Analysis</h5>
                    <p class="text-muted small mb-0">Decomposing linguistic syntax, phishing heuristics, payload headers, and threat fusion...</p>
                </div>
            `;
            resultBox.style.display = 'block';
            resultBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
            
            try {
                const formData = new FormData(analyzeForm);
                const res = await fetch('/api/analyze-email', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    renderSecurityReport(data.report, resultBox);
                    loadDashboardStats();
                    loadAnalysisHistory();
                    if (window.SOCToast) {
                        const r = data.report.overall_risk_level || 'LOW';
                        if (r === 'CRITICAL' || r === 'HIGH') {
                            SOCToast.error(`Analysis complete: ${r} RISK threat detected.`, 'Threat Alert');
                        } else if (r === 'MEDIUM') {
                            SOCToast.warning(`Analysis complete: MEDIUM RISK threat indicators.`, 'Security Notice');
                        } else {
                            SOCToast.success('Analysis complete: No threat indicators identified.', 'Inspection Complete');
                        }
                    }
                } else {
                    resultBox.innerHTML = `<div class="alert alert-danger mt-4"><i class="fas fa-exclamation-circle me-2"></i>${escapeHtml(data.error)}</div>`;
                }
            } catch (err) {
                resultBox.innerHTML = `<div class="alert alert-danger mt-4"><i class="fas fa-exclamation-circle me-2"></i>Inspection error: ${escapeHtml(err.message)}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-shield-virus me-2"></i> INITIATE THREAT ANALYSIS';
            }
        });
    }

    // Model Training Form
    const trainForm = document.getElementById('formTrainModel');
    if (trainForm) {
        trainForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnTrainModel');
            const resDiv = document.getElementById('trainingResultBox');
            
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Training & Evaluating...';
            resDiv.innerHTML = '<p class="text-muted mt-3">Training classifier and generating confusion matrix metrics...</p>';
            
            try {
                const payload = {
                    model_type: document.getElementById('selectModelType').value,
                    training_samples: parseInt(document.getElementById('selectTrainingSamples').value)
                };
                
                const res = await fetch('/api/train-model', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                
                if (data.success) {
                    renderTrainingMetrics(data.results, resDiv);
                    loadModelStatus();
                    if (window.SOCToast) SOCToast.success(`Model ${escapeHtml(data.results.model_type)} trained successfully.`, 'Model Studio');
                } else {
                    resDiv.innerHTML = `<div class="alert alert-danger mt-3">${escapeHtml(data.error)}</div>`;
                }
            } catch (err) {
                resDiv.innerHTML = `<div class="alert alert-danger mt-3">Training error: ${escapeHtml(err.message)}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-cogs me-2"></i> Train & Evaluate Model';
            }
        });
    }

    // Dataset Generator Form
    const datasetForm = document.getElementById('formGenerateDataset');
    if (datasetForm) {
        datasetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnGenerateDataset');
            const resDiv = document.getElementById('datasetResultBox');
            
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Generating Synthetic Corpus...';
            resDiv.innerHTML = '<p class="text-muted mt-3">Synthesizing multi-sheet academic communication dataset...</p>';
            
            try {
                const samples = parseInt(document.getElementById('selectDatasetSize').value);
                const res = await fetch('/api/generate-dataset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ num_samples: samples })
                });
                const data = await res.json();
                
                if (data.success) {
                    const info = data.dataset_info;
                    resDiv.innerHTML = `
                        <div class="soc-panel p-3 mt-3">
                            <h6 class="text-success mb-2"><i class="fas fa-check-circle me-1"></i> Dataset Generated Successfully!</h6>
                            <p class="mb-1 text-muted small"><strong>File:</strong> ${escapeHtml(info.filename)} (${escapeHtml(info.file_size)})</p>
                            <p class="mb-2 text-muted small"><strong>Total Samples:</strong> ${info.total_samples.toLocaleString()} (Bullying: ${info.bullying_samples}, Non-Bullying: ${info.non_bullying_samples})</p>
                            <a href="/api/download-dataset/${encodeURIComponent(info.filename)}" class="btn-soc-primary btn-sm">
                                <i class="fas fa-download me-1"></i> Download Excel (.xlsx)
                            </a>
                        </div>
                    `;
                    loadAvailableDatasets();
                    if (window.SOCToast) SOCToast.success('Dataset ready for export.', 'Dataset Studio');
                } else {
                    resDiv.innerHTML = `<div class="alert alert-danger mt-3">${escapeHtml(data.error)}</div>`;
                }
            } catch (err) {
                resDiv.innerHTML = `<div class="alert alert-danger mt-3">Generation error: ${escapeHtml(err.message)}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-file-excel me-2"></i> Generate Dataset (.xlsx)';
            }
        });
    }
}

/* ==========================================================================
   6. Comprehensive Threat Assessment Matrix Renderer
   ========================================================================== */
function renderSecurityReport(rep, container) {
    const rawRisk = (rep.overall_risk_level || (rep.is_bullying ? 'HIGH' : 'LOW')).toUpperCase();
    const risk = escapeHtml(rawRisk);
    const rawConf = (rep.overall_confidence !== undefined && rep.overall_confidence !== null)
        ? rep.overall_confidence
        : (rep.confidence || rep.ml_confidence || 0.85);
    const conf = Math.round(rawConf * 100);
    const threatScore = (rep.threat_score !== undefined && rep.threat_score !== null)
        ? rep.threat_score
        : (Math.round(rawConf * 100) / 100);

    const b = rep.bullying_analysis || {
        is_bullying: Boolean(rep.is_bullying),
        confidence: rep.confidence || rep.ml_confidence || 0.0,
        severity: rep.is_bullying ? 'HIGH' : 'LOW'
    };
    const p = rep.phishing_analysis || {
        risk_level: rep.phishing_risk_level || 'LOW',
        confidence: rep.phishing_confidence || 0.0
    };
    const urlSummary = rep.url_analysis_summary || [];
    const u = rep.url_analysis || {
        total_urls: rep.urls_detected || (Array.isArray(urlSummary) ? urlSummary.length : 0),
        suspicious_count: rep.suspicious_urls_count || (Array.isArray(urlSummary) ? urlSummary.filter(x => x && x.is_suspicious).length : 0)
    };
    const s = rep.social_eng_analysis || {
        risk_level: rep.social_eng_risk_level || 'LOW',
        confidence: rep.social_eng_confidence || 0.0
    };
    const m = rep.malware_analysis || {
        risk_level: rep.attachment_risk_level || (rep.malware_detected ? 'HIGH' : 'LOW'),
        total_attachments: rep.attachments_count || 0
    };
    const img = rep.image_analysis || {
        risk_level: (rep.suspicious_images_count > 0) ? 'HIGH' : 'LOW',
        total_images: rep.images_count || 0
    };

    const safeSubject = escapeHtml(rep.email_subject || 'No Subject');
    const safeFrom = escapeHtml(rep.email_from || 'Unknown Sender');
    const safeTo = rep.email_to ? escapeHtml(rep.email_to) : '';
    const caseId = rep.id ? escapeHtml(rep.id) : 'N/A';
    const safeDate = rep.created_at || rep.email_date ? new Date(rep.created_at || rep.email_date).toLocaleString() : 'Recent';

    let badgeClass = 'LOW';
    let scoreColorClass = 'score-color-safe';
    if (rawRisk === 'CRITICAL') {
        badgeClass = 'CRITICAL';
        scoreColorClass = 'score-color-critical';
    } else if (rawRisk === 'HIGH') {
        badgeClass = 'HIGH';
        scoreColorClass = 'score-color-high';
    } else if (rawRisk === 'MEDIUM') {
        badgeClass = 'MEDIUM';
        scoreColorClass = 'score-color-medium';
    }

    let html = `
        <div class="soc-drawer-investigation animate-fade-in">
            <!-- INCIDENT IDENTITY VERDICT HEADER -->
            <div class="soc-drawer-verdict-card mb-4 p-3 rounded">
                <div class="d-flex justify-content-between align-items-center">
                    <div style="flex: 1; min-width: 0; padding-right: 20px;">
                        <div class="mb-2">
                            <span class="badge-risk ${badgeClass}">${risk} RISK VERDICT</span>
                        </div>
                        <h4 class="mb-1 text-primary-soc text-truncate" style="font-size: 1.15rem; font-weight: 600; line-height: 1.3;" title="${safeSubject}">${safeSubject}</h4>
                        <div class="text-muted small text-truncate" title="${safeFrom}">
                            From: <strong class="text-secondary-soc">${safeFrom}</strong>
                            ${safeTo ? ` &bull; To: <strong class="text-secondary-soc">${safeTo}</strong>` : ''}
                        </div>
                    </div>

                    <!-- PROMINENT METRIC DISPLAY -->
                    <div class="d-flex align-items-center gap-4 text-end">
                        <div class="verdict-metric-box">
                            <div class="verdict-metric-label">CONFIDENCE</div>
                            <div class="verdict-metric-value text-primary-soc font-mono">${conf}%</div>
                        </div>
                        <div class="verdict-metric-box">
                            <div class="verdict-metric-label">THREAT SCORE</div>
                            <div class="verdict-metric-value font-mono ${scoreColorClass}">${threatScore}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SECTION 1 — INCIDENT SUMMARY -->
            <div class="mb-4">
                <h6 class="drawer-section-heading mb-2">
                    <i class="fas fa-info-circle me-1 text-accent"></i> Incident Summary
                </h6>
                <div class="incident-summary-grid">
                    <div class="summary-item">
                        <span class="summary-label">Severity</span>
                        <span class="summary-value font-weight-bold text-primary-soc">${risk}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Confidence</span>
                        <span class="summary-value font-mono">${conf}%</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Source</span>
                        <span class="summary-value text-truncate" title="${safeFrom}">${safeFrom}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Received</span>
                        <span class="summary-value font-mono small">${safeDate}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Status</span>
                        <span class="summary-value"><span class="badge bg-success-subtle text-success border border-success-subtle px-2 py-1" style="font-size: 0.7rem;">Analyzed</span></span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Case ID</span>
                        <span class="summary-value font-mono">#BM-${caseId}</span>
                    </div>
                </div>
            </div>

            <!-- SECTION 2 — DETECTION RESULTS MATRIX -->
            <div class="mb-4">
                <h6 class="drawer-section-heading mb-2">
                    <i class="fas fa-microscope me-1 text-accent"></i> Detection Results
                </h6>
                <div class="table-responsive">
                    <table class="soc-detection-table">
                        <thead>
                            <tr>
                                <th>Detection Vector</th>
                                <th>Result</th>
                                <th class="text-end">Confidence / Detail</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Cyberbullying -->
                            <tr>
                                <td><i class="fas fa-comment-slash me-2 text-muted"></i>Cyberbullying</td>
                                <td>${b.is_bullying ? `<span class="status-indicator status-detected">DETECTED</span>` : `<span class="status-indicator status-clean">Not detected</span>`}</td>
                                <td class="text-end font-mono">${Math.round((b.confidence || 0) * 100)}%</td>
                            </tr>
                            <!-- Phishing -->
                            <tr>
                                <td><i class="fas fa-fish me-2 text-muted"></i>Phishing Risk</td>
                                <td>${p.risk_level && p.risk_level !== 'LOW' && p.risk_level !== 'SAFE' ? `<span class="status-indicator ${p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH' ? 'status-detected' : 'status-medium'}">${escapeHtml(p.risk_level)}</span>` : `<span class="status-indicator status-clean">Not detected</span>`}</td>
                                <td class="text-end font-mono">${Math.round((p.confidence || 0) * 100)}%</td>
                            </tr>
                            <!-- Link Safety -->
                            <tr>
                                <td><i class="fas fa-link me-2 text-muted"></i>Link Safety</td>
                                <td>${u.suspicious_count > 0 ? `<span class="status-indicator status-medium">${u.suspicious_count} Risky</span>` : `<span class="status-indicator status-clean">Safe</span>`}</td>
                                <td class="text-end font-mono">${u.total_urls || 0} scanned</td>
                            </tr>
                            <!-- Social Engineering -->
                            <tr>
                                <td><i class="fas fa-user-secret me-2 text-muted"></i>Social Engineering</td>
                                <td>${s.risk_level && s.risk_level !== 'LOW' && s.risk_level !== 'SAFE' ? `<span class="status-indicator ${s.risk_level === 'CRITICAL' || s.risk_level === 'HIGH' ? 'status-detected' : 'status-medium'}">${escapeHtml(s.risk_level)}</span>` : `<span class="status-indicator status-clean">Not detected</span>`}</td>
                                <td class="text-end font-mono">${Math.round((s.confidence || 0) * 100)}%</td>
                            </tr>
                            <!-- Static File Analysis -->
                            <tr>
                                <td><i class="fas fa-file-code me-2 text-muted"></i>Static File Analysis</td>
                                <td>${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? `<span class="status-indicator status-detected">${escapeHtml(m.risk_level)}</span>` : `<span class="status-indicator status-clean">Clean</span>`}</td>
                                <td class="text-end font-mono">${m.total_attachments || 0} file(s)</td>
                            </tr>
                            <!-- Image Forensics -->
                            <tr>
                                <td><i class="fas fa-image me-2 text-muted"></i>Image Forensics</td>
                                <td>${img.risk_level && img.risk_level !== 'LOW' && img.risk_level !== 'SAFE' ? `<span class="status-indicator status-medium">${escapeHtml(img.risk_level)}</span>` : `<span class="status-indicator status-clean">Clean</span>`}</td>
                                <td class="text-end font-mono">${img.total_images || 0} image(s)</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- SECTION 3 — ANALYST FINDINGS -->
            <div class="mb-4">
                <h6 class="drawer-section-heading mb-2">
                    <i class="fas fa-fingerprint me-1 text-accent"></i> Analyst Findings
                </h6>
                <div class="analyst-findings-list">
    `;

    const evidenceItems = [];
    if (Array.isArray(rep.evidence) && rep.evidence.length > 0) {
        evidenceItems.push(...rep.evidence);
    } else if (Array.isArray(rep.evidence_summary) && rep.evidence_summary.length > 0) {
        evidenceItems.push(...rep.evidence_summary);
    } else if (Array.isArray(rep.top_risk_factors) && rep.top_risk_factors.length > 0) {
        rep.top_risk_factors.forEach(factor => {
            evidenceItems.push({
                severity: rep.overall_risk_level || 'MEDIUM',
                category: 'Threat Indicator',
                title: typeof factor === 'string' ? factor : (factor.factor || 'Risk Factor Identified'),
                details: typeof factor === 'string' ? factor : (factor.description || factor.factor || '')
            });
        });
    }

    if (evidenceItems.length === 0) {
        if (b.is_bullying) {
            evidenceItems.push({
                severity: b.severity || 'HIGH',
                category: 'Cyberbullying Analysis',
                title: 'Toxic / Bullying Content Flagged',
                details: `NLP & Hybrid Classifier identified targeted harassment keywords with ${Math.round((b.confidence || 0) * 100)}% confidence.`
            });
        }
        if (p.risk_level && p.risk_level !== 'LOW' && p.risk_level !== 'SAFE') {
            evidenceItems.push({
                severity: p.risk_level,
                category: 'Phishing Heuristics',
                title: 'Phishing Indicators Identified',
                details: `Spoofed headers or credential harvesting patterns detected with ${Math.round((p.confidence || 0) * 100)}% confidence.`
            });
        }
        if (u.suspicious_count > 0) {
            evidenceItems.push({
                severity: 'HIGH',
                category: 'URL & Link Audit',
                title: `${u.suspicious_count} Risky / Suspicious Link(s) Detected`,
                details: `Found ${u.suspicious_count} destination URL(s) matching known phishing, IP-host, or domain typosquatting patterns.`
            });
        }
        if (s.risk_level && s.risk_level !== 'LOW' && s.risk_level !== 'SAFE') {
            evidenceItems.push({
                severity: s.risk_level,
                category: 'Social Engineering',
                title: 'Psychological Coercion Detected',
                details: `Urgency, authority impersonation, or disciplinary threats detected with ${Math.round((s.confidence || 0) * 100)}% confidence.`
            });
        }
        if (m.risk_level && m.risk_level !== 'LOW' && m.risk_level !== 'SAFE') {
            evidenceItems.push({
                severity: m.risk_level,
                category: 'Static Attachment Analysis',
                title: 'Suspicious Attachment Flagged',
                details: `Attachment payload analysis identified elevated risk heuristics or executable extension markers.`
            });
        }
    }

    if (evidenceItems.length > 0) {
        evidenceItems.forEach(ev => {
            const rawSev = (typeof ev === 'string' ? 'MEDIUM' : ev.severity) || 'MEDIUM';
            const safeSev = escapeHtml(rawSev);
            const safeCat = escapeHtml((typeof ev === 'string' ? 'Evidence Item' : ev.category) || 'Threat Indicator');
            const safeTitle = escapeHtml(typeof ev === 'string' ? ev : (ev.title || 'Risk Finding'));
            const safeDetails = escapeHtml(typeof ev === 'string' ? '' : (ev.details || ''));
            html += `
                <div class="finding-row ${safeSev}">
                    <div class="d-flex align-items-center justify-content-between mb-1">
                        <span class="finding-title font-weight-bold text-primary-soc">${safeTitle}</span>
                        <span class="badge-risk ${safeSev}">${safeSev}</span>
                    </div>
                    ${safeDetails ? `<div class="finding-details text-muted small mb-1">${safeDetails}</div>` : ''}
                    <div class="finding-meta font-mono text-muted text-xs">${safeCat}</div>
                </div>
            `;
        });
    } else {
        html += `
            <div class="p-3 text-center rounded border border-subtle bg-inset">
                <div class="text-success mb-1"><i class="fas fa-check-circle me-1"></i>No Malicious Indicators Identified</div>
                <div class="text-muted small">The email content, sender headers, links, and attachments cleared all forensic security heuristics.</div>
            </div>
        `;
    }

    html += `
                </div>
            </div>

            <!-- SECTION 4 — FORENSIC PIPELINE DETAILS -->
            <div class="mb-4">
                <h6 class="drawer-section-heading mb-2">
                    <i class="fas fa-cogs me-1 text-accent"></i> Forensic Pipeline Details
                </h6>
                <div class="forensic-pipeline-rows">
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-comment-slash me-2 text-muted"></i>NLP / Bullying</span>
                        <span class="p-status font-mono ${b.is_bullying ? 'text-danger' : 'text-success'}">${b.is_bullying ? 'FLAGGED' : 'CLEAN'}</span>
                        <span class="p-conf font-mono text-end">${Math.round((b.confidence || 0) * 100)}% conf</span>
                    </div>
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-fish me-2 text-muted"></i>Phishing Heuristics</span>
                        <span class="p-status font-mono ${p.risk_level && p.risk_level !== 'LOW' && p.risk_level !== 'SAFE' ? 'text-warning' : 'text-success'}">${escapeHtml(p.risk_level || 'LOW')}</span>
                        <span class="p-conf font-mono text-end">${Math.round((p.confidence || 0) * 100)}% conf</span>
                    </div>
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-link me-2 text-muted"></i>URL Inspection</span>
                        <span class="p-status font-mono ${u.suspicious_count > 0 ? 'text-warning' : 'text-success'}">${u.suspicious_count > 0 ? `${u.suspicious_count} RISKY` : 'SAFE'}</span>
                        <span class="p-conf font-mono text-end">${u.total_urls} URLs</span>
                    </div>
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-user-secret me-2 text-muted"></i>Social Engineering</span>
                        <span class="p-status font-mono ${s.risk_level && s.risk_level !== 'LOW' && s.risk_level !== 'SAFE' ? 'text-warning' : 'text-success'}">${escapeHtml(s.risk_level || 'LOW')}</span>
                        <span class="p-conf font-mono text-end">${Math.round((s.confidence || 0) * 100)}% conf</span>
                    </div>
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-file-code me-2 text-muted"></i>Static File Analysis</span>
                        <span class="p-status font-mono ${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? 'text-danger' : 'text-success'}">${escapeHtml(m.risk_level || 'CLEAN')}</span>
                        <span class="p-conf font-mono text-end">${m.total_attachments || 0} Files</span>
                    </div>
                    <div class="pipeline-row">
                        <span class="p-name"><i class="fas fa-image me-2 text-muted"></i>Image Forensics</span>
                        <span class="p-status font-mono ${img.risk_level && img.risk_level !== 'LOW' && img.risk_level !== 'SAFE' ? 'text-warning' : 'text-success'}">${escapeHtml(img.risk_level || 'CLEAN')}</span>
                        <span class="p-conf font-mono text-end">${img.total_images || 0} Images</span>
                    </div>
                    <div class="pipeline-row border-0">
                        <span class="p-name"><i class="fas fa-layer-group me-2 text-accent"></i>Risk Fusion Engine</span>
                        <span class="p-status font-mono font-weight-bold text-primary-soc">${risk} VERDICT</span>
                        <span class="p-conf font-mono text-end">${conf}% conf</span>
                    </div>
                </div>
            </div>

            <!-- SECTION 5 — RECOMMENDED ACTION -->
            <div class="recommended-action-box p-3 rounded">
                <div class="d-flex align-items-center justify-content-between">
                    <div>
                        <div class="font-weight-bold text-primary-soc mb-1" style="font-size: 0.85rem;">
                            <i class="fas fa-shield-virus me-2 text-accent"></i>Recommended Action
                        </div>
                        <div class="text-muted small">
                            ${b.is_bullying ? 'Review this message for targeted harassment and policy enforcement.' :
                              (p.risk_level && p.risk_level !== 'LOW' && p.risk_level !== 'SAFE' ? 'Verify sender authenticity and inspect email headers for domain spoofing.' :
                              (u.suspicious_count > 0 ? 'Quarantine message and block suspicious destination URLs at network gateway.' :
                              'No immediate remediation required. Standard security monitoring active.'))}
                        </div>
                    </div>
                    ${rep.id ? `
                    <div class="ms-3">
                        <a href="/api/reports/view/${encodeURIComponent(rep.id)}" target="_blank" class="btn-soc-outline btn-sm">
                            <i class="fas fa-file-pdf me-1"></i> Audit PDF
                        </a>
                    </div>` : ''}
                </div>
            </div>
        </div>
    `;
    container.innerHTML = html;
}

/* ==========================================================================
   7. Model Training & Evaluation Metrics UI
   ========================================================================== */
function renderTrainingMetrics(metrics, container) {
    const cm = metrics.confusion_matrix || [[0,0],[0,0]];
    container.innerHTML = `
        <div class="soc-panel p-4 mt-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h6 class="mb-0 text-success"><i class="fas fa-check-circle me-2"></i>Classifier Evaluated Successfully</h6>
                <span class="badge bg-primary">${escapeHtml(metrics.model_type)}</span>
            </div>
            
            <div class="row text-center g-3 mb-4">
                <div class="col-3">
                    <div class="p-2 border border-secondary rounded">
                        <small class="text-muted">Accuracy</small>
                        <h4 class="mb-0 text-primary-soc font-mono">${Math.round(metrics.accuracy * 100)}%</h4>
                    </div>
                </div>
                <div class="col-3">
                    <div class="p-2 border border-secondary rounded">
                        <small class="text-muted">Precision</small>
                        <h4 class="mb-0 text-primary-soc font-mono">${metrics.precision}</h4>
                    </div>
                </div>
                <div class="col-3">
                    <div class="p-2 border border-secondary rounded">
                        <small class="text-muted">Recall</small>
                        <h4 class="mb-0 text-primary-soc font-mono">${metrics.recall}</h4>
                    </div>
                </div>
                <div class="col-3">
                    <div class="p-2 border border-secondary rounded">
                        <small class="text-muted">F1-Score</small>
                        <h4 class="mb-0 text-primary-soc font-mono">${metrics.f1_score}</h4>
                    </div>
                </div>
            </div>

            <h6 class="text-primary-soc mb-2">Confusion Matrix (Test Split: ${metrics.test_samples} samples)</h6>
            <div class="confusion-matrix-grid mb-3">
                <div></div>
                <div class="text-muted small">Pred: Clean</div>
                <div class="text-muted small">Pred: Bullying</div>
                
                <div class="text-muted small text-end pe-2">Actual: Clean</div>
                <div class="cm-cell cm-tn">${cm[0][0]} (TN)</div>
                <div class="cm-cell cm-fp">${cm[0][1]} (FP)</div>
                
                <div class="text-muted small text-end pe-2">Actual: Bullying</div>
                <div class="cm-cell cm-fn">${cm[1][0]} (FN)</div>
                <div class="cm-cell cm-tp">${cm[1][1]} (TP)</div>
            </div>

            <div class="alert alert-info small mb-0">
                <i class="fas fa-shield-alt me-1"></i> ${escapeHtml(metrics.evaluation_notice || 'Standard evaluation metrics.')}
            </div>
        </div>
    `;
}

/* ==========================================================================
   8. Model Status & Available Datasets
   ========================================================================== */
async function loadModelStatus() {
    try {
        const res = await fetch('/api/model-status');
        const data = await res.json();
        const statusEl = document.getElementById('currentModelStatus');
        if (!statusEl) return;
        
        if (data.success && data.model_loaded) {
            statusEl.innerHTML = `
                <div class="d-flex align-items-center gap-3">
                    <div class="metric-icon-wrap" style="background: var(--threat-safe-bg); color: var(--threat-safe); width: 34px; height: 34px; border-radius: 6px; display: flex; align-items: center; justify-content: center;"><i class="fas fa-check"></i></div>
                    <div>
                        <strong class="text-primary-soc">${escapeHtml(data.model_type)}</strong>
                        <div class="text-muted small font-mono">Active Production Classifier &bull; Saved Artifacts: ${parseInt(data.saved_models.length)}</div>
                    </div>
                </div>
            `;
        } else {
            statusEl.innerHTML = `<span class="text-warning"><i class="fas fa-circle me-1"></i> No model artifact loaded</span>`;
        }
    } catch (e) {}
}

async function loadAvailableDatasets() {
    try {
        const res = await fetch('/api/available-datasets');
        const data = await res.json();
        const container = document.getElementById('availableDatasetsContainer');
        if (!container) return;
        
        if (data.success && data.datasets.length > 0) {
            let html = '<div class="list-group list-group-flush">';
            data.datasets.forEach(d => {
                const safeName = escapeHtml(d.filename);
                const safeSize = escapeHtml(d.file_size);
                const safeTime = escapeHtml(d.created_at);
                html += `
                    <div class="list-group-item bg-transparent text-secondary-soc d-flex justify-content-between align-items-center border-secondary px-0">
                        <div>
                            <strong class="text-primary-soc">${safeName}</strong>
                            <div class="text-muted small font-mono">${safeSize} • Created ${safeTime}</div>
                        </div>
                        <a href="/api/download-dataset/${encodeURIComponent(d.filename)}" class="btn-soc-secondary btn-sm">
                            <i class="fas fa-download me-1"></i> Excel
                        </a>
                    </div>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        } else {
            container.innerHTML = '<p class="text-muted small">No generated datasets found. Create one using the generator panel.</p>';
        }
    } catch (e) {}
}

/* ==========================================================================
   9. Threat Incident Archive (Analysis History Table)
   ========================================================================== */
async function loadAnalysisHistory(filterRisk = '') {
    try {
        const url = filterRisk ? `/api/analysis-history?risk=${encodeURIComponent(filterRisk)}` : '/api/analysis-history';
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById('historyTableBody');
        if (!tbody) return;
        
        if (data.success && data.history.length > 0) {
            tbody.innerHTML = '';
            data.history.forEach(item => {
                const tr = document.createElement('tr');
                const risk = escapeHtml(item.overall_risk_level || 'LOW');
                const safeSubject = escapeHtml(item.email_subject || 'No Subject');
                const safeFrom = escapeHtml(item.email_from || 'Unknown');
                const safeTime = escapeHtml(item.created_at || 'Just now');
                
                const confVal = Math.round((item.overall_confidence || item.confidence || item.ml_confidence || 0.85) * 100);
                tr.innerHTML = `
                    <td class="font-mono text-muted small">${safeTime}</td>
                    <td><strong class="text-primary-soc">${safeSubject}</strong></td>
                    <td class="text-muted small font-mono">${safeFrom}</td>
                    <td><span class="badge-risk ${risk}">${risk}</span></td>
                    <td class="font-mono text-primary-soc">${confVal}%</td>
                    <td>
                        <a href="/api/reports/view/${encodeURIComponent(item.id)}" target="_blank" class="btn-soc-secondary btn-sm me-1" title="Print/View PDF Report">
                            <i class="fas fa-print"></i>
                        </a>
                        <button class="btn-soc-primary btn-sm" onclick="openIncidentDrawer(${item.id})" title="Inspect Incident in Drawer">
                            <i class="fas fa-search-plus me-1"></i> Inspect
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No email security analyses logged yet.</td></tr>';
        }
    } catch (e) {}
}

/* ==========================================================================
   10. Quick Preset Sample Selector
   ========================================================================== */
function loadSampleEmail(type) {
    const samples = {
        clean: {
            subject: "CS301 Lecture Slides & Office Hours Schedule",
            from: "professor.johnson@harvard.edu",
            body: "Dear Students, the lecture slides for Chapter 4 on Graph Algorithms have been posted on the student portal. Please let me know if you have questions during office hours on Thursday at 2 PM."
        },
        single_insult: {
            subject: "Your Unacceptable Performance",
            from: "advisor@university.edu",
            body: "idiot"
        },
        bullying: {
            subject: "Your Disappointing Contribution",
            from: "advisor@university.edu",
            body: "Your recent thesis draft is a complete failure and proves you cannot do anything right. You are a useless student and you should quit the academic program before embarrassing us further. Nobody wants you in this lab."
        },
        violence: {
            subject: "Final Warning",
            from: "threat@anonymous.com",
            body: "You are completely useless. If you don't stop reporting this issue, I will hurt you and ensure you regret ever stepping into this department."
        },
        phishing: {
            subject: "URGENT: Verify Your University Portal Account",
            from: "University IT Helpdesk <admin-support@gmail.com>",
            body: "Unusual sign-in activity was detected on your account. You must verify your password immediately at http://paypa1-security.com/login within 24 hours or your student portal access will be permanently locked."
        },
        url: {
            subject: "Research Materials & Shared Resources",
            from: "colleague@university.edu",
            body: "Please review the updated research documentation and datasets at http://192.168.1.50/auth/download before tomorrow's meeting."
        },
        social: {
            subject: "Confidential Notice from Dean's Office",
            from: "Dean Office <dean.admin@univ-alerts.com>",
            body: "Immediate mandatory action required: You will face disciplinary expulsion and law enforcement escalation unless you submit your response without delay."
        }
    };

    const s = samples[type];
    if (s) {
        document.getElementById('inputEmailSubject').value = s.subject;
        document.getElementById('inputEmailFrom').value = s.from;
        document.getElementById('inputEmailText').value = s.body;
        
        const counter = document.getElementById('charCountDisplay');
        if (counter) {
            const words = s.body.trim().split(/\s+/).length;
            counter.textContent = `${s.body.length} chars • ${words} words`;
        }

        if (window.SOCToast) SOCToast.info(`Loaded ${type.replace('_', ' ').toUpperCase()} preset case.`, 'Preset Ingested');
    }
}

/* ==========================================================================
   11. SOC Secure Mailbox Operations Center JS Engine
   ========================================================================== */
let cachedMailboxes = [];

async function fetchWithTimeout(resource, options = {}, timeoutMs = 25000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(resource, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        if (error.name === 'AbortError') {
            throw new Error(`Request timed out after ${Math.round(timeoutMs/1000)} seconds.`);
        }
        throw error;
    }
}

async function loadInstitutions() {
    try {
        const res = await fetchWithTimeout('/api/institutions', {}, 10000);
        const data = await res.json();
        if (data.success && data.institutions) {
            window.cachedInstitutions = data.institutions;
            renderInstitutionSelect(data.institutions);
        }
    } catch (err) {
        console.error("Error loading institutions:", err);
    }
}

function renderInstitutionSelect(institutions) {
    const sel = document.getElementById('socInstitutionSelect');
    if (!sel) return;

    if (!institutions || institutions.length === 0) {
        sel.innerHTML = `<option value="1">BullyMail Demo Institution</option>`;
        return;
    }

    let html = '';
    institutions.forEach(inst => {
        const selected = (inst.id === window.activeInstitutionId) ? 'selected' : '';
        html += `<option value="${inst.id}" ${selected}>${escapeHtml(inst.name)} (${escapeHtml(inst.code || 'INST')})</option>`;
    });
    sel.innerHTML = html;

    if (!institutions.some(i => i.id === window.activeInstitutionId)) {
        window.activeInstitutionId = institutions[0].id;
    }
    updateInstitutionBanner(window.activeInstitutionId);
}

window.AUTO_SYNC_INTERVAL = 60; // 60 seconds polling interval
window.mailboxAutoSyncTimer = null;
window.mailboxCountdownSeconds = 60;
window.isAutoSyncing = false; // Atomic lock guard against overlapping sync jobs

function initMailboxAutoSync() {
    if (window.mailboxAutoSyncTimer) return; // Prevent duplicate timers

    window.mailboxCountdownSeconds = window.AUTO_SYNC_INTERVAL;
    updateAutoSyncUI('idle', window.mailboxCountdownSeconds);

    window.mailboxAutoSyncTimer = setInterval(() => {
        if (window.isAutoSyncing) return;

        window.mailboxCountdownSeconds--;
        if (window.mailboxCountdownSeconds <= 0) {
            window.mailboxCountdownSeconds = window.AUTO_SYNC_INTERVAL;
            performBackgroundAutoSync();
        } else {
            updateAutoSyncUI('countdown', window.mailboxCountdownSeconds);
        }
    }, 1000);
}

function stopMailboxAutoSync() {
    if (window.mailboxAutoSyncTimer) {
        clearInterval(window.mailboxAutoSyncTimer);
        window.mailboxAutoSyncTimer = null;
    }
}

function updateAutoSyncUI(state, extra) {
    const statusEl = document.getElementById('socAutoSyncStatus');
    const textEl = document.getElementById('socAutoSyncText');
    const timerEl = document.getElementById('socAutoSyncTimer');

    if (!statusEl || !textEl) return;
    const dotEl = statusEl.querySelector('.soc-ping-dot');

    if (state === 'syncing') {
        textEl.textContent = 'SYNCING...';
        if (timerEl) timerEl.textContent = '';
        if (dotEl) dotEl.className = 'soc-ping-dot bg-warning rounded-circle';
    } else if (state === 'live') {
        const timeStr = extra || new Date().toLocaleTimeString('en-US', { hour12: false });
        textEl.textContent = 'LIVE';
        if (timerEl) timerEl.textContent = `(Synced ${timeStr})`;
        if (dotEl) dotEl.className = 'soc-ping-dot bg-success rounded-circle';
    } else if (state === 'error') {
        textEl.textContent = 'SYNC ERROR';
        if (timerEl) timerEl.textContent = extra ? `(${extra})` : '';
        if (dotEl) dotEl.className = 'soc-ping-dot bg-danger rounded-circle';
    } else {
        textEl.textContent = 'AUTO-SYNC ON';
        if (timerEl) timerEl.textContent = extra ? `(${extra}s)` : '';
        if (dotEl) dotEl.className = 'soc-ping-dot bg-success rounded-circle';
    }
}

async function performBackgroundAutoSync() {
    if (window.isAutoSyncing) {
        console.log("Auto-sync skipped: previous sync operation still running.");
        return;
    }

    window.isAutoSyncing = true;
    updateAutoSyncUI('syncing');

    const instId = window.activeInstitutionId || 1;
    try {
        const res = await fetchWithTimeout(`/api/institutions/${instId}/sync-all`, { method: 'POST' }, 45000);
        const data = await res.json();

        if (data.success) {
            const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
            updateAutoSyncUI('live', timeStr);
        } else {
            updateAutoSyncUI('error', data.error || 'Failed');
        }
    } catch (err) {
        console.error("Background auto-sync error:", err);
        updateAutoSyncUI('error', 'Connection Warning');
    } finally {
        window.isAutoSyncing = false;
        window.mailboxCountdownSeconds = window.AUTO_SYNC_INTERVAL;

        // Perform partial non-disruptive refresh of UI metrics
        await loadSecureMailboxes(true);
        if (window.currentMailboxId) {
            loadMailboxInbox(window.currentMailboxId);
        }
    }
}

async function handleSyncAllMailboxes() {
    const btn = document.getElementById('btnSyncAllMailboxes');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Syncing All...';
    }

    try {
        await performBackgroundAutoSync();
        if (window.SOCToast) SOCToast.success('All active mailboxes synchronized.', 'Sync Complete');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync-alt me-1"></i> Sync All';
        }
    }
}

function handleInstitutionChange(newId) {
    const instId = parseInt(newId, 10);
    if (!instId) return;
    window.activeInstitutionId = instId;
    stopMailboxAutoSync();
    updateInstitutionBanner(instId);
    loadSecureMailboxes();
    loadInstitutionEmails(instId);
}

async function loadSecureMailboxes(skipAutoSyncStart = false) {
    const listContainer = document.getElementById('connectedMailboxesList');
    if (!listContainer) return;

    const instId = window.activeInstitutionId || 1;
    try {
        const res = await fetchWithTimeout(`/api/institutions/${instId}/mailboxes`, {}, 15000);
        const data = await res.json();

        if (!data.success) {
            listContainer.innerHTML = `<div class="alert alert-danger font-mono small p-3">${escapeHtml(data.error || 'Failed to load mailboxes')}</div>`;
            return;
        }

        cachedMailboxes = data.mailboxes || [];
        renderSecureMailboxesSummary(cachedMailboxes);
        renderSecureMailboxesList(cachedMailboxes, listContainer);
        loadInstitutionStats(instId);

        if (!skipAutoSyncStart) {
            initMailboxAutoSync();
        }
    } catch (err) {
        listContainer.innerHTML = `<div class="alert alert-danger font-mono small p-3">Error connecting to mailbox API: ${escapeHtml(err.message)}</div>`;
    }
}

async function loadInstitutionStats(instId) {
    const targetId = instId || window.activeInstitutionId || 1;
    try {
        const res = await fetchWithTimeout(`/api/institutions/${targetId}/stats`, {}, 10000);
        const data = await res.json();
        if (data.success && data.stats) {
            const s = data.stats;
            const mbCountEl = document.getElementById('mb-stat-total');
            const activeCountEl = document.getElementById('mb-stat-active');
            const ingCountEl = document.getElementById('mb-stat-ingested');
            const trCountEl = document.getElementById('instBannerThreats');
            const syncTimeEl = document.getElementById('instBannerLastSync');
            const syncDateEl = document.getElementById('instBannerLastSyncDate');

            if (mbCountEl && s.total_mailboxes !== undefined) mbCountEl.textContent = s.total_mailboxes;
            if (activeCountEl && s.active_mailboxes !== undefined) activeCountEl.textContent = s.active_mailboxes;
            if (ingCountEl && s.total_emails !== undefined) ingCountEl.textContent = s.total_emails;
            if (trCountEl && s.total_threats !== undefined) trCountEl.textContent = s.total_threats;

            if (s.last_sync) {
                const syncDt = new Date(s.last_sync);
                if (syncTimeEl) syncTimeEl.textContent = syncDt.toLocaleTimeString('en-US', { hour12: false });
                if (syncDateEl) syncDateEl.textContent = syncDt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
            } else {
                if (syncTimeEl) syncTimeEl.textContent = 'Never';
                if (syncDateEl) syncDateEl.textContent = 'No sync record';
            }
        }
    } catch (err) {
        console.error("Error loading institution stats:", err);
    }
}

async function loadInstitutionEmails(instId) {
    const tbody = document.getElementById('instMailTableBody');
    if (!tbody) return;

    const targetId = instId || window.activeInstitutionId || 1;
    try {
        const res = await fetchWithTimeout(`/api/institutions/${targetId}/emails?limit=50`, {}, 15000);
        const data = await res.json();

        if (!data.success || !data.emails || data.emails.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4"><i class="fas fa-inbox me-2"></i>No ingested emails for this institution workspace.</td></tr>`;
            return;
        }

        let html = '';
        data.emails.forEach(item => {
            const dateStr = item.created_at ? new Date(item.created_at).toLocaleString() : 'N/A';
            const risk = item.overall_risk_level || 'LOW';
            let riskBadge = '<span class="badge bg-success">LOW</span>';
            if (risk === 'CRITICAL') riskBadge = '<span class="badge bg-danger">CRITICAL</span>';
            else if (risk === 'HIGH') riskBadge = '<span class="badge bg-warning text-dark">HIGH</span>';
            else if (risk === 'MEDIUM') riskBadge = '<span class="badge bg-info text-dark">MEDIUM</span>';

            let vector = 'Clean';
            if (item.is_bullying) vector = 'Cyberbullying';
            else if (item.phishing_risk_level && item.phishing_risk_level !== 'LOW') vector = 'Phishing';
            else if (item.suspicious_urls_count > 0) vector = 'Malicious Links';
            else if (item.social_eng_risk_level && item.social_eng_risk_level !== 'LOW') vector = 'Social Eng.';
            else if (item.malware_detected) vector = 'Malware';

            html += `
                <tr>
                    <td class="font-mono small">${escapeHtml(dateStr)}</td>
                    <td class="font-mono small text-accent">${escapeHtml(item.email_from || 'Unknown')}</td>
                    <td class="font-mono small">${escapeHtml(item.email_to || 'N/A')}</td>
                    <td class="fw-semibold text-primary-soc">${escapeHtml(item.email_subject || 'No Subject')}</td>
                    <td>${riskBadge}</td>
                    <td class="font-mono small text-muted">${escapeHtml(vector)}</td>
                    <td><span class="badge bg-dark border border-secondary text-accent">Analyzed</span></td>
                    <td class="font-mono small text-accent">#BM-${item.id}</td>
                    <td>
                        <button type="button" class="btn-soc-secondary btn-sm px-2 py-1" onclick="openIncidentDrawer(${item.id})">
                            <i class="fas fa-search me-1"></i> Inspect
                        </button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">Error loading institution mail: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function openAddMailboxModal() {
    const instId = window.activeInstitutionId || 1;
    const inst = (window.cachedInstitutions || []).find(i => i.id === instId);

    const nameEl = document.getElementById('inputMailboxInstitutionName');
    const idEl = document.getElementById('inputMailboxInstitutionId');

    if (nameEl) nameEl.value = inst ? `${inst.name} (${inst.code || 'INST'})` : 'BullyMail Demo Institution';
    if (idEl) idEl.value = instId;

    const modalEl = document.getElementById('addMailboxModal');
    if (modalEl && typeof bootstrap !== 'undefined') {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

function renderSecureMailboxesSummary(mailboxes) {
    const totalEl = document.getElementById('mb-stat-total');
    const activeEl = document.getElementById('mb-stat-active');
    const ingestedEl = document.getElementById('mb-stat-ingested');

    if (!mailboxes) return;

    const total = mailboxes.length;
    const active = mailboxes.filter(m => m.status === 'active').length;
    const totalIngested = mailboxes.reduce((acc, m) => acc + (m.total_ingested_count || 0), 0);

    if (totalEl) totalEl.textContent = total;
    if (activeEl) activeEl.textContent = active;
    if (ingestedEl) ingestedEl.textContent = totalIngested;
}

window.inFlightMailboxSyncs = new Set();

function renderSecureMailboxesList(mailboxes, container) {
    if (!mailboxes || mailboxes.length === 0) {
        container.innerHTML = `
            <div class="soc-panel p-4 text-center">
                <div class="text-muted mb-2"><i class="fas fa-inbox fa-2x"></i></div>
                <h6 class="fw-bold font-mono mb-1" style="color: var(--text-primary);">No Institutional Mailboxes Configured</h6>
                <p class="text-muted small mb-3">Add a TLS-encrypted IMAP mailbox to enable background threat ingestion.</p>
                <button type="button" class="btn-soc-primary btn-sm font-mono" data-bs-toggle="modal" data-bs-target="#addMailboxModal">
                    <i class="fas fa-plus me-1"></i> Add Mailbox
                </button>
            </div>
        `;
        return;
    }

    let html = '';
    mailboxes.forEach(m => {
        const isEnabled = m.status === 'active';
        const isCurrentlySyncing = window.inFlightMailboxSyncs && window.inFlightMailboxSyncs.has(m.id);
        const dbSyncStatus = m.sync_status || 'IDLE';
        const syncStatus = isCurrentlySyncing ? 'SYNCING' : dbSyncStatus;

        let badgeClass = 'soc-status-pill status-connected';
        let badgeText = 'Connected';

        if (!isEnabled) {
            badgeClass = 'soc-status-pill status-disabled';
            badgeText = 'Disabled';
        } else if (syncStatus === 'SYNCING') {
            badgeClass = 'soc-status-pill status-syncing';
            badgeText = 'Syncing...';
        } else if (m.last_error || syncStatus === 'ERROR' || syncStatus === 'FAILED') {
            badgeClass = 'soc-status-pill status-error';
            badgeText = 'Connection Error';
        } else {
            badgeClass = 'soc-status-pill status-connected';
            badgeText = 'Connected';
        }

        const formattedLastSync = m.last_synced_at ? new Date(m.last_synced_at).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Never';
        const formattedConfigured = m.configured_at ? new Date(m.configured_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : 'N/A';
        const isAdmin = (window.currentUserRole === 'admin');
        const isGmail = (m.email_address || '').toLowerCase().includes('gmail');

        html += `
            <div class="soc-mailbox-card">
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-3">
                    <!-- Left: Mailbox Identity -->
                    <div class="d-flex align-items-center gap-3" style="min-width: 280px;">
                        <div class="soc-mailbox-provider-icon">
                            <i class="${isGmail ? 'fab fa-google text-primary' : 'fas fa-inbox text-accent'} fa-lg"></i>
                        </div>
                        <div>
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <h6 class="mb-0 fw-bold font-mono" style="color: var(--text-primary);">${escapeHtml(m.email_address)}</h6>
                                <span class="${badgeClass}">${badgeText}</span>
                            </div>
                            <div class="text-muted small font-mono">
                                <span>${escapeHtml(m.provider || 'Gmail')}</span> • <span>IMAP: ${escapeHtml(m.imap_server || 'imap.gmail.com')}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Middle: Detail Metrics -->
                    <div class="d-flex gap-4 font-mono small text-muted flex-wrap align-items-center">
                        <div>
                            <div class="text-uppercase" style="font-size: 0.65rem; letter-spacing: 0.05em;">LAST SYNC</div>
                            <strong style="color: var(--text-primary);">${formattedLastSync}</strong>
                        </div>
                        <div>
                            <div class="text-uppercase" style="font-size: 0.65rem; letter-spacing: 0.05em;">EMAILS INGESTED</div>
                            <strong class="text-accent">${m.total_ingested_count || 0}</strong> <span class="small text-muted">Total emails</span>
                        </div>
                        <div>
                            <div class="text-uppercase" style="font-size: 0.65rem; letter-spacing: 0.05em;">CONFIGURED ON</div>
                            <strong style="color: var(--text-primary);">${formattedConfigured}</strong>
                        </div>
                        <div>
                            <div class="text-uppercase" style="font-size: 0.65rem; letter-spacing: 0.05em;">STATUS</div>
                            <strong class="${m.last_error ? 'text-danger' : 'text-success'}">${m.last_error ? 'Connection Error' : 'Clean (No errors)'}</strong>
                        </div>
                    </div>

                    <!-- Right: Action Buttons -->
                    <div class="d-flex gap-2 flex-wrap align-items-center">
                        <button type="button" class="btn-soc-primary btn-sm px-3 font-mono" onclick="openMailboxInbox(${m.id})">
                            <i class="fas fa-envelope-open me-1"></i> Open Inbox
                        </button>
                        ${isAdmin ? `
                        <button type="button" class="btn-soc-outline btn-sm font-mono" id="btnSync-${m.id}" onclick="handleMailboxSync(${m.id})" ${!isEnabled ? 'disabled' : ''}>
                            <i class="fas fa-arrows-rotate me-1"></i> Sync Now
                        </button>
                        <button type="button" class="btn-soc-outline btn-sm font-mono" id="btnTest-${m.id}" onclick="handleMailboxTest(${m.id})">
                            <i class="fas fa-plug me-1"></i> Test Connection
                        </button>
                        <button type="button" class="btn-soc-outline btn-sm font-mono ${isEnabled ? 'text-warning' : 'text-success'}" onclick="handleMailboxToggle(${m.id}, '${m.status}')">
                            <i class="fas ${isEnabled ? 'fa-pause' : 'fa-play'} me-1"></i> ${isEnabled ? 'Disable' : 'Enable'}
                        </button>
                        ` : ''}
                        <button type="button" class="btn-soc-outline btn-sm font-mono" onclick="openMailboxDetails(${m.id})">
                            <i class="fas fa-chart-line me-1"></i> Activity Details
                        </button>
                    </div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

window.currentMailboxId = null;
window.currentMailboxData = null;
window.currentMailboxRawEmails = [];

function openMailboxInbox(mailboxId) {
    window.currentMailboxId = mailboxId;
    const overview = document.getElementById('mailboxOverviewView');
    const inbox = document.getElementById('mailboxInboxView');

    if (overview) overview.style.display = 'none';
    if (inbox) inbox.style.display = 'block';

    loadMailboxInbox(mailboxId);
}

function closeMailboxInbox() {
    window.currentMailboxId = null;
    window.currentMailboxData = null;
    window.currentMailboxRawEmails = [];
    const overview = document.getElementById('mailboxOverviewView');
    const inbox = document.getElementById('mailboxInboxView');

    if (inbox) inbox.style.display = 'none';
    if (overview) overview.style.display = 'block';

    loadSecureMailboxes();
}

async function loadMailboxInbox(mailboxId, searchVal = '') {
    const tbody = document.getElementById('mailboxInboxTableBody');
    const emptyState = document.getElementById('mailboxInboxEmptyState');
    const tableWrapper = document.getElementById('mailboxInboxTableWrapper');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><i class="fas fa-spinner fa-spin me-2"></i>Loading mailbox messages...</td></tr>`;
    if (emptyState) emptyState.style.display = 'none';
    if (tableWrapper) tableWrapper.style.display = 'block';

    try {
        let url = `/api/mailboxes/${mailboxId}/emails?limit=100`;
        if (searchVal) {
            url += `&search=${encodeURIComponent(searchVal)}`;
        }
        const res = await fetchWithTimeout(url, {}, 15000);
        const data = await res.json();

        if (!data.success) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">${escapeHtml(data.error || 'Failed to load mailbox messages')}</td></tr>`;
            return;
        }

        window.currentMailboxData = data.mailbox;
        window.currentMailboxRawEmails = data.emails || [];
        renderMailboxInboxHeader(data.mailbox, window.currentMailboxRawEmails.length);

        if (window.currentMailboxRawEmails.length === 0) {
            if (tableWrapper) tableWrapper.style.display = 'none';
            if (emptyState) emptyState.style.display = 'block';
            return;
        }

        applyMailboxFilters();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Error loading mailbox messages: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function renderMailboxInboxTableRows(emails, tbody) {
    let html = '';
    emails.forEach(item => {
        const dateStr = item.created_at ? new Date(item.created_at).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'N/A';
        const risk = item.overall_risk_level || 'LOW';

        let riskBadge = '<span class="badge bg-success font-mono">LOW</span>';
        if (risk === 'CRITICAL') riskBadge = '<span class="badge bg-danger font-mono">CRITICAL</span>';
        else if (risk === 'HIGH') riskBadge = '<span class="badge bg-warning text-dark font-mono">HIGH</span>';
        else if (risk === 'MEDIUM') riskBadge = '<span class="badge bg-info text-dark font-mono">MEDIUM</span>';

        let vector = 'Clean';
        if (item.is_bullying) vector = 'Cyberbullying';
        else if (item.phishing_risk_level && item.phishing_risk_level !== 'LOW') vector = 'Phishing';
        else if (item.suspicious_urls_count > 0) vector = 'Malicious Links';
        else if (item.social_eng_risk_level && item.social_eng_risk_level !== 'LOW') vector = 'Social Eng.';
        else if (item.malware_detected) vector = 'Malware';

        const senderStr = item.email_from ? escapeHtml(item.email_from) : 'Unknown Sender';
        const subjectStr = item.email_subject ? escapeHtml(item.email_subject) : 'No Subject';

        html += `
            <tr>
                <td class="font-mono small text-muted" style="white-space: nowrap;">${dateStr}</td>
                <td class="font-mono small text-accent font-semibold">${senderStr}</td>
                <td class="fw-semibold text-primary-soc">${subjectStr}</td>
                <td>${riskBadge}</td>
                <td class="font-mono small text-muted">${escapeHtml(vector)}</td>
                <td><span class="badge bg-dark border border-secondary text-accent font-mono">Analyzed</span></td>
                <td>
                    <button type="button" class="btn-soc-secondary btn-sm px-2 py-1 font-mono" onclick="openIncidentDrawer(${item.id})">
                        <i class="fas fa-search me-1"></i> Inspect
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

function applyMailboxFilters() {
    const emails = window.currentMailboxRawEmails || [];
    const tbody = document.getElementById('mailboxInboxTableBody');
    const emptyState = document.getElementById('mailboxInboxEmptyState');
    const tableWrapper = document.getElementById('mailboxInboxTableWrapper');
    if (!tbody) return;

    const riskVal = document.getElementById('inboxRiskFilter') ? document.getElementById('inboxRiskFilter').value : 'ALL';
    const vectorVal = document.getElementById('inboxVectorFilter') ? document.getElementById('inboxVectorFilter').value : 'ALL';
    const statusVal = document.getElementById('inboxStatusFilter') ? document.getElementById('inboxStatusFilter').value : 'ALL';
    const msgVal = document.getElementById('inboxMsgFilter') ? document.getElementById('inboxMsgFilter').value : 'ALL';
    const searchVal = document.getElementById('mailboxSearchInput') ? document.getElementById('mailboxSearchInput').value.trim().toLowerCase() : '';

    // Handle clear search button visibility
    const btnClearSearch = document.getElementById('btnClearSearchInput');
    if (btnClearSearch) {
        if (searchVal) btnClearSearch.classList.remove('d-none');
        else btnClearSearch.classList.add('d-none');
    }

    const filtered = emails.filter(item => {
        // Msg Filter
        if (msgVal === 'UNREAD' && item.is_read) return false;
        if (msgVal === 'FLAGGED' && !item.is_flagged) return false;

        // Risk Filter
        const risk = (item.overall_risk_level || 'LOW').toUpperCase();
        if (riskVal !== 'ALL' && risk !== riskVal) return false;

        // Vector Filter
        let vector = 'Clean';
        if (item.is_bullying) vector = 'Cyberbullying';
        else if (item.phishing_risk_level && item.phishing_risk_level !== 'LOW') vector = 'Phishing';
        else if (item.suspicious_urls_count > 0) vector = 'Links';
        else if (item.social_eng_risk_level && item.social_eng_risk_level !== 'LOW') vector = 'SocialEng';
        else if (item.malware_detected) vector = 'Malware';

        if (vectorVal !== 'ALL' && vector !== vectorVal) return false;

        // Status Filter
        const status = 'Analyzed';
        if (statusVal !== 'ALL' && status !== statusVal) return false;

        // Search Filter (sender, subject, body)
        if (searchVal) {
            const subject = (item.email_subject || '').toLowerCase();
            const sender = (item.email_from || '').toLowerCase();
            const body = (item.email_text || item.body || '').toLowerCase();
            if (!subject.includes(searchVal) && !sender.includes(searchVal) && !body.includes(searchVal)) {
                return false;
            }
        }

        return true;
    });

    // Update Result Count text
    const resultCountEl = document.getElementById('inboxResultCountText');
    const headerCountEl = document.getElementById('inboxHeaderCount');
    if (resultCountEl) {
        resultCountEl.textContent = `Showing ${filtered.length} of ${emails.length} messages`;
    }
    if (headerCountEl) {
        headerCountEl.textContent = `${filtered.length}`;
    }

    // Update Active Filter Chips & Clear Button Highlight
    updateActiveFilterChips(searchVal, msgVal, riskVal, vectorVal, statusVal, emails.length, filtered.length);

    // Empty state handling
    if (filtered.length === 0) {
        if (tableWrapper) tableWrapper.style.display = 'none';
        if (emptyState) {
            emptyState.style.display = 'block';
            if (emails.length === 0) {
                emptyState.innerHTML = `
                    <div class="p-5 text-center text-muted">
                        <i class="fas fa-inbox fa-3x mb-3 text-secondary"></i>
                        <h5 class="fw-bold font-mono">No messages in this mailbox</h5>
                        <p class="small text-muted mb-3">No emails have been ingested into this institutional mailbox yet.</p>
                        <button type="button" class="btn-soc-primary btn-sm font-mono" onclick="syncCurrentMailboxInbox()">
                            <i class="fas fa-sync me-1"></i> Sync Mailbox Now
                        </button>
                    </div>`;
            } else {
                emptyState.innerHTML = `
                    <div class="p-5 text-center text-muted">
                        <i class="fas fa-filter fa-3x mb-3 text-accent"></i>
                        <h5 class="fw-bold font-mono">No messages match your filters</h5>
                        <p class="small text-muted mb-3">Try clearing search keywords or threat level filters.</p>
                        <button type="button" class="btn-soc-secondary btn-sm font-mono" onclick="resetMailboxFilters()">
                            <i class="fas fa-undo-alt me-1"></i> Clear All Filters
                        </button>
                    </div>`;
            }
        }
        return;
    }

    if (tableWrapper) tableWrapper.style.display = 'block';
    if (emptyState) emptyState.style.display = 'none';

    renderMailboxInboxTableRows(filtered, tbody);
}

function updateActiveFilterChips(searchVal, msgVal, riskVal, vectorVal, statusVal, totalCount, filteredCount) {
    const chipsContainer = document.getElementById('inboxActiveFilterChips');
    const resetBtn = document.getElementById('btnResetInboxFilters');
    let activeCount = 0;
    let chipsHtml = '';

    if (searchVal) {
        activeCount++;
        chipsHtml += `<span class="soc-chip">Search: "${escapeHtml(searchVal)}" <i class="fas fa-times chip-remove" onclick="clearSpecificFilter('search')"></i></span>`;
    }
    if (msgVal !== 'ALL') {
        activeCount++;
        chipsHtml += `<span class="soc-chip">Msg: ${escapeHtml(msgVal)} <i class="fas fa-times chip-remove" onclick="clearSpecificFilter('msg')"></i></span>`;
    }
    if (riskVal !== 'ALL') {
        activeCount++;
        chipsHtml += `<span class="soc-chip">Threat: ${escapeHtml(riskVal)} <i class="fas fa-times chip-remove" onclick="clearSpecificFilter('risk')"></i></span>`;
    }
    if (vectorVal !== 'ALL') {
        activeCount++;
        chipsHtml += `<span class="soc-chip">Vector: ${escapeHtml(vectorVal)} <i class="fas fa-times chip-remove" onclick="clearSpecificFilter('vector')"></i></span>`;
    }
    if (statusVal !== 'ALL') {
        activeCount++;
        chipsHtml += `<span class="soc-chip">Status: ${escapeHtml(statusVal)} <i class="fas fa-times chip-remove" onclick="clearSpecificFilter('status')"></i></span>`;
    }

    if (chipsContainer) chipsContainer.innerHTML = chipsHtml;

    if (resetBtn) {
        if (activeCount > 0) {
            resetBtn.classList.add('has-active');
            resetBtn.innerHTML = `<i class="fas fa-undo-alt me-1"></i> Clear (${activeCount})`;
        } else {
            resetBtn.classList.remove('has-active');
            resetBtn.innerHTML = `<i class="fas fa-undo-alt me-1"></i> Clear`;
        }
    }

    // Highlight filter select dropdowns if active
    const msgSel = document.getElementById('inboxMsgFilter');
    const riskSel = document.getElementById('inboxRiskFilter');
    const vectorSel = document.getElementById('inboxVectorFilter');
    const statusSel = document.getElementById('inboxStatusFilter');
    if (msgSel) msgSel.classList.toggle('active-filter', msgVal !== 'ALL');
    if (riskSel) riskSel.classList.toggle('active-filter', riskVal !== 'ALL');
    if (vectorSel) vectorSel.classList.toggle('active-filter', vectorVal !== 'ALL');
    if (statusSel) statusSel.classList.toggle('active-filter', statusVal !== 'ALL');
}

function clearSpecificFilter(type) {
    if (type === 'search') {
        const input = document.getElementById('mailboxSearchInput');
        if (input) input.value = '';
    } else if (type === 'msg') {
        const sel = document.getElementById('inboxMsgFilter');
        if (sel) sel.value = 'ALL';
    } else if (type === 'risk') {
        const sel = document.getElementById('inboxRiskFilter');
        if (sel) sel.value = 'ALL';
    } else if (type === 'vector') {
        const sel = document.getElementById('inboxVectorFilter');
        if (sel) sel.value = 'ALL';
    } else if (type === 'status') {
        const sel = document.getElementById('inboxStatusFilter');
        if (sel) sel.value = 'ALL';
    }
    applyMailboxFilters();
}

function clearSearchInput() {
    const input = document.getElementById('mailboxSearchInput');
    if (input) input.value = '';
    applyMailboxFilters();
}

function resetMailboxFilters() {
    const riskSel = document.getElementById('inboxRiskFilter');
    const vectorSel = document.getElementById('inboxVectorFilter');
    const statusSel = document.getElementById('inboxStatusFilter');
    const msgSel = document.getElementById('inboxMsgFilter');
    const searchInp = document.getElementById('mailboxSearchInput');

    if (riskSel) riskSel.value = 'ALL';
    if (vectorSel) vectorSel.value = 'ALL';
    if (statusSel) statusSel.value = 'ALL';
    if (msgSel) msgSel.value = 'ALL';
    if (searchInp) searchInp.value = '';

    applyMailboxFilters();
}

function renderMailboxInboxHeader(mb, msgCount) {
    const emailEl = document.getElementById('inboxHeaderEmail');
    const metaEl = document.getElementById('inboxHeaderMeta');
    const statusEl = document.getElementById('inboxHeaderStatus');
    const countEl = document.getElementById('inboxHeaderCount');

    if (emailEl) emailEl.textContent = mb.email_address || 'Mailbox Inbox';
    if (metaEl) metaEl.textContent = `${mb.provider || 'Gmail'} • Connected • IMAP: ${mb.imap_server || 'imap.gmail.com'}`;
    if (statusEl) {
        const isConn = mb.status === 'active' && mb.sync_status !== 'ERROR';
        statusEl.textContent = isConn ? 'Connected' : 'Connection Warning';
        statusEl.className = `badge ${isConn ? 'bg-success' : 'bg-danger'} font-mono px-2 py-1`;
    }
    if (countEl) countEl.textContent = mb.total_ingested_count !== undefined ? mb.total_ingested_count : msgCount;
}

function refreshMailboxInbox() {
    if (!window.currentMailboxId) return;
    const input = document.getElementById('mailboxSearchInput');
    const val = input ? input.value.trim() : '';
    loadMailboxInbox(window.currentMailboxId, val);
}

function handleMailboxSearch(e, force = false) {
    if (e && e.key !== 'Enter' && !force && e.target.value.length > 0 && e.target.value.length < 3) {
        applyMailboxFilters();
        return;
    }
    applyMailboxFilters();
}

async function syncCurrentMailboxInbox() {
    if (!window.currentMailboxId) return;
    const btn = document.getElementById('btnSyncCurrentInbox');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Syncing...';
    }
    try {
        await handleMailboxSync(window.currentMailboxId);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync me-1"></i> Sync Now';
        }
        refreshMailboxInbox();
    }
}

async function handleMailboxSync(mailboxId) {
    if (window.inFlightMailboxSyncs && window.inFlightMailboxSyncs.has(mailboxId)) {
        if (window.SOCToast) SOCToast.info('Mailbox sync already in progress.', 'Sync Busy');
        return;
    }

    if (window.inFlightMailboxSyncs) window.inFlightMailboxSyncs.add(mailboxId);
    if (cachedMailboxes && cachedMailboxes.length > 0) {
        const container = document.getElementById('connectedMailboxesList');
        if (container) renderSecureMailboxesList(cachedMailboxes, container);
    }

    const btn = document.getElementById(`btnSync-${mailboxId}`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Syncing...';
    }

    try {
        const res = await fetchWithTimeout(`/api/mailbox/${mailboxId}/sync`, { method: 'POST' }, 35000);
        const data = await res.json();

        if (data.success) {
            const processed = data.emails_processed || 0;
            const threats = data.threats_detected || 0;
            const dupes = data.duplicates_skipped || 0;

            const msg = processed > 0
                ? `Sync Completed: ${processed} email(s) processed, ${threats} threat(s) detected, ${dupes} duplicate(s) skipped.`
                : `Sync Completed: No new emails found (${dupes} already processed).`;

            if (window.SOCToast) SOCToast.success(msg, 'Mailbox Synced');
        } else {
            if (window.SOCToast) SOCToast.error(data.error || 'Mailbox sync failed', 'Sync Error');
        }
    } catch (e) {
        if (window.SOCToast) SOCToast.error(e.message, 'Sync Error');
    } finally {
        if (window.inFlightMailboxSyncs) window.inFlightMailboxSyncs.delete(mailboxId);
        if (btn && document.contains(btn)) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync me-1"></i> Sync Now';
        }
        await loadSecureMailboxes(true);
        if (window.currentMailboxId === mailboxId) {
            refreshMailboxInbox();
        }
        if (typeof loadDashboardStats === 'function') loadDashboardStats();
    }
}

async function handleMailboxTest(mailboxId) {
    const btn = document.getElementById(`btnTest-${mailboxId}`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Testing...';
    }

    try {
        const res = await fetchWithTimeout(`/api/mailbox/${mailboxId}/test`, { method: 'POST' }, 20000);
        const data = await res.json();

        if (data.success) {
            if (window.SOCToast) SOCToast.success(data.message, 'Connection Verified');
        } else {
            if (window.SOCToast) SOCToast.error(data.message || 'IMAP Connection Test Failed', 'Connection Error');
        }
    } catch (e) {
        if (window.SOCToast) SOCToast.error(e.message, 'Test Error');
    } finally {
        if (btn && document.contains(btn)) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-vial me-1"></i> Test Connection';
        }
        await loadSecureMailboxes();
    }
}

async function handleMailboxToggle(mailboxId, currentStatus) {
    const endpoint = currentStatus === 'active' ? `/api/mailbox/${mailboxId}/disable` : `/api/mailbox/${mailboxId}/enable`;
    try {
        const res = await fetchWithTimeout(endpoint, { method: 'POST' }, 15000);
        const data = await res.json();

        if (data.success) {
            if (window.SOCToast) SOCToast.success(data.message, 'Status Updated');
        } else {
            if (window.SOCToast) SOCToast.error(data.error || 'Failed to update status', 'Error');
        }
    } catch (e) {
        if (window.SOCToast) SOCToast.error(e.message, 'Error');
    } finally {
        await loadSecureMailboxes();
    }
}

function handleProviderChange() {
    const preset = document.getElementById('selectMailboxProvider').value;
    const imapInput = document.getElementById('inputNewImapServer');
    const portInput = document.getElementById('inputNewSmtpPort');

    if (preset === 'gmail') {
        imapInput.value = 'imap.gmail.com';
        portInput.value = '587';
    } else if (preset === 'outlook') {
        imapInput.value = 'outlook.office365.com';
        portInput.value = '587';
    }
}

async function handleTestNewMailboxConnection() {
    const email = document.getElementById('inputNewMailboxEmail').value.trim();
    const pass = document.getElementById('inputNewMailboxPassword').value.trim();
    const imap = document.getElementById('inputNewImapServer').value.trim();
    const btn = document.getElementById('btnTestNewMailbox');

    if (!email || !pass) {
        if (window.SOCToast) SOCToast.error('Please fill in email and App Password.', 'Validation Error');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Pre-flight Testing...';

    try {
        const res = await fetchWithTimeout('/api/mailbox/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email_address: email, app_password: pass, imap_server: imap })
        }, 20000);
        const data = await res.json();

        if (data.success) {
            if (window.SOCToast) SOCToast.success(data.message, 'IMAP Test Succeeded');
        } else {
            if (window.SOCToast) SOCToast.error(data.message || data.error, 'IMAP Test Failed');
        }
    } catch (e) {
        if (window.SOCToast) SOCToast.error(e.message, 'Test Error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-vial me-1"></i> Test Connection';
        }
    }
}

async function handleAddMailboxSubmit() {
    const email = document.getElementById('inputNewMailboxEmail').value.trim();
    const pass = document.getElementById('inputNewMailboxPassword').value.trim();
    const imap = document.getElementById('inputNewImapServer').value.trim();
    const port = document.getElementById('inputNewSmtpPort').value.trim();
    const btn = document.getElementById('btnSubmitNewMailbox');

    if (!email || !pass) return;

    const instIdInput = document.getElementById('inputMailboxInstitutionId');
    const instId = instIdInput ? (parseInt(instIdInput.value, 10) || window.activeInstitutionId || 1) : (window.activeInstitutionId || 1);

    try {
        const res = await fetchWithTimeout('/api/mailbox', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ institution_id: instId, email_address: email, app_password: pass, imap_server: imap, smtp_port: port })
        }, 25000);
        const data = await res.json();

        if (data.success) {
            if (window.SOCToast) SOCToast.success(data.message, 'Mailbox Activated');
            const modalEl = document.getElementById('addMailboxModal');
            if (modalEl && window.bootstrap) {
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
            }
            document.getElementById('formAddMailbox').reset();
            await loadSecureMailboxes();
        } else {
            if (window.SOCToast) SOCToast.error(data.details || data.error, 'Configuration Error');
        }
    } catch (e) {
        if (window.SOCToast) SOCToast.error(e.message, 'Configuration Error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-save me-1"></i> Save & Activate Mailbox';
        }
    }
}

async function openMailboxDetails(mailboxId) {
    const modalEl = document.getElementById('mailboxDetailsModal');
    const container = document.getElementById('mailboxDetailsContent');
    if (!modalEl || !container) return;

    container.innerHTML = '<div class="p-4 text-center text-muted"><i class="fas fa-spinner fa-spin me-2"></i>Fetching mailbox telemetry...</div>';

    if (window.bootstrap) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    try {
        const res = await fetchWithTimeout(`/api/mailbox/${mailboxId}`, {}, 15000);
        const data = await res.json();

        if (!data.success) {
            container.innerHTML = `<div class="alert alert-danger font-mono small p-3">${escapeHtml(data.error || 'Failed to load details')}</div>`;
            return;
        }

        const m = data.mailbox;
        const formattedLastSync = m.last_synced_at ? new Date(m.last_synced_at).toLocaleString() : 'Never';
        const formattedConfigured = m.configured_at ? new Date(m.configured_at).toLocaleString() : 'N/A';

        container.innerHTML = `
            <div class="soc-panel p-3 bg-base mb-3 font-mono small">
                <div class="row g-3">
                    <div class="col-md-6">
                        <div class="text-muted">MAILBOX ADDRESS:</div>
                        <div class="text-primary-soc font-bold">${escapeHtml(m.email_address)}</div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-muted">PROVIDER / PROTOCOL:</div>
                        <div class="text-accent">${escapeHtml(m.provider)} (IMAP SSL / Port 993)</div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-muted">STATUS / TELEMETRY:</div>
                        <div class="text-light">${m.status.toUpperCase()} &bull; ${m.sync_status}</div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-muted">LAST SYNCHRONIZED:</div>
                        <div class="text-light">${formattedLastSync}</div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-muted">EMAILS INGESTED:</div>
                        <div class="text-accent font-bold">${m.total_ingested_count || 0}</div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-muted">CONFIGURED TIMESTAMP:</div>
                        <div class="text-light">${formattedConfigured}</div>
                    </div>
                </div>
            </div>

            <h6 class="text-primary-soc font-mono text-uppercase mb-2" style="font-size: 0.78rem;">
                <i class="fas fa-terminal text-accent me-2"></i>Live Telemetry Activity Console
            </h6>
            <div class="p-3 bg-dark text-success font-mono rounded border border-secondary" style="font-size: 0.75rem; max-height: 200px; overflow-y: auto;">
                <div>[${new Date().toLocaleTimeString()}] [TELEMETRY] Connection state: ${m.status.toUpperCase()} (${m.sync_status})</div>
                <div>[${new Date().toLocaleTimeString()}] [SECURITY] Credentials encrypted via Fernet CryptoService</div>
                <div>[${new Date().toLocaleTimeString()}] [INGESTION] Total messages processed: ${m.total_ingested_count || 0}</div>
                <div>[${new Date().toLocaleTimeString()}] [STATUS] ${m.last_error ? 'Error logged: ' + escapeHtml(m.last_error) : 'IMAP session healthy'}</div>
            </div>
        `;
    } catch (e) {
        container.innerHTML = `<div class="alert alert-danger font-mono small p-3">Error: ${escapeHtml(e.message)}</div>`;
    }
}
