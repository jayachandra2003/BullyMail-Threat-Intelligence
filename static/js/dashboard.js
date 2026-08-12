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
    initNavigation();
    initSidebarToggle();
    initDropzones();
    initCharCounter();
    initDrawer();
    loadDashboardStats();
    loadAnalysisHistory();
    loadModelStatus();
    loadAvailableDatasets();
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
    const navLinks = document.querySelectorAll('.nav-link-v2');
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
    
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
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
        overlay.addEventListener('click', closeIncidentDrawer);
    }
    if (closeBtn) {
        closeBtn.addEventListener('click', closeIncidentDrawer);
    }
}

async function openIncidentDrawer(id) {
    const overlay = document.getElementById('socDrawerOverlay');
    const drawer = document.getElementById('socDrawer');
    const body = document.getElementById('socDrawerBody');
    const title = document.getElementById('socDrawerTitle');
    
    if (!drawer || !body) return;
    
    if (title) title.textContent = `Incident Case #BM-${escapeHtml(id)}`;
    body.innerHTML = `
        <div class="p-5 text-center text-muted">
            <i class="fas fa-spinner fa-spin fa-2x text-accent mb-3"></i>
            <div class="small">Retrieving multi-vector forensic telemetry...</div>
        </div>
    `;
    
    overlay?.classList.add('active');
    drawer.classList.add('active');
    
    try {
        const res = await fetch(`/api/analysis/${id}`);
        const data = await res.json();
        if (data.success) {
            renderSecurityReport(data.analysis, body);
        } else {
            body.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.error || 'Failed to load case.')}</div>`;
        }
    } catch (e) {
        body.innerHTML = `<div class="alert alert-danger">Error: ${escapeHtml(e.message)}</div>`;
    }
}

function closeIncidentDrawer() {
    document.getElementById('socDrawerOverlay')?.classList.remove('active');
    document.getElementById('socDrawer')?.classList.remove('active');
}

/* ==========================================================================
   3. Mission Control Dashboard Telemetry & Visualizations
   ========================================================================== */
let threatRadarChart = null;

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

            // Throughput metrics
            setVal('statTotalAnalyses', s.total_analyses);
            setVal('postureTotalScanned', s.total_analyses);
            setVal('statBullying', s.bullying_detected);
            setVal('statPhishing', s.phishing_detected);
            setVal('statUrls', s.suspicious_urls);
            setVal('statMalware', s.malware_detected);
            setVal('statSocialEng', s.social_eng_detected);

            // Posture readout
            const postureVal = document.getElementById('postureThreatLevel');
            const postureSub = document.getElementById('postureSubtext');
            const r = s.risk_distribution || {};
            const criticals = r.CRITICAL || 0;
            const highs = r.HIGH || 0;

            if (postureVal) {
                if (criticals > 0) {
                    postureVal.innerHTML = `<span class="text-danger">ELEVATED THREAT</span> <small class="text-muted font-mono" style="font-size: 0.85rem;">(Critical Risks Active)</small>`;
                    if (postureSub) postureSub.textContent = `${criticals} critical security incident(s) flagged across monitored communications.`;
                } else if (highs > 0) {
                    postureVal.innerHTML = `<span class="text-warning">MODERATE THREAT</span> <small class="text-muted font-mono" style="font-size: 0.85rem;">(Active High Risks)</small>`;
                    if (postureSub) postureSub.textContent = `${highs} high-severity threat incidents identified requiring review.`;
                } else {
                    postureVal.innerHTML = `<span class="text-success">LOW RISK POSTURE</span> <small class="text-muted font-mono" style="font-size: 0.85rem;">(95% Confidence)</small>`;
                    if (postureSub) postureSub.textContent = `Environment currently shows low threat activity across all inspected vectors.`;
                }
            }

            window.dashboardStatsData = s;
            renderSeverityMatrix(s.risk_distribution || {});
            renderCharts();
        }
    } catch (e) {
        console.error('Error loading SOC telemetry stats:', e);
    }

    // Also load live stream
    loadLiveThreatStream();
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
    if (!container) return;

    try {
        const res = await fetch('/api/analysis-history?limit=8');
        const data = await res.json();
        if (data.success && data.history && data.history.length > 0) {
            let html = '';
            data.history.forEach(item => {
                const risk = escapeHtml(item.overall_risk_level || 'LOW');
                const timeStr = item.created_at ? escapeHtml(item.created_at.split(' ')[1] || item.created_at) : 'Just now';
                html += `
                    <div class="stream-event-item" onclick="openIncidentDrawer(${item.id})">
                        <span class="badge-risk ${risk}">${risk}</span>
                        <div class="stream-event-content">
                            <div class="stream-event-title">${escapeHtml(item.email_subject || 'Untitled Communication')}</div>
                            <div class="stream-event-meta font-mono">${escapeHtml(item.email_from || 'Unknown')} &bull; Conf: ${Math.round(item.overall_confidence * 100)}%</div>
                        </div>
                        <div class="stream-time-badge">${timeStr}</div>
                    </div>
                `;
            });
            container.innerHTML = html;
        } else {
            container.innerHTML = `
                <div class="p-4 text-center text-muted">
                    <i class="fas fa-satellite-dish fa-2x mb-2 text-dim"></i>
                    <div class="small">No threat incidents recorded in stream yet.</div>
                </div>
            `;
        }
    } catch (e) {}
}

function renderCharts() {
    const s = window.dashboardStatsData;
    if (!s || typeof Chart === 'undefined') return;

    const resolvedTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const isDark = resolvedTheme === 'dark';
    const chartTextColor = isDark ? '#e2e8f0' : '#1e293b';
    const chartMutedColor = isDark ? '#94a3b8' : '#64748b';
    const chartGridColor = isDark ? '#1e293b' : '#e2e8f0';

    // Radar Threat Vector Profile Chart
    const radarCanvas = document.getElementById('chartThreatRadar');
    if (radarCanvas) {
        if (threatRadarChart) threatRadarChart.destroy();
        threatRadarChart = new Chart(radarCanvas, {
            type: 'radar',
            data: {
                labels: ['Cyberbullying', 'Phishing', 'Malicious Links', 'Malware', 'Social Eng.'],
                datasets: [{
                    label: 'Threat Incidents',
                    data: [
                        s.bullying_detected || 0,
                        s.phishing_detected || 0,
                        s.suspicious_urls || 0,
                        s.malware_detected || 0,
                        s.social_eng_detected || 0
                    ],
                    backgroundColor: isDark ? 'rgba(99, 102, 241, 0.22)' : 'rgba(79, 70, 229, 0.16)',
                    borderColor: isDark ? '#818cf8' : '#4f46e5',
                    pointBackgroundColor: isDark ? '#818cf8' : '#4f46e5',
                    pointBorderColor: '#ffffff',
                    borderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: { color: chartGridColor },
                        grid: { color: chartGridColor },
                        pointLabels: { color: chartTextColor, font: { family: 'Inter', size: 11, weight: 700 } },
                        ticks: { backdropColor: 'transparent', color: chartMutedColor, stepSize: 2 }
                    }
                },
                plugins: {
                    legend: { labels: { color: chartTextColor, font: { family: 'Inter', size: 12, weight: 600 } } }
                }
            }
        });
    }
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
    const rawRisk = rep.overall_risk_level || 'LOW';
    const risk = escapeHtml(rawRisk);
    const conf = Math.round((rep.overall_confidence || 0) * 100);
    const threatScore = rep.threat_score !== undefined ? rep.threat_score : (conf / 100);
    
    // Risk Color Mapping
    const colorMap = {
        CRITICAL: '#ef4444',
        HIGH: '#f97316',
        MEDIUM: '#f59e0b',
        LOW: '#10b981',
        SAFE: '#10b981'
    };
    const riskColor = colorMap[rawRisk] || '#10b981';

    // SVG Gauge Calculations (Radius = 42 -> Circumference = 263.89)
    const circumference = 263.89;
    const strokeOffset = circumference - (circumference * Math.min(1, Math.max(0, threatScore)));

    const b = rep.bullying_analysis || {};
    const p = rep.phishing_analysis || {};
    const u = rep.url_analysis || {};
    const s = rep.social_eng_analysis || {};
    const m = rep.malware_analysis || {};
    const img = rep.image_analysis || {};

    const safeSubject = escapeHtml(rep.email_subject || 'No Subject');
    const safeFrom = escapeHtml(rep.email_from || 'Unknown Sender');
    const safeTo = rep.email_to ? escapeHtml(rep.email_to) : '';

    let html = `
        <div class="assessment-matrix-panel animate-fade-in">
            <!-- Assessment Hero Verdict -->
            <div class="assessment-hero-row">
                <!-- Circular Risk Gauge -->
                <div class="risk-gauge-wrap">
                    <svg class="risk-gauge-circle" width="95" height="95" viewBox="0 0 95 95">
                        <circle class="risk-gauge-bg" cx="47.5" cy="47.5" r="42" />
                        <circle class="risk-gauge-bar" cx="47.5" cy="47.5" r="42"
                                style="stroke: ${riskColor}; stroke-dasharray: ${circumference}; stroke-dashoffset: ${strokeOffset};" />
                    </svg>
                    <div class="risk-gauge-val">${conf}%</div>
                </div>

                <!-- Verdict Summary -->
                <div>
                    <div class="d-flex align-items-center gap-2 mb-1">
                        <span class="badge-risk ${risk}">${risk} RISK VERDICT</span>
                        <span class="text-muted small font-mono">• Score: ${threatScore}</span>
                    </div>
                    <h3 class="mb-1 text-primary-soc" style="font-size: 1.25rem;">${safeSubject}</h3>
                    <p class="text-muted small mb-0 font-mono">
                        From: <strong class="text-secondary-soc">${safeFrom}</strong>
                        ${safeTo ? ` &bull; To: <strong class="text-secondary-soc">${safeTo}</strong>` : ''}
                    </p>
                </div>

                <!-- Print Action -->
                <div>
                    <a href="/api/reports/view/${encodeURIComponent(rep.id || '')}" target="_blank" class="btn-soc-secondary btn-sm text-center">
                        <i class="fas fa-print me-1"></i> Audit PDF
                    </a>
                </div>
            </div>

            <!-- Multi-Stage Threat Pipeline Flow -->
            <div class="pipeline-flow-container">
                <div class="pipeline-nodes">
                    <div class="pipeline-node completed">
                        <div class="node-dot"><i class="fas fa-check"></i></div>
                        <span class="node-label">Ingest</span>
                    </div>
                    <div class="pipeline-node ${b.is_bullying ? 'flagged' : 'completed'}">
                        <div class="node-dot"><i class="fas ${b.is_bullying ? 'fa-exclamation' : 'fa-check'}"></i></div>
                        <span class="node-label">NLP Bully</span>
                    </div>
                    <div class="pipeline-node ${p.risk_level && p.risk_level !== 'LOW' ? 'flagged' : 'completed'}">
                        <div class="node-dot"><i class="fas ${p.risk_level && p.risk_level !== 'LOW' ? 'fa-exclamation' : 'fa-check'}"></i></div>
                        <span class="node-label">Phishing</span>
                    </div>
                    <div class="pipeline-node ${u.suspicious_count > 0 ? 'flagged' : 'completed'}">
                        <div class="node-dot"><i class="fas ${u.suspicious_count > 0 ? 'fa-exclamation' : 'fa-check'}"></i></div>
                        <span class="node-label">Link Audit</span>
                    </div>
                    <div class="pipeline-node ${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? 'flagged' : 'completed'}">
                        <div class="node-dot"><i class="fas ${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? 'fa-exclamation' : 'fa-check'}"></i></div>
                        <span class="node-label">Static File</span>
                    </div>
                    <div class="pipeline-node ${rawRisk === 'CRITICAL' || rawRisk === 'HIGH' ? 'flagged' : 'completed'}">
                        <div class="node-dot"><i class="fas fa-brain"></i></div>
                        <span class="node-label">Risk Fusion</span>
                    </div>
                </div>
            </div>

            <!-- 6 Threat Vectors Matrix Grid -->
            <h6 class="mb-2 text-primary-soc font-mono text-uppercase" style="font-size: 0.76rem; letter-spacing: 0.08em;">
                <i class="fas fa-microscope text-accent me-1"></i> Multi-Vector Forensic Decomposition
            </h6>
            <div class="threat-matrix-grid">
                <!-- Bullying -->
                <div class="matrix-vector-card ${b.is_bullying ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-comment-slash"></i></div>
                    <div class="matrix-vector-name">Cyberbullying</div>
                    <div class="matrix-vector-status ${b.is_bullying ? 'text-danger' : 'text-success'}">
                        ${b.is_bullying ? '● DETECTED' : '✓ NOT DETECTED'}
                    </div>
                    <div class="matrix-vector-detail">${b.is_bullying ? escapeHtml(b.severity || 'MEDIUM') + ' &bull; ' : ''}${Math.round((b.confidence || 0) * 100)}% conf</div>
                </div>

                <!-- Phishing -->
                <div class="matrix-vector-card ${p.risk_level && p.risk_level !== 'LOW' ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-fish"></i></div>
                    <div class="matrix-vector-name">Phishing Risk</div>
                    <div class="matrix-vector-status ${p.risk_level && p.risk_level !== 'LOW' ? 'text-danger' : 'text-success'}">
                        ${p.risk_level === 'LOW' || !p.risk_level ? '✓ NOT DETECTED' : '● ' + escapeHtml(p.risk_level)}
                    </div>
                    <div class="matrix-vector-detail">${Math.round((p.confidence || 0) * 100)}% conf</div>
                </div>

                <!-- Links / URLs -->
                <div class="matrix-vector-card ${u.suspicious_count > 0 ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-link"></i></div>
                    <div class="matrix-vector-name">Link Safety</div>
                    <div class="matrix-vector-status ${u.suspicious_count > 0 ? 'text-warning' : 'text-success'}">
                        ${u.suspicious_count > 0 ? '⚠ ' + parseInt(u.suspicious_count) + ' RISKY' : '✓ SAFE'}
                    </div>
                    <div class="matrix-vector-detail">${parseInt(u.total_urls || 0)} link(s) scanned</div>
                </div>

                <!-- Social Engineering -->
                <div class="matrix-vector-card ${s.risk_level && s.risk_level !== 'LOW' ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-user-secret"></i></div>
                    <div class="matrix-vector-name">Social Eng.</div>
                    <div class="matrix-vector-status ${s.risk_level && s.risk_level !== 'LOW' ? 'text-warning' : 'text-success'}">
                        ${s.risk_level === 'LOW' || !s.risk_level ? '✓ NOT DETECTED' : '● ' + escapeHtml(s.risk_level)}
                    </div>
                    <div class="matrix-vector-detail">${Math.round((s.confidence || 0) * 100)}% conf</div>
                </div>

                <!-- Malware -->
                <div class="matrix-vector-card ${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-file-code"></i></div>
                    <div class="matrix-vector-name">Static File</div>
                    <div class="matrix-vector-status ${m.risk_level && m.risk_level !== 'SAFE' && m.risk_level !== 'LOW' ? 'text-danger' : 'text-success'}">
                        ${m.risk_level === 'SAFE' || !m.risk_level ? '✓ CLEAN' : '● ' + escapeHtml(m.risk_level)}
                    </div>
                    <div class="matrix-vector-detail">${parseInt(m.total_attachments || 0)} attachment(s)</div>
                </div>

                <!-- Image Forensics -->
                <div class="matrix-vector-card ${img.risk_level && img.risk_level !== 'LOW' ? 'detected' : 'clean'}">
                    <div class="matrix-vector-icon"><i class="fas fa-image"></i></div>
                    <div class="matrix-vector-name">Image Forensics</div>
                    <div class="matrix-vector-status ${img.risk_level && img.risk_level !== 'LOW' ? 'text-warning' : 'text-success'}">
                        ${img.risk_level === 'LOW' || !img.risk_level ? '✓ CLEAN' : '⚠ ' + escapeHtml(img.risk_level)}
                    </div>
                    <div class="matrix-vector-detail">${parseInt(img.total_images || 0)} image(s)</div>
                </div>
            </div>

            <!-- Explainable AI Evidence Stream -->
            <h6 class="mb-2 text-primary-soc font-mono text-uppercase" style="font-size: 0.76rem; letter-spacing: 0.08em;">
                <i class="fas fa-fingerprint text-accent me-1"></i> AI Forensic Reasoning & Evidence
            </h6>
            <div class="evidence-feed-matrix">
    `;

    if (rep.evidence && rep.evidence.length > 0) {
        rep.evidence.forEach(ev => {
            const rawSev = ev.severity || 'MEDIUM';
            const safeSev = escapeHtml(rawSev);
            const safeCat = escapeHtml(ev.category || 'Threat Indicator');
            const safeTitle = escapeHtml(ev.title || '');
            const safeDetails = escapeHtml(ev.details || '');
            html += `
                <div class="evidence-reasoning-card ${safeSev}">
                    <div class="evidence-reasoning-header">
                        <span class="evidence-reasoning-cat">${safeCat}</span>
                        <span class="badge-risk ${safeSev}">${safeSev}</span>
                    </div>
                    <div class="evidence-reasoning-title">${safeTitle}</div>
                    <div class="evidence-reasoning-details">${safeDetails}</div>
                </div>
            `;
        });
    } else {
        html += `
            <div class="soc-panel p-3 text-center">
                <div class="text-success mb-1"><i class="fas fa-check-circle fa-lg"></i></div>
                <h6 class="text-primary-soc mb-1" style="font-size: 0.85rem;">No Malicious Indicators Identified</h6>
                <p class="text-muted small mb-0">The email content, sender headers, links, and attachments cleared all forensic security heuristics.</p>
            </div>
        `;
    }

    html += `</div></div>`;
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
                
                tr.innerHTML = `
                    <td class="font-mono text-muted small">${safeTime}</td>
                    <td><strong class="text-primary-soc">${safeSubject}</strong></td>
                    <td class="text-muted small font-mono">${safeFrom}</td>
                    <td><span class="badge-risk ${risk}">${risk}</span></td>
                    <td class="font-mono text-primary-soc">${Math.round(item.overall_confidence * 100)}%</td>
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
