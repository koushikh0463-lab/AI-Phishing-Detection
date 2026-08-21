// Tab switching
const tabs = document.querySelectorAll('.tab');
const views = document.querySelectorAll('.view');

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    views.forEach(v => v.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('view-' + tab.dataset.view).classList.add('active');
    if (tab.dataset.view === 'dashboard') loadDashboard();
  });
});

// Scan form
const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const btn = document.getElementById('scan-btn');
const resultArea = document.getElementById('result-area');
const errorMsg = document.getElementById('error-msg');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  errorMsg.hidden = true;
  btn.disabled = true;
  btn.querySelector('.btn-label').textContent = 'Analyzing…';

  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Something went wrong.');
    }
    renderResult(data);
  } catch (err) {
    errorMsg.textContent = err.message;
    errorMsg.hidden = false;
    resultArea.hidden = true;
  } finally {
    btn.disabled = false;
    btn.querySelector('.btn-label').textContent = 'Analyze';
  }
});

function renderResult(data) {
  resultArea.hidden = false;

  const badge = document.getElementById('verdict-badge');
  const icon = document.getElementById('verdict-icon');
  const text = document.getElementById('verdict-text');

  const isPhishing = data.prediction === 'Phishing';
  badge.className = 'verdict-badge ' + (isPhishing ? 'phishing' : 'legitimate');
  icon.textContent = isPhishing ? '⚠' : '✓';
  text.textContent = isPhishing ? 'PHISHING DETECTED' : 'LEGITIMATE';

  document.getElementById('risk-score-num').textContent = data.risk_score + '%';
  document.getElementById('risk-meter-fill').style.width = data.risk_score + '%';
  document.getElementById('risk-level-label').textContent = data.risk_level.toUpperCase();

  const reasonsList = document.getElementById('reasons-list');
  reasonsList.innerHTML = '';
  data.reasons.forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  const featTable = document.getElementById('features-table');
  featTable.innerHTML = '';
  Object.entries(data.features).forEach(([name, val]) => {
    const row = document.createElement('div');
    row.className = 'feature-row';
    row.innerHTML = `<span class="fname">${prettyName(name)}</span><span class="fval">${val}</span>`;
    featTable.appendChild(row);
  });

  resultArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function prettyName(name) {
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// Dashboard
async function loadDashboard() {
  try {
    const res = await fetch('/dashboard');
    const data = await res.json();

    document.getElementById('stat-total').textContent = data.total_scanned;
    document.getElementById('stat-phishing').textContent = data.phishing_detected;
    document.getElementById('stat-legit').textContent = data.legitimate;
    document.getElementById('stat-rate').textContent = data.detection_rate + '%';

    const historyTable = document.getElementById('history-table');
    if (!data.recent.length) {
      historyTable.innerHTML = '<p class="empty-note">No scans yet — run a URL through the scanner first.</p>';
      return;
    }

    historyTable.innerHTML = '';
    data.recent.forEach(item => {
      const row = document.createElement('div');
      row.className = 'history-row';
      const tagClass = item.prediction === 'Phishing' ? 'phishing' : 'legitimate';
      row.innerHTML = `
        <span class="history-url" title="${item.url}">${item.url}</span>
        <span class="history-tag ${tagClass}">${item.prediction}</span>
        <span class="history-score">${item.risk_score}%</span>
      `;
      historyTable.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to load dashboard', err);
  }
}
