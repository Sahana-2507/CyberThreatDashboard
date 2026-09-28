let chartInstance = null;
let currentFilter = 'All';
let allAlerts = [];

// Initialize live UTC clock
function initLiveClock() {
  const clockEl = document.getElementById('socClock');
  if (!clockEl) return;

  function updateClock() {
    const now = new Date();
    const utcHours = String(now.getUTCHours()).padStart(2, '0');
    const utcMinutes = String(now.getUTCMinutes()).padStart(2, '0');
    const utcSeconds = String(now.getUTCSeconds()).padStart(2, '0');
    clockEl.innerText = `${utcHours}:${utcMinutes}:${utcSeconds} UTC`;
  }

  updateClock();
  setInterval(updateClock, 1000);
}

// Toggle mobile sidebar
function toggleSidebar() {
  const sidebar = document.getElementById('socSidebar');
  if (sidebar) {
    sidebar.classList.toggle('open');
  }
}

// Close sidebar on link click (mobile)
document.addEventListener('DOMContentLoaded', () => {
  initLiveClock();
  
  const navLinks = document.querySelectorAll('.soc-sidebar .nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const sidebar = document.getElementById('socSidebar');
      if (sidebar && window.innerWidth <= 900) {
        sidebar.classList.remove('open');
      }
    });
  });
});

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();

    const packets = data.totalPackets || 0;
    const threats = data.totalThreats || 0;
    const high = data.high || 0;
    const med = data.medium || 0;
    const low = data.low || 0;

    // Update core KPI counters
    document.getElementById('totalPackets').innerText = packets.toLocaleString();
    document.getElementById('totalThreats').innerText = threats.toLocaleString();
    document.getElementById('highThreats').innerText = high.toLocaleString();
    document.getElementById('medThreats').innerText = (med + low).toLocaleString();

    // Derived detection rate
    const detectionRateBadge = document.getElementById('detectionRatioBadge');
    if (detectionRateBadge) {
      const rate = packets > 0 ? ((threats / packets) * 100).toFixed(1) : '0.0';
      detectionRateBadge.innerText = `Rate: ${rate}%`;
    }

    allAlerts = data.alerts || [];

    // Update total badge
    const badge = document.getElementById('threatCountBadge');
    if (badge) {
      badge.innerText = `${allAlerts.length} logged`;
    }

    // Update legend counts
    const legHigh = document.getElementById('legendHighCount');
    const legMed = document.getElementById('legendMedCount');
    const legLow = document.getElementById('legendLowCount');
    if (legHigh) legHigh.innerText = high;
    if (legMed) legMed.innerText = med;
    if (legLow) legLow.innerText = low;

    // Update filter counts
    updateFilterCounts(allAlerts);

    renderTable(allAlerts);
    renderChart(high, med, low);
  } catch (err) {
    console.error('Failed fetching data:', err);
  }
}

function updateFilterCounts(alerts) {
  let crit = 0, high = 0, med = 0, low = 0;
  alerts.forEach(a => {
    const s = (a.severity || '').toUpperCase();
    if (s === 'CRITICAL') crit++;
    else if (s === 'HIGH') high++;
    else if (s === 'MEDIUM') med++;
    else if (s === 'LOW') low++;
  });

  const countAll = document.getElementById('count-all');
  const countCrit = document.getElementById('count-critical');
  const countHigh = document.getElementById('count-high');
  const countMed = document.getElementById('count-medium');
  const countLow = document.getElementById('count-low');

  if (countAll) countAll.innerText = alerts.length;
  if (countCrit) countCrit.innerText = crit;
  if (countHigh) countHigh.innerText = high;
  if (countMed) countMed.innerText = med;
  if (countLow) countLow.innerText = low;
}

function renderTable(alerts) {
  const tbody = document.getElementById('threatTableBody');
  tbody.innerHTML = '';

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `
      <tr class="no-filter-row">
        <td colspan="5" style="text-align: center; color: #64748b; padding: 36px;">
          <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.5" style="display:block; margin:0 auto 10px; color:#475569;">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          No incident telemetry logged yet. Live monitor active.
        </td>
      </tr>
    `;
    return;
  }

  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.dataset.severity = (a.severity || '').toUpperCase();
    tr.innerHTML = `
      <td>${escapeHtml(a.timestamp)}</td>
      <td>${escapeHtml(a.type)}</td>
      <td><code>${escapeHtml(a.sourceIp)}</code></td>
      <td><span class="severity-badge sev-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
      <td>${escapeHtml(a.desc)}</td>
    `;
    tbody.appendChild(tr);
  });

  // Empty state row for when the selected filter matches 0 rows
  const emptyRow = document.createElement('tr');
  emptyRow.id = 'noFilterResultsRow';
  emptyRow.className = 'no-filter-row';
  emptyRow.style.display = 'none';
  emptyRow.innerHTML = `
    <td colspan="5" style="text-align: center; color: #94a3b8; padding: 36px;">
      No threats matching severity filter <strong>${escapeHtml(currentFilter)}</strong> found in active telemetry.
    </td>
  `;
  tbody.appendChild(emptyRow);

  // Apply current filter to visible table rows without page reload
  applyFilterToRows();
}

function filterBySeverity(severity) {
  currentFilter = severity;

  // Update active state on filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    const filterVal = btn.getAttribute('data-filter') || btn.innerText.trim();
    if (filterVal.toUpperCase() === severity.toUpperCase()) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Filter visible rows immediately without reloading the page
  applyFilterToRows();
}

function applyFilterToRows() {
  const rows = document.querySelectorAll('#threatTableBody tr:not(.no-filter-row)');
  let matchCount = 0;

  rows.forEach(tr => {
    const badge = tr.querySelector('.severity-badge') || tr.children[3];
    const sev = badge ? badge.textContent.trim().toUpperCase() : '';

    if (currentFilter.toUpperCase() === 'ALL' || sev === currentFilter.toUpperCase()) {
      tr.style.display = '';
      matchCount++;
    } else {
      tr.style.display = 'none';
    }
  });

  const noResultRow = document.getElementById('noFilterResultsRow');
  if (noResultRow) {
    if (matchCount === 0 && rows.length > 0) {
      noResultRow.style.display = '';
      noResultRow.querySelector('td').innerHTML = `No <strong>${escapeHtml(currentFilter)}</strong> severity threats found in current logs.`;
    } else {
      noResultRow.style.display = 'none';
    }
  }
}

function exportThreatsToCSV() {
  if (!allAlerts || allAlerts.length === 0) {
    alert('No threat logs available to export.');
    return;
  }

  // Required columns: Timestamp, Attack Type, Severity, Payload
  const headers = ['Timestamp', 'Attack Type', 'Severity', 'Payload'];
  const csvRows = [];

  // Header row
  csvRows.push(headers.map(escapeCsvValue).join(','));

  // Data rows
  allAlerts.forEach(a => {
    const timestamp = a.timestamp || '';
    const attackType = a.type || '';
    const severity = a.severity || '';
    // Payload can be from a.payload or extracted from a.desc
    const payload = a.payload || a.desc || '';

    const row = [
      escapeCsvValue(timestamp),
      escapeCsvValue(attackType),
      escapeCsvValue(severity),
      escapeCsvValue(payload)
    ];
    csvRows.push(row.join(','));
  });

  // UTF-8 BOM prefix (\uFEFF) ensures Excel and text editors render special characters properly
  const csvContent = '\uFEFF' + csvRows.join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10);
  const timeStr = now.toTimeString().slice(0, 8).replace(/:/g, '-');
  link.download = `threat_logs_${dateStr}_${timeStr}.csv`;
  link.style.display = 'none';

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);

  // Button visual feedback
  const exportBtn = document.getElementById('exportCsvBtn');
  if (exportBtn) {
    const originalContent = exportBtn.innerHTML;
    exportBtn.classList.add('exported');
    exportBtn.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
      </svg>
      Exported (${allAlerts.length})!
    `;
    setTimeout(() => {
      exportBtn.innerHTML = originalContent;
      exportBtn.classList.remove('exported');
    }, 2000);
  }
}

function escapeCsvValue(val) {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/"/g, '""');
  return `"${str}"`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderChart(high, med, low) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  const dataValues = [high || 0, med || 0, low || 0];

  if (chartInstance) {
    chartInstance.data.datasets[0].data = dataValues;
    chartInstance.update();
    return;
  }

  chartInstance = new Chart(ctx.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical / High', 'Medium', 'Low'],
      datasets: [{
        data: dataValues,
        backgroundColor: [
          '#ef4444', // Red for Critical/High
          '#f59e0b', // Amber for Medium
          '#00f2fe'  // Electric cyan for Low
        ],
        borderColor: '#0b1120',
        borderWidth: 3,
        hoverBorderColor: '#ffffff',
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          display: false // We use our custom SOC legend cards!
        },
        tooltip: {
          backgroundColor: 'rgba(11, 17, 32, 0.95)',
          titleColor: '#f8fafc',
          bodyColor: '#cbd5e1',
          borderColor: 'rgba(0, 242, 254, 0.3)',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 8,
          bodyFont: {
            family: "'Inter', sans-serif",
            size: 12
          },
          titleFont: {
            family: "'Inter', sans-serif",
            size: 12,
            weight: 'bold'
          },
          boxPadding: 4
        }
      }
    }
  });
}

function loadSampleAttack(val) {
  if (!val) return;
  const input = document.getElementById('payloadInput');
  if (input) {
    input.value = val;
    input.focus();
    const resultDiv = document.getElementById('inspectorResult');
    if (resultDiv) {
      resultDiv.style.display = 'none';
    }
  }
}

function setSample(val) {
  const input = document.getElementById('payloadInput');
  if (input) {
    input.value = val;
    input.focus();
    const resultDiv = document.getElementById('inspectorResult');
    if (resultDiv) {
      resultDiv.style.display = 'none';
    }
  }
}

async function inspectCustomPayload() {
  const input = document.getElementById('payloadInput').value;
  const resultDiv = document.getElementById('inspectorResult');
  if (!input.trim()) return;

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      body: input
    });
    const result = await res.json();

    resultDiv.style.display = 'block';
    if (result.threatDetected) {
      resultDiv.className = 'result-box danger-box';
      resultDiv.innerHTML = `
        <div style="display:flex; align-items:flex-start; gap:10px;">
          <span style="font-size:16px;">🚨</span>
          <div>
            <div style="font-weight:700; color:#f87171; letter-spacing:0.5px;">[ALERT TRIGGERED] Heuristic Match Found</div>
            <div style="margin-top:4px;">
              Detected: <strong>${escapeHtml(result.alert.type)}</strong> 
              <span class="severity-badge sev-${escapeHtml(result.alert.severity)}" style="margin-left:6px;">${escapeHtml(result.alert.severity)}</span>
            </div>
            <div style="margin-top:4px; color:#cbd5e1; font-size:12px;">&bull; ${escapeHtml(result.alert.desc)}</div>
          </div>
        </div>
      `;
    } else {
      resultDiv.className = 'result-box success-box';
      resultDiv.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px;">
          <span style="font-size:16px;">🛡️</span>
          <div>
            <span style="font-weight:700; color:#34d399;">[CLEAN PACKET] Traffic Analyzed</span>
            <div style="margin-top:2px; color:#a7f3d0; font-size:12px;">${escapeHtml(result.message)}</div>
          </div>
        </div>
      `;
    }
    fetchStats();
  } catch (e) {
    console.error(e);
  }
}

setInterval(fetchStats, 2000);
fetchStats();