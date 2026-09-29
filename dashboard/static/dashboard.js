/**
 * NetGuardian Dashboard JavaScript Client
 * Manages tab switching, asynchronous trust toggling, anomaly resolution,
 * manual on-demand scanning, and live metrics auto-refresh.
 */

// Tab Navigation
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(pane => pane.style.display = 'none');

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  const activePane = document.getElementById(`tab-pane-${tabId}`);

  if (activeBtn) activeBtn.classList.add('active');
  if (activePane) activePane.style.display = 'block';
}

// Toggle Trust Status
async function toggleTrust(mac) {
  try {
    const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/trust`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      window.location.reload();
    }
  } catch (err) {
    console.error('Failed to toggle trust:', err);
    alert('Error updating trust status');
  }
}

// Resolve Anomaly
async function resolveAnomaly(anomalyId) {
  try {
    const res = await fetch(`/api/anomalies/${anomalyId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      const row = document.getElementById(`anomaly-row-${anomalyId}`);
      if (row) {
        row.style.opacity = '0.4';
        const actionBtn = row.querySelector('.resolve-btn');
        if (actionBtn) {
          actionBtn.textContent = 'Resolved';
          actionBtn.disabled = true;
        }
      }
    }
  } catch (err) {
    console.error('Failed to resolve anomaly:', err);
  }
}

// Trigger Manual Scan
async function triggerScan() {
  const btn = document.getElementById('scan-btn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⚡ Scanning Network...';
  }

  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert(`Scan complete: ${data.discovered_count} active devices confirmed.`);
      window.location.reload();
    } else {
      alert(`Scan failed: ${data.error}`);
    }
  } catch (err) {
    alert('Failed to connect to scanner service.');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Scan Subnet Now';
    }
  }
}

// Auto-refresh summary counters periodically (every 10 seconds)
setInterval(async () => {
  try {
    const res = await fetch('/api/summary');
    const data = await res.json();
    if (data) {
      const totalDev = document.getElementById('stat-total-devices');
      const activeDev = document.getElementById('stat-active-devices');
      const totalPkts = document.getElementById('stat-total-packets');
      const totalAnom = document.getElementById('stat-unresolved-anomalies');

      if (totalDev) totalDev.textContent = data.total_devices;
      if (activeDev) activeDev.textContent = data.active_devices;
      if (totalPkts) totalPkts.textContent = Number(data.total_packets).toLocaleString();
      if (totalAnom) totalAnom.textContent = data.unresolved_anomalies;
    }
  } catch (e) {
    // Silent fail on background polling
  }
}, 10000);
