const API_BASE = '/api';

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchLogs(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${API_BASE}/logs?${query}`);
  if (!res.ok) throw new Error('Failed to fetch logs');
  return res.json();
}

export async function ingestRawLog(rawText, source = 'syslog') {
  const res = await fetch(`${API_BASE}/logs/raw?default_source=${source}`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: rawText,
  });
  if (!res.ok) throw new Error('Failed to ingest raw log');
  return res.json();
}

export async function fetchAlerts(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${API_BASE}/alerts?${query}`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchAlertDetail(alertId) {
  const res = await fetch(`${API_BASE}/alerts/${alertId}`);
  if (!res.ok) throw new Error('Failed to fetch alert detail');
  return res.json();
}

export async function triageAlert(alertId, status, incidentId = null) {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/triage`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, incident_id: incidentId }),
  });
  if (!res.ok) throw new Error('Failed to triage alert');
  return res.json();
}

export async function fetchIncidents(params = {}) {
  const query = new URLSearchParams(params).toString();
  const res = await fetch(`${API_BASE}/incidents?${query}`);
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export async function fetchIncidentDetail(incidentId) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}`);
  if (!res.ok) throw new Error('Failed to fetch incident detail');
  return res.json();
}

export async function updateIncidentStatus(incidentId, status, assignedAnalyst = null) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, assigned_analyst: assignedAnalyst }),
  });
  if (!res.ok) throw new Error('Failed to update status');
  return res.json();
}

export async function updatePlaybookStep(incidentId, actionIndex, completed) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/playbook`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_index: actionIndex, completed }),
  });
  if (!res.ok) throw new Error('Failed to update playbook');
  return res.json();
}

export async function triggerAIInvestigation(incidentId) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/ai-investigate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to run AI investigation');
  return res.json();
}

export async function fetchIncidentReport(incidentId, format = 'markdown') {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/report?format=${format}`);
  if (!res.ok) throw new Error('Failed to fetch report');
  return res.text();
}

export async function triggerScenario(scenario) {
  const res = await fetch(`${API_BASE}/simulator/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario }),
  });
  if (!res.ok) throw new Error('Failed to trigger scenario');
  return res.json();
}

export async function toggleSimulator(enabled) {
  const res = await fetch(`${API_BASE}/simulator/toggle?enabled=${enabled}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to toggle simulator');
  return res.json();
}

export async function askAIChat(query, incidentId = null, alertId = null) {
  const res = await fetch(`${API_BASE}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, incident_id: incidentId, alert_id: alertId }),
  });
  if (!res.ok) throw new Error('Failed to chat with AI analyst');
  return res.json();
}

export async function fetchAISettings() {
  const res = await fetch(`${API_BASE}/ai/settings`);
  if (!res.ok) throw new Error('Failed to fetch AI settings');
  return res.json();
}

export async function updateAISettings(data) {
  const res = await fetch(`${API_BASE}/ai/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update AI settings');
  return res.json();
}
