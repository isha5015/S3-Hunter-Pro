// S3-Hunter Pro — Axios + WebSocket API client
import axios from 'axios';

const API = axios.create({ baseURL: 'http://localhost:8000' });

// ── Scans ─────────────────────────────────────────────────────────────────
export const createScan    = (data)    => API.post('/api/scans', data);
export const listScans     = ()        => API.get('/api/scans');
export const getScan       = (id)      => API.get(`/api/scans/${id}`);
export const pauseScan     = (id)      => API.post(`/api/scans/${id}/pause`);
export const resumeScan    = (id)      => API.post(`/api/scans/${id}/resume`);
export const stopScan      = (id)      => API.post(`/api/scans/${id}/stop`);
export const deleteScan    = (id)      => API.delete(`/api/scans/${id}`);
export const retestBucket  = (bucketName) => API.post('/api/scans/retest', { bucket_name: bucketName });

// ── Buckets ───────────────────────────────────────────────────────────────
export const listBuckets      = (scanId) => API.get('/api/buckets', { params: scanId ? { scan_id: scanId } : {} });
export const getBucketFiles   = (id, prefix) => API.get(`/api/buckets/${id}/files`, { params: prefix ? { prefix } : {} });
export const getBucketFindings = (id) => API.get(`/api/buckets/${id}/findings`);
export const downloadFile     = (bucketId, key) =>
  `http://localhost:8000/api/buckets/${bucketId}/download?key=${encodeURIComponent(key)}`;
export const previewFile      = (bucketId, key) =>
  `http://localhost:8000/api/buckets/${bucketId}/download?inline=true&key=${encodeURIComponent(key)}`;

// ── Wordlists ─────────────────────────────────────────────────────────────
export const listWordlists    = ()       => API.get('/api/wordlists');
export const uploadWordlist   = (file)   => {
  const fd = new FormData();
  fd.append('file', file);
  return API.post('/api/wordlists/upload', fd);
};
export const createCustomWl   = (name, content) => API.post('/api/wordlists/custom', { name, content });
export const deleteWordlist   = (id)     => API.delete(`/api/wordlists/${id}`);

// ── Reports ───────────────────────────────────────────────────────────────
export const reportJsonUrl = (scanId) => `http://localhost:8000/api/reports/${scanId}/json`;
export const reportCsvUrl  = (scanId) => `http://localhost:8000/api/reports/${scanId}/csv`;

// ── Stats ─────────────────────────────────────────────────────────────────
export const getStats = () => API.get('/api/stats');

// ── AI ────────────────────────────────────────────────────────────────────
export const getAiStatus        = ()        => API.get('/api/ai/status');
export const aiAnalyzeBucket    = (bucketId) => API.post(`/api/ai/analyze/${bucketId}`);
export const aiSuggestConfig    = (desc)    => API.post('/api/ai/suggest-config', { description: desc });
export const aiChat             = (msg, ctx) => API.post('/api/ai/chat', { message: msg, context: ctx });
export const aiGenerateReport   = (scanId)  => API.post(`/api/ai/report/${scanId}`);

// ── WebSocket ─────────────────────────────────────────────────────────────
export function createWsConnection(onMessage) {
  const ws = new WebSocket('ws://localhost:8000/ws');
  ws.onopen    = () => { ws.send(JSON.stringify({ type: 'ping' })); };
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)); } catch {} };
  ws.onerror   = (e) => console.error('WS error:', e);

  // keep‑alive ping every 25 s
  const timer = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
  }, 25000);
  ws.onclose = () => clearInterval(timer);
  return ws;
}
