import { useState, useEffect, useCallback } from 'react';
import { History, Play, Trash2, RefreshCw, Clock, CheckCircle, XCircle, PauseCircle } from 'lucide-react';
import { listScans, deleteScan, resumeScan, stopScan } from '../services/api';

function statusIcon(s) {
  if (s==='running')  return <span className="flex items-center gap-1.5 text-cyber-green"><span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse"/>Running</span>;
  if (s==='paused')   return <span className="flex items-center gap-1.5 text-cyber-yellow"><PauseCircle className="w-3.5 h-3.5"/>Paused</span>;
  if (s==='done')     return <span className="flex items-center gap-1.5 text-cyber-green"><CheckCircle className="w-3.5 h-3.5"/>Done</span>;
  if (s==='stopped')  return <span className="flex items-center gap-1.5 text-cyber-muted"><XCircle className="w-3.5 h-3.5"/>Stopped</span>;
  if (s==='error')    return <span className="flex items-center gap-1.5 text-cyber-red"><XCircle className="w-3.5 h-3.5"/>Error</span>;
  return <span className="text-cyber-muted text-xs capitalize">{s}</span>;
}

export default function SessionHistory() {
  const [scans, setScans]   = useState([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast]   = useState(null);

  const showToast = (msg, type='info') => { setToast({msg,type}); setTimeout(()=>setToast(null),3000); };

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await listScans(); setScans(r.data); }
    catch { showToast('Backend not reachable','danger'); }
    finally { setLoading(false); }
  },[]);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (id, name) => {
    if (!confirm(`Delete scan "${name}"? This will remove all associated buckets and findings.`)) return;
    try { await deleteScan(id); setScans(p=>p.filter(s=>s.id!==id)); showToast('Deleted','success'); }
    catch { showToast('Delete failed','danger'); }
  };

  const handleResume = async (id) => {
    try { await resumeScan(id); showToast('Resumed','success'); load(); }
    catch(e) { showToast(e.response?.data?.detail||'Cannot resume — start a new scan','danger'); }
  };

  const handleStop = async (id) => {
    try { await stopScan(id); load(); showToast('Stopped','success'); }
    catch { showToast('Stop failed','danger'); }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 toast-enter px-5 py-3 rounded-xl border text-sm font-medium shadow-lg
          ${toast.type==='danger'?'bg-cyber-red/20 border-cyber-red/40 text-cyber-red'
          :toast.type==='success'?'bg-cyber-green/20 border-cyber-green/40 text-cyber-green'
          :'bg-cyber-accent/20 border-cyber-accent/40 text-cyber-accent'}`}>{toast.msg}</div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Session History</h1>
          <p className="text-cyber-muted text-sm mt-1">All past and active scan sessions</p>
        </div>
        <button className="btn-ghost flex items-center gap-2" onClick={load}>
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      <div className="card">
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-8 h-8 border-2 border-cyber-accent/40 border-t-cyber-accent rounded-full animate-spin"/>
          </div>
        ) : scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <History className="w-12 h-12 text-cyber-muted mb-4" />
            <p className="text-white font-medium">No scan sessions yet</p>
            <p className="text-cyber-muted text-sm mt-1">Start a scan from the Dashboard</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-cyber-border text-left">
                  {['ID','Name','Wordlist','Progress','Checkpoint','Buckets Found','Status','Actions'].map(h=>(
                    <th key={h} className="pb-3 text-xs font-medium text-cyber-muted uppercase tracking-wider px-2 first:pl-0">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/50">
                {scans.map(s=>(
                  <tr key={s.id} className="hover:bg-cyber-panel/50 transition-colors group">
                    <td className="py-3 px-2 first:pl-0 text-xs text-cyber-muted mono">#{s.id}</td>
                    <td className="py-3 px-2">
                      <p className="text-sm font-medium text-white">{s.name}</p>
                      <p className="text-xs text-cyber-muted">{s.created_at ? new Date(s.created_at).toLocaleString() : '—'}</p>
                    </td>
                    <td className="py-3 px-2">
                      <p className="text-xs mono text-cyber-text truncate max-w-[120px]">{s.wordlist_name||'—'}</p>
                      <p className="text-xs text-cyber-muted">{s.total_lines?.toLocaleString()||0} lines</p>
                    </td>
                    <td className="py-3 px-2">
                      <div className="flex items-center gap-2">
                        <div className="risk-bar w-20 flex-shrink-0">
                          <div className="risk-fill bg-cyber-accent" style={{width:`${s.progress||0}%`}}/>
                        </div>
                        <span className="text-xs text-cyber-muted tabular-nums">{s.progress||0}%</span>
                      </div>
                    </td>
                    <td className="py-3 px-2 text-xs mono text-cyber-muted">
                      L{s.checkpoint?.toLocaleString()||0}
                    </td>
                    <td className="py-3 px-2">
                      <span className="text-lg font-bold text-cyber-green">{s.buckets_found||0}</span>
                    </td>
                    <td className="py-3 px-2 text-xs">{statusIcon(s.status)}</td>
                    <td className="py-3 px-2">
                      <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        {s.status==='paused' && (
                          <button className="text-cyber-green hover:text-white transition-colors" onClick={()=>handleResume(s.id)} title="Resume">
                            <Play className="w-3.5 h-3.5"/>
                          </button>
                        )}
                        {s.status==='running' && (
                          <button className="text-cyber-yellow hover:text-white transition-colors" onClick={()=>handleStop(s.id)} title="Stop">
                            <XCircle className="w-3.5 h-3.5"/>
                          </button>
                        )}
                        <button className="text-cyber-muted hover:text-cyber-red transition-colors" onClick={()=>handleDelete(s.id,s.name)} title="Delete">
                          <Trash2 className="w-3.5 h-3.5"/>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
