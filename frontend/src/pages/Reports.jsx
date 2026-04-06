import { useState, useEffect, useCallback } from 'react';
import { FileBarChart2, Download, RefreshCw, FileJson, FileText, Sparkles, AlertTriangle } from 'lucide-react';
import { listScans, listBuckets, getStats, reportJsonUrl, reportCsvUrl, aiGenerateReport } from '../services/api';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend } from 'recharts';

const RISK_COLORS = { critical:'#ff3366', high:'#ff8c00', medium:'#ffd700', low:'#00ff88', unknown:'#4a5980' };

export default function Reports() {
  const [scans, setScans]   = useState([]);
  const [stats, setStats]   = useState(null);
  const [buckets, setBuckets] = useState([]);
  const [selScan, setSelScan] = useState('');
  const [narrative, setNarrative] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [toast, setToast]   = useState(null);

  const showToast = (msg, type='info') => { setToast({msg,type}); setTimeout(()=>setToast(null),3000); };

  const load = useCallback(async () => {
    try {
      const [sc, st, bk] = await Promise.all([listScans(), getStats(), listBuckets()]);
      setScans(sc.data); setStats(st.data); setBuckets(bk.data);
      if (sc.data.length && !selScan) setSelScan(String(sc.data[0].id));
    } catch { showToast('Backend not reachable','danger'); }
  },[selScan]);

  useEffect(()=>{ load(); },[]);

  const handleAiReport = async () => {
    if (!selScan) return showToast('Select a scan','danger');
    setAiLoading(true); setNarrative('');
    try {
      const r = await aiGenerateReport(parseInt(selScan));
      setNarrative(r.data.narrative || r.data.message || JSON.stringify(r.data));
    } catch(e) {
      setNarrative('⚠ AI unavailable. Ensure Ollama is running: ollama serve && ollama pull llama3.2:3b');
    }
    setAiLoading(false);
  };

  // Aggregated chart data
  const riskDist = ['critical','high','medium','low','unknown'].map(r=>({
    name: r.charAt(0).toUpperCase()+r.slice(1),
    value: buckets.filter(b=>b.risk_level===r).length,
    color: RISK_COLORS[r],
  })).filter(d=>d.value>0);

  const permData = [
    { name:'LIST',   count: buckets.filter(b=>b.can_list).length },
    { name:'READ',   count: buckets.filter(b=>b.can_read).length },
    { name:'WRITE',  count: buckets.filter(b=>b.can_write).length },
    { name:'DELETE', count: buckets.filter(b=>b.can_delete).length },
  ];

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
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-cyber-muted text-sm mt-1">Export results and generate AI-powered narratives</p>
        </div>
        <button className="btn-ghost flex items-center gap-2" onClick={load}>
          <RefreshCw className="w-4 h-4"/> Refresh
        </button>
      </div>

      {/* Global summary cards */}
      {stats && (
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          {[
            { label:'Total Scans',       val: stats.total_scans,      color:'#00d4ff' },
            { label:'Buckets Found',     val: stats.total_buckets,    color:'#00ff88' },
            { label:'Vulnerable',        val: stats.total_vulnerable, color:'#ff3366' },
            { label:'Sensitive Secrets', val: stats.total_sensitive,  color:'#ffd700' },
          ].map(({label,val,color})=>(
            <div key={label} className="card">
              <p className="label">{label}</p>
              <p className="text-3xl font-bold tabular-nums" style={{color}}>{val.toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      {/* Charts row */}
      {buckets.length > 0 && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Risk distribution pie */}
          <div className="card">
            <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-cyber-red"/> Risk Distribution
            </h2>
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={riskDist} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                    paddingAngle={3} dataKey="value" label={({name,value})=>`${name}: ${value}`}
                    labelLine={false}>
                    {riskDist.map((e,i)=><Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{background:'#0f1629',border:'1px solid #1e2d52',borderRadius:'8px',fontSize:'12px'}}/>
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Permission bar chart */}
          <div className="card">
            <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
              <FileBarChart2 className="w-4 h-4 text-cyber-accent"/> Permission Exposure
            </h2>
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={permData} margin={{top:4,right:4,left:-20,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d52"/>
                  <XAxis dataKey="name" tick={{fill:'#c8d6f0',fontSize:11}}/>
                  <YAxis tick={{fill:'#4a5980',fontSize:11}}/>
                  <Tooltip contentStyle={{background:'#0f1629',border:'1px solid #1e2d52',borderRadius:'8px',fontSize:'12px'}}/>
                  <Bar dataKey="count" name="Buckets" radius={[4,4,0,0]}>
                    {permData.map((_,i)=>(
                      <Cell key={i} fill={['#00d4ff','#00ff88','#ff8c00','#ff3366'][i]}/>
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Export section */}
      <div className="card space-y-4">
        <h2 className="font-semibold text-white flex items-center gap-2">
          <Download className="w-4 h-4 text-cyber-accent"/> Export Report
        </h2>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="label">Select Scan</label>
            <select className="input" value={selScan} onChange={e=>setSelScan(e.target.value)}>
              <option value="">-- Choose scan --</option>
              {scans.map(s=>(
                <option key={s.id} value={s.id}>
                  #{s.id} — {s.name} ({s.buckets_found} buckets)
                </option>
              ))}
            </select>
          </div>
          <div className="flex gap-3 pt-5">
            <a href={selScan ? reportJsonUrl(selScan) : '#'}
              className={`btn-primary flex items-center gap-2 ${!selScan?'pointer-events-none opacity-40':''}`}
              download>
              <FileJson className="w-4 h-4"/> Export JSON
            </a>
            <a href={selScan ? reportCsvUrl(selScan) : '#'}
              className={`btn-ghost flex items-center gap-2 ${!selScan?'pointer-events-none opacity-40':''}`}
              download>
              <FileText className="w-4 h-4"/> Export CSV
            </a>
            <button className={`btn flex items-center gap-2 bg-cyber-purple/20 text-purple-300 border border-purple-500/30 hover:bg-cyber-purple/30 ${aiLoading?'opacity-60':''}`}
              onClick={handleAiReport} disabled={aiLoading || !selScan}>
              {aiLoading
                ? <div className="w-4 h-4 border-2 border-purple-400/40 border-t-purple-400 rounded-full animate-spin"/>
                : <Sparkles className="w-4 h-4"/>}
              AI Narrative
            </button>
          </div>
        </div>
      </div>

      {/* AI Narrative */}
      {narrative && (
        <div className="card border-purple-500/30 space-y-3 animate-slide-up">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-purple-400"/> AI Executive Summary
          </h3>
          <div className="text-sm text-cyber-text leading-7 whitespace-pre-wrap bg-cyber-panel rounded-lg p-4 border border-cyber-border">
            {narrative}
          </div>
        </div>
      )}

      {/* Recent scans table */}
      <div className="card">
        <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
          <FileBarChart2 className="w-4 h-4 text-cyber-accent"/> All Scans
        </h2>
        {scans.length === 0 ? (
          <p className="text-cyber-muted text-sm text-center py-8">No scans yet</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-cyber-border text-left">
                  {['Scan','Wordlist','Buckets','Status','Date','Export'].map(h=>(
                    <th key={h} className="pb-3 text-xs text-cyber-muted uppercase tracking-wider px-2 first:pl-0">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/50">
                {scans.map(s=>(
                  <tr key={s.id} className="hover:bg-cyber-panel/50">
                    <td className="py-3 px-2 first:pl-0">
                      <p className="font-medium text-white">{s.name}</p>
                      <p className="text-xs text-cyber-muted mono">#{s.id}</p>
                    </td>
                    <td className="py-3 px-2 text-xs mono text-cyber-muted truncate max-w-[120px]">{s.wordlist_name||'—'}</td>
                    <td className="py-3 px-2 text-lg font-bold text-cyber-green">{s.buckets_found||0}</td>
                    <td className="py-3 px-2">
                      <span className={`badge ${s.status==='done'?'badge-low':s.status==='running'?'badge-info':s.status==='error'?'badge-critical':'badge-unknown'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 px-2 text-xs text-cyber-muted">
                      {s.created_at ? new Date(s.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="py-3 px-2">
                      <div className="flex gap-2">
                        <a href={reportJsonUrl(s.id)} className="text-cyber-accent hover:text-white text-xs" download>JSON</a>
                        <a href={reportCsvUrl(s.id)}  className="text-cyber-muted hover:text-white text-xs" download>CSV</a>
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
