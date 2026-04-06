import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Zap, AlertTriangle, Eye, Upload, Play, Pause,
  StopCircle, TrendingUp, Globe, Lock, Unlock, Trash2, RefreshCw
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  createScan, listScans, pauseScan, resumeScan, stopScan,
  listWordlists, getStats, createWsConnection
} from '../services/api';

function MetricCard({ icon: Icon, label, value, color, glow }) {
  return (
    <div className={`card flex items-center gap-4 animate-fade-in ${glow ? 'card-glow' : ''}`}>
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0`}
           style={{ background: `${color}22`, border: `1px solid ${color}44` }}>
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <div>
        <p className="label">{label}</p>
        <p className="text-2xl font-bold text-white tabular-nums">{value.toLocaleString()}</p>
      </div>
    </div>
  );
}

function RiskBadge({ level }) {
  const map = {
    critical: 'badge-critical', high: 'badge-high',
    medium: 'badge-medium', low: 'badge-low', unknown: 'badge-unknown'
  };
  return <span className={map[level] || 'badge-unknown'}>{level}</span>;
}

function PermChip({ label, on }) {
  return <span className={on ? 'perm-on' : 'perm-off'}>{label}</span>;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats]       = useState({ total_scans:0, total_buckets:0, total_vulnerable:0, total_sensitive:0, critical:0, high:0 });
  const [wordlists, setWordlists] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [buckets, setBuckets]   = useState([]);
  const [chartData, setChartData] = useState([]);
  const [progress, setProgress] = useState({ tested:0, found:0, vulnerable:0, sensitive:0, pct:0, total:0 });
  const [scanForm, setScanForm] = useState({
    name: '', wordlist_id: '', direct_payloads: '', concurrency: 50,
    prefixes: '', suffixes: '', regions: 'us-east-1',
    anon_mode: true, write_test: false, delete_test: false,
    aws_key: '', aws_secret: ''
  });
  const [targetMode, setTargetMode] = useState('wordlist'); // 'wordlist' | 'quick'
  const [loading, setLoading]   = useState(false);
  const [toast, setToast]       = useState(null);
  const [termLogs, setTermLogs] = useState(["[SYS] S3-Hunter Pro initialized", "[SYS] Waiting for targets..."]);
  const wsRef = useRef(null);
  const chartRef = useRef([]);

  const showToast = (msg, type = 'info') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const fetchStats = useCallback(async () => {
    try {
      const [s, w] = await Promise.all([getStats(), listWordlists()]);
      setStats(s.data);
      setWordlists(w.data);
    } catch { /* backend may not be running */ }
  }, []);

  useEffect(() => {
    fetchStats();
    const ws = createWsConnection((msg) => {
      if (msg.type === 'scan_started') {
        setActiveScan(prev => ({ ...prev, status: 'running' }));
        setTermLogs(p => ["[SYS] Engines engaged...", "[*] ThreadPool activated: MAX concurrency", "[+] Handshake initiated...", ...p].slice(0, 50));
      }
      if (msg.type === 'progress') {
        setProgress({
          tested: msg.stats.tested, found: msg.stats.found,
          vulnerable: msg.stats.vulnerable, sensitive: msg.stats.sensitive,
          pct: msg.progress, total: msg.total,
        });
        chartRef.current = [...chartRef.current.slice(-29), {
          t: msg.stats.tested, found: msg.stats.found, vuln: msg.stats.vulnerable
        }];
        setChartData([...chartRef.current]);
      }
      
      if (msg.type === 'engine_log') {
        setTermLogs(p => [msg.message, ...p].slice(0, 100));
      }
      
      if (msg.type === 'bucket_found') {
        setBuckets(prev => [msg.bucket, ...prev].slice(0, 100));
        const prefix = msg.bucket.is_takeover_candidate ? "🚩" : "🪣";
        const label = msg.bucket.is_takeover_candidate ? "TAKEOVER" : msg.bucket.risk_level.toUpperCase();
        showToast(`${prefix} Found: ${msg.bucket.name} [${label}]`,
          msg.bucket.risk_level === 'critical' ? 'danger' : 'success');
      }
      
      if (msg.type === 'scan_complete') {
        setActiveScan(prev => ({ ...prev, status: msg.status }));
        fetchStats();
        showToast('✅ Scan complete!', 'success');
        setTermLogs(p => ["[SYS] Scan sequence completed natively.", ...p].slice(0, 50));
      }
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [fetchStats]);

  const handleStartScan = async () => {
    if (!scanForm.name) return showToast('Enter a scan name', 'danger');
    if (targetMode === 'wordlist' && !scanForm.wordlist_id) return showToast('Select a wordlist', 'danger');
    if (targetMode === 'quick' && !scanForm.direct_payloads) return showToast('Enter at least 1 payload', 'danger');
    setLoading(true);
    setBuckets([]);
    chartRef.current = [];
    setChartData([]);
    setProgress({ tested:0, found:0, vulnerable:0, sensitive:0, pct:0, total:0 });
    try {
      const payload = {
        ...scanForm,
        wordlist_id: targetMode === 'wordlist' ? parseInt(scanForm.wordlist_id) : undefined,
        direct_payloads: targetMode === 'quick' ? scanForm.direct_payloads : undefined,
        concurrency: parseInt(scanForm.concurrency),
        aws_key: !scanForm.anon_mode ? scanForm.aws_key : undefined,
        aws_secret: !scanForm.anon_mode ? scanForm.aws_secret : undefined,
      };
      const res = await createScan(payload);
      setActiveScan({ id: res.data.scan_id, name: scanForm.name, status: 'running' });
      showToast('🚀 Scan started!', 'success');
    } catch(e) {
      showToast('Failed to start scan: ' + (e.response?.data?.detail || e.message), 'danger');
    } finally { setLoading(false); }
  };

  const handlePause  = async () => { if(activeScan) { await pauseScan(activeScan.id); setActiveScan(p=>({...p,status:'paused'})); }};
  const handleResume = async () => { if(activeScan) { await resumeScan(activeScan.id); setActiveScan(p=>({...p,status:'running'})); }};
  const handleStop   = async () => { if(activeScan) { await stopScan(activeScan.id); setActiveScan(p=>({...p,status:'stopped'})); }};

  const riskColor = (level) => ({
    critical:'#ff3366', high:'#ff8c00', medium:'#ffd700', low:'#00ff88', unknown:'#4a5980'
  }[level] || '#4a5980');

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 toast-enter px-5 py-3 rounded-xl border text-sm font-medium shadow-lg
          ${toast.type==='danger' ? 'bg-cyber-red/20 border-cyber-red/40 text-cyber-red'
          : toast.type==='success' ? 'bg-cyber-green/20 border-cyber-green/40 text-cyber-green'
          : 'bg-cyber-accent/20 border-cyber-accent/40 text-cyber-accent'}`}>
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-cyber-muted text-sm mt-1">Real-time S3 bucket security assessment</p>
        </div>
        <button onClick={fetchStats} className="btn-ghost flex items-center gap-2">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard icon={Globe}         label="Buckets Found"   value={stats.total_buckets}    color="#00d4ff" />
        <MetricCard icon={AlertTriangle} label="Vulnerable"      value={stats.total_vulnerable}  color="#ff3366" glow />
        <MetricCard icon={Shield}        label="Critical Risk"   value={stats.critical}          color="#ff3366" />
        <MetricCard icon={Eye}           label="Sensitive Files" value={stats.total_sensitive}   color="#ffd700" />
      </div>

      {/* Scan form + progress */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* New Scan */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyber-accent" /> New Scan
          </h2>

          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="label">Scan Name</label>
              <input className="input" placeholder="e.g. ACME Corp Assessment"
                value={scanForm.name} onChange={e=>setScanForm(p=>({...p,name:e.target.value}))} />
            </div>
            <div className="col-span-2">
              <div className="flex items-center justify-between mb-1.5">
                <label className="label mb-0">Target Mode</label>
                <div className="flex gap-1 bg-cyber-bg p-0.5 rounded border border-cyber-border">
                  <button className={`px-3 py-1 rounded text-xs font-medium transition-all ${targetMode==='wordlist'?'bg-cyber-panel text-white shadow-sm border border-cyber-border':'text-cyber-muted'}`}
                    onClick={() => setTargetMode('wordlist')}>Wordlist</button>
                  <button className={`px-3 py-1 rounded text-xs font-medium transition-all ${targetMode==='quick'?'bg-cyber-panel text-white shadow-sm border border-cyber-border':'text-cyber-muted'}`}
                    onClick={() => setTargetMode('quick')}>Quick Payloads</button>
                </div>
              </div>
              
              {targetMode === 'wordlist' ? (
                <select className="input" value={scanForm.wordlist_id}
                  onChange={e=>setScanForm(p=>({...p,wordlist_id:e.target.value}))}>
                  <option value="">-- Select wordlist --</option>
                  {wordlists.map(w=><option key={w.id} value={w.id}>{w.name} ({w.line_count.toLocaleString()} lines)</option>)}
                </select>
              ) : (
                <textarea className="input text-sm resize-none" rows={3} placeholder="Enter bucket names directly (e.g. acme-backend, test-bucket)&#10;One per line..."
                  value={scanForm.direct_payloads} onChange={e=>setScanForm(p=>({...p,direct_payloads:e.target.value}))} />
              )}
            </div>
            <div>
              <label className="label">Prefixes</label>
              <input className="input" placeholder="dev,staging,prod"
                value={scanForm.prefixes} onChange={e=>setScanForm(p=>({...p,prefixes:e.target.value}))} />
            </div>
            <div>
              <label className="label">Suffixes</label>
              <input className="input" placeholder="backup,data,files"
                value={scanForm.suffixes} onChange={e=>setScanForm(p=>({...p,suffixes:e.target.value}))} />
            </div>
            <div>
              <label className="label">Regions</label>
              <input className="input" placeholder="us-east-1,eu-west-1"
                value={scanForm.regions} onChange={e=>setScanForm(p=>({...p,regions:e.target.value}))} />
            </div>
            <div>
              <label className="label">Concurrency</label>
              <input className="input" type="number" min="1" max="200"
                value={scanForm.concurrency} onChange={e=>setScanForm(p=>({...p,concurrency:e.target.value}))} />
            </div>
          </div>

          {/* Toggles */}
          <div className="flex flex-wrap gap-3 pt-1">
            {[
              { key:'anon_mode',   label:'Anonymous Mode', safe: true },
              { key:'write_test',  label:'⚠ Write Test',   safe: false },
              { key:'delete_test', label:'⚠ Delete Test',  safe: false },
            ].map(({key,label,safe})=>(
              <button key={key}
                className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border transition-all
                  ${scanForm[key]
                    ? safe ? 'bg-cyber-green/20 border-cyber-green/40 text-cyber-green'
                           : 'bg-cyber-red/20 border-cyber-red/40 text-cyber-red'
                    : 'bg-transparent border-cyber-border text-cyber-muted hover:border-cyber-accent/30'}`}
                onClick={()=>setScanForm(p=>({...p,[key]:!p[key]}))}>
                {scanForm[key] ? <Unlock className="w-3 h-3"/> : <Lock className="w-3 h-3"/>} {label}
              </button>
            ))}
          </div>

          {/* Auth fields */}
          {!scanForm.anon_mode && (
            <div className="grid grid-cols-2 gap-3 pt-1 border-t border-cyber-border">
              <div>
                <label className="label">AWS Access Key</label>
                <input className="input mono" placeholder="AKIA..." type="password"
                  value={scanForm.aws_key} onChange={e=>setScanForm(p=>({...p,aws_key:e.target.value}))} />
              </div>
              <div>
                <label className="label">AWS Secret Key</label>
                <input className="input mono" placeholder="••••••••" type="password"
                  value={scanForm.aws_secret} onChange={e=>setScanForm(p=>({...p,aws_secret:e.target.value}))} />
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex gap-3 pt-2">
            <button className="btn-primary flex items-center gap-2 flex-1 justify-center"
              onClick={handleStartScan} disabled={loading || activeScan?.status==='running'}>
              <Play className="w-4 h-4" /> {loading ? 'Starting…' : 'Start Scan'}
            </button>
            {activeScan?.status==='running' && (
              <button className="btn-ghost flex items-center gap-2" onClick={handlePause}>
                <Pause className="w-4 h-4" /> Pause
              </button>
            )}
            {activeScan?.status==='paused' && (
              <button className="btn-success flex items-center gap-2" onClick={handleResume}>
                <Play className="w-4 h-4" /> Resume
              </button>
            )}
            {activeScan && ['running','paused'].includes(activeScan.status) && (
              <button className="btn-danger flex items-center gap-2" onClick={handleStop}>
                <StopCircle className="w-4 h-4" /> Stop
              </button>
            )}
          </div>
        </div>

        {/* Live Progress */}
        <div className="card space-y-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyber-accent" /> Live Progress
            {activeScan?.status==='running' && (
              <span className="ml-auto flex items-center gap-2 text-xs text-cyber-green font-bold tracking-widest relative">
                <div className="w-4 h-4 rounded-full border border-cyber-green/50 relative overflow-hidden flex items-center justify-center shrink-0">
                  <div className="radar-sweep"></div>
                  <div className="w-1.5 h-1.5 bg-cyber-green rounded-full z-10"></div>
                </div>
                HUNTING
              </span>
            )}
          </h2>

          {/* Progress bar */}
          <div>
            <div className="flex justify-between text-xs text-cyber-muted mb-2">
              <span>{progress.tested.toLocaleString()} tested</span>
              <span>{progress.pct}%</span>
            </div>
            <div className="risk-bar">
              <div className="risk-fill progress-glow bg-gradient-to-r from-cyber-accent to-cyber-purple"
                style={{width:`${progress.pct}%`}} />
            </div>
          </div>

          {/* Live stats */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label:'Tested',      val:progress.tested,     color:'#00d4ff' },
              { label:'Found',       val:progress.found,      color:'#00ff88' },
              { label:'Vulnerable',  val:progress.vulnerable, color:'#ff3366' },
              { label:'Sensitive',   val:progress.sensitive,  color:'#ffd700' },
            ].map(({label,val,color})=>(
              <div key={label} className="bg-cyber-panel rounded-lg p-3 border border-cyber-border">
                <p className="text-xs text-cyber-muted">{label}</p>
                <p className="text-xl font-bold mt-0.5 tabular-nums" style={{color}}>{val.toLocaleString()}</p>
              </div>
            ))}
          </div>

          {/* Mini chart */}
          {chartData.length > 1 && (
            <div className="h-28">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{top:4,right:4,left:-28,bottom:0}}>
                  <defs>
                    <linearGradient id="gFound" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#00ff88" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00ff88" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="gVuln" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ff3366" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ff3366" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d52" />
                  <XAxis hide />
                  <YAxis tick={{fill:'#4a5980',fontSize:10}} />
                  <Tooltip contentStyle={{background:'#0f1629',border:'1px solid #1e2d52',borderRadius:'8px',fontSize:'12px'}} />
                  <Area type="monotone" dataKey="found" stroke="#00ff88" fill="url(#gFound)" strokeWidth={2} dot={false} name="Found" />
                  <Area type="monotone" dataKey="vuln"  stroke="#ff3366" fill="url(#gVuln)"  strokeWidth={2} dot={false} name="Vuln" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
          {chartData.length === 0 && (
            <div className="h-28 flex items-center justify-center border border-dashed border-cyber-border rounded-lg">
              <p className="text-cyber-muted text-xs">Chart appears once scanning starts</p>
            </div>
          )}

          {/* Hacker Terminal stream */}
          <div className="mt-4 rounded-lg border border-cyber-border terminal-console overflow-hidden flex flex-col h-32 relative">
             <div className="absolute top-0 w-full bg-cyber-bg/80 backdrop-blur-sm border-b border-cyber-accent/20 px-2 py-1 flex items-center gap-2 z-10">
                <div className="flex gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-cyber-red/80"/>
                  <div className="w-2 h-2 rounded-full bg-cyber-yellow/80"/>
                  <div className="w-2 h-2 rounded-full bg-cyber-green/80"/>
                </div>
                <span className="text-[10px] text-cyber-muted mono uppercase tracking-widest font-bold">Raw Logs</span>
             </div>
             <div className="flex-1 overflow-hidden pt-8 pb-3 px-3 relative">
               <div className="absolute bottom-3 left-3 right-3 flex flex-col-reverse text-[11px] mono text-cyber-green leading-[18px]">
                 {termLogs.map((log, i) => (
                   <div key={i} className={`truncate opacity-${Math.max(100 - (i*15), 10)}`}>
                     {log.startsWith('[!!!]') ? <span className="text-cyber-red font-bold animate-pulse">{log}</span> : log}
                   </div>
                 ))}
               </div>
             </div>
          </div>
        </div>
      </div>

      {/* Live bucket feed */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyber-accent" /> Discovered Buckets
            <span className="ml-2 text-xs bg-cyber-accent/20 text-cyber-accent px-2 py-0.5 rounded-full">{buckets.length}</span>
          </h2>
          {buckets.length > 0 && (
            <button className="btn-ghost text-xs flex items-center gap-1"
              onClick={() => navigate('/explorer')}>
              View in Explorer →
            </button>
          )}
        </div>

        {buckets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="w-16 h-16 rounded-2xl bg-cyber-card border border-cyber-border flex items-center justify-center mb-4">
              <Globe className="w-7 h-7 text-cyber-muted" />
            </div>
            <p className="text-cyber-muted text-sm">No buckets found yet. Start a scan above.</p>
          </div>
        ) : (
          <div className="space-y-4 max-h-96 overflow-y-auto pr-2 pb-2">
            {buckets.map((b, i) => (
              <div key={i} className="server-blade flex items-center gap-3 px-4 py-3 rounded-lg transition-all animate-slide-up group">
                <div className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse" style={{background: riskColor(b.risk_level), boxShadow: `0 0 10px ${riskColor(b.risk_level)}`}} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-bold text-white mono truncate tracking-wide">
                    {b.is_takeover_candidate && <span className="text-cyber-accent mr-1 font-black">[TAKEOVER]</span>}
                    {b.name}
                  </p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <p className="text-[10px] text-cyber-muted mono">{b.region} | {b.object_count} obj</p>
                    {b.proxy_detected?.map(p => (
                      <span key={p} className="text-[9px] bg-cyber-bg border border-cyber-border text-cyber-accent px-1 rounded uppercase font-bold tracking-tighter">
                        {p} Detected
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <PermChip label="LIST"   on={b.can_list} />
                  <PermChip label="READ"   on={b.can_read} />
                  <PermChip label="WRITE"  on={b.can_write} />
                  <PermChip label="DEL"    on={b.can_delete} />
                </div>
                <RiskBadge level={b.risk_level} />
                {b.sensitive_count > 0 && (
                  <span className="badge bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/40 shadow-[0_0_10px_rgba(255,215,0,0.2)]">! {b.sensitive_count}</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
