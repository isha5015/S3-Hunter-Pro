import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  FolderSearch, Folder, File as FileIcon, Download, Shield, AlertTriangle,
  ChevronRight, Search, Eye, RefreshCw, X, HardDrive, Filter, Image as ImageIcon,
  FileText, Activity, Bot, Terminal
} from 'lucide-react';
import { listBuckets, getBucketFiles, getBucketFindings, downloadFile, previewFile, aiAnalyzeBucket } from '../services/api';

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024*1024) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1024/1024).toFixed(2)} MB`;
}

function RiskBadge({ level, onClick }) {
  const cls = { critical:'badge-critical', high:'badge-high', medium:'badge-medium', low:'badge-low', unknown:'badge-unknown' };
  return <span className={`${cls[level]} cursor-pointer hover:opacity-80`} onClick={onClick}>{level}</span>;
}

function PermChip({ label, on }) {
  return <span className={on ? 'perm-on flex-1 text-center' : 'perm-off flex-1 text-center'}>{label}</span>;
}

const getFileIcon = (mime, key) => {
  const k = key.toLowerCase();
  if (k.endsWith('.png') || k.endsWith('.jpg') || k.endsWith('.svg') || k.endsWith('.jpeg')) return ImageIcon;
  if (k.endsWith('.txt') || k.endsWith('.json') || k.endsWith('.md') || k.endsWith('.csv')) return FileText;
  return FileIcon;
}

export default function BucketExplorer() {
  const [buckets, setBuckets]     = useState([]);
  const [selected, setSelected]   = useState(null);
  const [files, setFiles]         = useState([]);
  const [findings, setFindings]   = useState([]);
  const [searchQ, setSearchQ]     = useState('');
  
  // Navigation & UI state
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [currentPath, setCurrentPath]   = useState([]); 
  const [preview, setPreview]           = useState(null);
  const [vulnModal, setVulnModal]       = useState(null);
  
  // AI State
  const [aiResult, setAiResult]   = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  
  // Filters
  const [filterRisk, setFilterRisk] = useState('all');
  const [filterPerm, setFilterPerm] = useState('all'); // list, read, write, delete
  const [bucketSearch, setBucketSearch] = useState('');

  useEffect(() => {
    listBuckets().then(r => setBuckets(r.data)).catch(() => {});
  }, []);

  const selectBucket = useCallback(async (b) => {
    setSelected(b); setFiles([]); setFindings([]); setAiResult(null); setCurrentPath([]); setPreview(null);
    setLoadingFiles(true);
    try {
      const [fRes, findRes] = await Promise.all([getBucketFiles(b.id, ''), getBucketFindings(b.id)]);
      setFiles(fRes.data.files);
      setFindings(findRes.data);
    } catch {}
    setLoadingFiles(false);
  }, []);

  const runAiAnalysis = async () => {
    if (!selected) return;
    setAiLoading(true); setAiResult(null);
    try {
      const r = await aiAnalyzeBucket(selected.id);
      setAiResult(r.data);
    } catch(e) {
      setAiResult({ error: e.response?.data?.detail || 'AI unavailable. Start Ollama' });
    }
    setAiLoading(false);
  };

  // Filter buckets sidebar
  const visibleBuckets = useMemo(() => {
    return buckets.filter(b => {
      if (filterRisk !== 'all' && b.risk_level !== filterRisk) return false;
      if (filterPerm !== 'all') {
        if (filterPerm === 'list' && !b.can_list) return false;
        if (filterPerm === 'read' && !b.can_read) return false;
        if (filterPerm === 'write' && !b.can_write) return false;
        if (filterPerm === 'delete' && !b.can_delete) return false;
      }
      if (bucketSearch && !b.name.toLowerCase().includes(bucketSearch.toLowerCase()) && !(b.payload_used||'').toLowerCase().includes(bucketSearch.toLowerCase())) return false;
      return true;
    });
  }, [buckets, filterRisk, filterPerm, bucketSearch]);

  // File explorer active folder logic
  const currentItems = useMemo(() => {
    if (!files.length) return [];
    
    // Convert flat keys to current directory contents
    const curPrefix = currentPath.length > 0 ? currentPath.join('/') + '/' : '';
    const items = new Map();
    
    files.forEach(f => {
      if (!f.key.startsWith(curPrefix)) return;
      if (searchQ && !f.key.toLowerCase().includes(searchQ.toLowerCase())) return;

      const relative = f.key.slice(curPrefix.length);
      const isFolder = relative.includes('/');
      const name = isFolder ? relative.split('/')[0] : relative;
      
      if (!name) return; // Exact folder match itself

      if (isFolder) {
        if (!items.has(name)) items.set(name, { isDir: true, name, itemsCount: 1 });
        else items.get(name).itemsCount++;
      } else {
        items.set(name, { isDir: false, name, ...f });
      }
    });

    return Array.from(items.values()).sort((a,b) => {
      if (a.isDir && !b.isDir) return -1;
      if (!a.isDir && b.isDir) return 1;
      return a.name.localeCompare(b.name);
    });
  }, [files, currentPath, searchQ]);

  const riskColor = (l) => ({ critical:'#ff3366',high:'#ff8c00',medium:'#ffd700',low:'#00ff88',unknown:'#4a5980' }[l]||'#4a5980');

  return (
    <div className="flex gap-4 h-[calc(100vh-6rem)] animate-fade-in relative">
      
      {/* Previews ModalOverlay */}
      {preview && (
        <div className="fixed inset-0 bg-cyber-bg/90 backdrop-blur-sm z-50 flex items-center justify-center p-8 animate-fade-in">
          <div className="bg-cyber-panel border border-cyber-border rounded-xl shadow-2xl w-full max-w-5xl h-full max-h-[85vh] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-cyber-border bg-cyber-card">
              <div className="min-w-0 flex-1">
                <h3 className="font-semibold text-white mono truncate">{preview.key}</h3>
                <p className="text-xs text-cyber-muted mt-1">{formatBytes(preview.size)} • {preview.content_type}</p>
              </div>
              <div className="flex items-center gap-3">
                <a href={downloadFile(selected.id, preview.key)} download className="btn-ghost flex items-center gap-2">
                  <Download className="w-4 h-4"/> Download
                </a>
                <button onClick={()=>setPreview(null)} className="btn-ghost text-cyber-muted hover:text-white p-2">
                  <X className="w-5 h-5"/>
                </button>
              </div>
            </div>
            <div className="flex-1 bg-cyber-bg overflow-hidden relative">
              <iframe
                title="preview"
                src={previewFile(selected.id, preview.key)}
                className="w-full h-full border-0 bg-white"
                sandbox="allow-same-origin allow-scripts"
              />
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability Modal */}
      {vulnModal && (
        <div className="fixed inset-0 bg-cyber-bg/90 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-cyber-panel border border-cyber-accent/30 rounded-xl shadow-2xl max-w-md w-full p-6 relative">
            <div className="absolute top-4 right-4">
              <button onClick={()=>setVulnModal(null)} className="text-cyber-muted hover:text-white"><X className="w-5 h-5"/></button>
            </div>
            <div className="w-12 h-12 rounded-full flex items-center justify-center bg-cyber-red/20 mb-4">
              <AlertTriangle className="w-6 h-6 text-cyber-red"/>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">{vulnModal.level.toUpperCase()} Severity Exposure</h3>
            <p className="text-sm text-cyber-text leading-relaxed">
              This bucket was flagged as <span className="font-bold text-white">{vulnModal.level}</span> because it has <span className="font-bold text-white mono">{vulnModal.perm}</span> permissions enabled for anonymous/unauthorized access.
            </p>
            <div className="mt-4 bg-cyber-card p-3 rounded-lg border border-cyber-border">
              <p className="text-xs text-cyber-muted mb-1">Exploitation Context:</p>
              <p className="text-xs text-white">
                {vulnModal.perm === 'WRITE' ? 'Attackers can upload malicious files, deface websites hosted here, or use it to host malware.' 
                : vulnModal.perm === 'DELETE' ? 'Attackers can permanently delete your company data leading to denial of service.'
                : vulnModal.perm === 'READ' ? 'Attackers can read private files directly by knowing their exact name.'
                : 'Attackers can recursively list and discover all hidden files and architecture inside this bucket.'}
              </p>
            </div>
            <button className="btn-primary w-full mt-6" onClick={()=>setVulnModal(null)}>Close</button>
          </div>
        </div>
      )}

      {/* Left: Bucket list & Filters */}
      <div className="w-72 flex-shrink-0 card overflow-hidden flex flex-col p-0">
        <div className="p-4 border-b border-cyber-border">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold text-white flex items-center gap-2 text-sm">
              <HardDrive className="w-4 h-4 text-cyber-accent" /> Discovered Buckets
              <span className="text-xs bg-cyber-accent/20 text-cyber-accent px-2 py-0.5 rounded-full">{visibleBuckets.length}</span>
            </h2>
            <button className="text-cyber-muted hover:text-cyber-text" onClick={() => listBuckets().then(r=>setBuckets(r.data))}>
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
          
          <div className="space-y-2 mt-4">
            <div className="flex items-center gap-2">
              <Filter className="w-3 h-3 text-cyber-muted"/>
              <select className="input text-xs py-1.5 px-2 bg-cyber-bg" value={filterRisk} onChange={e=>setFilterRisk(e.target.value)}>
                <option value="all">All Risks</option>
                <option value="critical">Critical Risk</option>
                <option value="high">High Risk</option>
                <option value="medium">Medium Risk</option>
                <option value="low">Low Risk</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-3 h-3 text-cyber-muted"/>
              <select className="input text-xs py-1.5 px-2 bg-cyber-bg" value={filterPerm} onChange={e=>setFilterPerm(e.target.value)}>
                <option value="all">All Permissions</option>
                <option value="list">Can LIST</option>
                <option value="read">Can READ</option>
                <option value="write">Can WRITE</option>
                <option value="delete">Can DELETE</option>
              </select>
            </div>
          </div>
          <div className="mt-3 relative">
             <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-cyber-muted" />
             <input className="input text-xs pl-8 py-1.5 bg-cyber-bg" placeholder="Filter by Name/Payload..."
               value={bucketSearch} onChange={e=>setBucketSearch(e.target.value)} />
          </div>
        </div>

        <div className="overflow-y-auto flex-1 p-2 space-y-1">
          {visibleBuckets.length === 0 && (
            <p className="text-cyber-muted text-xs text-center py-8">No matching buckets.</p>
          )}
          {visibleBuckets.map(b => (
            <button key={b.id}
              onClick={() => selectBucket(b)}
              className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all group
                ${selected?.id===b.id
                  ? 'bg-cyber-accent/10 border-cyber-accent/50 text-cyber-accent shadow-[inset_2px_0_0_#00d4ff]'
                  : 'border-transparent hover:bg-cyber-card hover:border-cyber-border'}`}>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{background:riskColor(b.risk_level)}} />
                <span className="text-xs font-medium mono truncate flex-1 leading-5">{b.name}</span>
              </div>
              <div className="flex flex-col gap-1 mt-1.5 ml-3.5">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-cyber-muted mono">{b.region}</span>
                  {b.sensitive_count > 0 && <span className="text-[10px] font-bold text-cyber-yellow">⚠ {b.sensitive_count} sec</span>}
                </div>
                {b.payload_used && (
                  <span className="text-[10px] text-cyber-muted/70 truncate">Via: {b.payload_used}</span>
                )}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Right: File explorer UI */}
      <div className="flex-1 flex flex-col gap-3 min-w-0">
        {!selected ? (
          <div className="card flex-1 flex flex-col items-center justify-center text-center">
            <FolderSearch className="w-14 h-14 text-cyber-muted mb-4" />
            <h3 className="text-white font-semibold">Desktop Workspace</h3>
            <p className="text-cyber-muted text-sm mt-1">Select a discovered bucket to browse its files natively.</p>
          </div>
        ) : (
          <>
            {/* Context Header */}
            <div className="card py-3 px-5 flex items-center justify-between shadow-sm">
              <div className="flex-1 min-w-0 pr-4">
                <div className="flex items-center gap-3">
                  <h2 className="text-lg font-bold text-white mono truncate">{selected.name}</h2>
                  <RiskBadge level={selected.risk_level} onClick={()=>setVulnModal({level:selected.risk_level, perm: selected.can_write?'WRITE':selected.can_delete?'DELETE':'READ'})}/>
                </div>
                <div className="flex gap-4 text-xs text-cyber-muted mt-2">
                  <span>{selected.region}</span>
                  <span>{selected.object_count} objects • {formatBytes(selected.total_size_bytes)}</span>
                  {selected.payload_used && <span className="bg-cyber-bg px-2 rounded mono border border-cyber-border">Payload: {selected.payload_used}</span>}
                </div>
              </div>
              
              <div className="flex flex-col items-end gap-2 shrink-0">
                <div className="flex gap-1 w-48">
                  <PermChip label="L" on={selected.can_list} />
                  <PermChip label="R" on={selected.can_read} />
                  <PermChip label="W" on={selected.can_write} />
                  <PermChip label="D" on={selected.can_delete} />
                </div>
                <div className="flex gap-2 mt-2">
                  <button className={`btn-ghost border-cyber-accent/30 text-cyber-accent hover:bg-cyber-accent/10 px-3 py-1 text-xs flex items-center gap-1.5`}
                    onClick={() => {
                        const cmd = `aws s3 sync s3://${selected.name} ./${selected.name} --no-sign-request`;
                        navigator.clipboard.writeText(cmd);
                        alert(`Terminal command copied to clipboard!\n\nRun this in your terminal to securely download the entire bucket:\n\n${cmd}`);
                    }}>
                    <Terminal className="w-3.5 h-3.5"/> CLI Sync
                  </button>
                  <button className={`btn-primary px-3 py-1 text-xs flex items-center gap-1.5 ${aiLoading?'opacity-60':''}`}
                    onClick={runAiAnalysis} disabled={aiLoading}>
                    {aiLoading ? <div className="w-3 h-3 border-2 border-white/40 border-t-white rounded-full animate-spin"/> : <Bot className="w-3.5 h-3.5"/>}
                    Automated Analysis
                  </button>
                </div>
              </div>
            </div>

            {/* AI result panel */}
            {aiResult && !aiResult.error && (
              <div className="card border-purple-500/30 p-4 animate-slide-up relative bg-gradient-to-br from-cyber-panel to-[#151124]">
                <button onClick={()=>setAiResult(null)} className="absolute top-3 right-3 text-cyber-muted hover:text-white"><X className="w-4 h-4"/></button>
                <div className="flex items-center gap-2 mb-2">
                  <Bot className="w-4 h-4 text-purple-400"/>
                  <h3 className="font-semibold text-white text-sm">Automated Triage</h3>
                  <span className={`text-xs ml-2 px-2 rounded-full ${aiResult.priority==='immediate'?'bg-cyber-red/20 text-cyber-red':'bg-orange-400/20 text-orange-400'}`}>
                    Risk: {aiResult.risk_score}/10
                  </span>
                </div>
                <p className="text-xs text-cyber-text leading-5 mb-3">{aiResult.risk_summary}</p>
                <div className="text-xs space-y-1">
                  <p className="font-medium text-cyber-muted mb-1">Recommended Action:</p>
                  {(aiResult.remediation||[]).map((r,i)=><div key={i} className="flex gap-2"><span className="text-cyber-accent">→</span><span className="text-cyber-text">{r}</span></div>)}
                </div>
              </div>
            )}

            {/* Main File Browser */}
            <div className="card flex-1 flex flex-col p-0 overflow-hidden">
              
              {/* Explorer Toolbar / Breadcrumbs */}
              <div className="bg-cyber-card border-b border-cyber-border p-3 flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-sm overflow-x-auto no-scrollbar">
                  <button onClick={()=>setCurrentPath([])} 
                    className="flex items-center gap-2 text-cyber-muted hover:text-white transition-colors">
                    <HardDrive className="w-4 h-4 text-cyber-accent"/>
                    <span className={`font-medium ${currentPath.length===0?'text-white':''}`}>root</span>
                  </button>
                  {currentPath.map((folder, i) => (
                    <div key={i} className="flex items-center gap-1.5 shrink-0">
                      <ChevronRight className="w-4 h-4 text-cyber-border"/>
                      <button 
                        onClick={()=>setCurrentPath(currentPath.slice(0, i+1))}
                        className={`hover:text-white transition-colors ${i===currentPath.length-1?'text-white font-medium':'text-cyber-muted'}`}>
                        {folder}
                      </button>
                    </div>
                  ))}
                </div>
                
                <div className="relative w-48 shrink-0">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
                  <input className="input pl-8 py-1.5 text-xs w-full bg-cyber-bg" placeholder="Filter current view…"
                    value={searchQ} onChange={e=>setSearchQ(e.target.value)} />
                </div>
              </div>

              {/* Grid View contents */}
              <div className="flex-1 overflow-y-auto p-5 bg-cyber-bg/50">
                {loadingFiles ? (
                   <div className="h-full flex items-center justify-center">
                     <div className="w-8 h-8 border-2 border-cyber-accent/40 border-t-cyber-accent rounded-full animate-spin"/>
                   </div>
                ) : !selected.can_list && files.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-cyber-muted">
                    <Shield className="w-12 h-12 mb-3 opacity-50"/>
                    <p>LIST requests are denied by AWS for this bucket.</p>
                  </div>
                ) : currentItems.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-cyber-muted">
                    <p>Folder is empty</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4 auto-rows-max">
                    {/* Render grid items */}
                    {currentItems.map((item, i) => {
                      if (item.isDir) {
                        return (
                          <div key={`dir-${i}`} 
                            className="bg-cyber-card border border-cyber-border hover:border-cyber-accent hover:shadow-[0_0_15px_-3px_rgba(0,212,255,0.2)] rounded-xl p-4 flex flex-col justify-center gap-3 transition-all cursor-pointer group h-28"
                            onClick={()=>setCurrentPath([...currentPath, item.name])}>
                            <Folder className="w-10 h-10 text-cyber-accent group-hover:scale-110 transition-transform duration-300" />
                            <div className="min-w-0">
                              <p className="text-sm font-medium text-white truncate w-full">{item.name}</p>
                              <p className="text-[10px] text-cyber-muted mt-0.5">{item.itemsCount} items nested</p>
                            </div>
                          </div>
                        );
                      } else {
                        const Icon = getFileIcon(item.content_type, item.key);
                        return (
                          <div key={`file-${i}`} 
                            className={`bg-cyber-panel border rounded-xl p-4 flex flex-col justify-center gap-3 transition-all cursor-pointer group h-28 relative
                              ${item.is_sensitive ? 'border-cyber-yellow hover:shadow-[0_0_15px_-3px_rgba(255,215,0,0.3)]' : 'border-cyber-border hover:border-white/30'}`}
                            onClick={() => setPreview(item)}>
                            
                            {item.is_sensitive && (
                              <div className="absolute top-2 right-2 text-cyber-yellow" title="Regex match detected inside file">
                                <AlertTriangle className="w-3.5 h-3.5"/>
                              </div>
                            )}

                            <Icon className={`w-9 h-9 transition-transform duration-300 group-hover:scale-105 ${item.is_sensitive?'text-cyber-yellow':'text-cyber-muted'}`} />
                            <div className="min-w-0">
                              <p className={`text-xs font-medium truncate w-full ${item.is_sensitive?'text-cyber-yellow':'text-cyber-text group-hover:text-white'}`}>
                                {item.name}
                              </p>
                              <p className="text-[10px] text-cyber-muted mt-0.5">{formatBytes(item.size)}</p>
                            </div>
                          </div>
                        );
                      }
                    })}
                  </div>
                )}
              </div>
            </div>
            
            {/* Sensitive Finding Quick Bar */}
            {findings.length > 0 && (
              <div className="card p-3 border-cyber-yellow/30 bg-cyber-yellow/5 shrink-0 flex items-center gap-4 overflow-x-auto no-scrollbar">
                <div className="flex items-center gap-2 shrink-0">
                  <Activity className="w-4 h-4 text-cyber-yellow"/>
                  <span className="text-xs font-bold text-cyber-yellow">{findings.length} Exfiltrated Match{findings.length!==1?'es':''}</span>
                </div>
                {findings.map((f, i) => (
                  <div key={i} className="flex items-center gap-2 bg-cyber-bg border border-cyber-yellow/20 px-3 py-1.5 rounded-lg shrink-0 max-w-sm truncate text-xs cursor-pointer hover:border-cyber-yellow/50 transition-colors"
                       onClick={() => {
                          const parts = f.file_key.split('/');
                          parts.pop(); // remove file name
                          setCurrentPath(parts); // navigate to its directory
                       }}>
                    <span className="text-white font-semibold">{f.pattern_name}</span>
                    <span className="text-cyber-muted mono mx-1">in</span>
                    <span className="text-cyber-accent truncate mono">{f.file_key.split('/').pop()}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
