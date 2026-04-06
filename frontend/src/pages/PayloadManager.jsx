import { useState, useEffect, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  ListChecks, Upload, Plus, Trash2, FileText,
  CheckCircle, XCircle, Edit3, Save, X
} from 'lucide-react';
import {
  listWordlists, uploadWordlist, createCustomWl, deleteWordlist
} from '../services/api';

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024*1024) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1024/1024).toFixed(1)} MB`;
}

export default function PayloadManager() {
  const [wordlists, setWordlists] = useState([]);
  const [loading, setLoading]     = useState(false);
  const [toast, setToast]         = useState(null);
  const [showEditor, setShowEditor] = useState(false);
  const [editorName, setEditorName] = useState('');
  const [editorContent, setEditorContent] = useState('');
  const [uploading, setUploading] = useState(false);

  const showToast = (msg, type='info') => {
    setToast({msg,type});
    setTimeout(()=>setToast(null), 3000);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await listWordlists(); setWordlists(r.data); }
    catch { showToast('Backend not reachable', 'danger'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const onDrop = useCallback(async (files) => {
    for (const file of files) {
      setUploading(true);
      try {
        await uploadWordlist(file);
        showToast(`✅ Uploaded: ${file.name}`, 'success');
        await load();
      } catch(e) {
        showToast(`Failed: ${file.name}`, 'danger');
      } finally { setUploading(false); }
    }
  }, [load]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, accept: { 'text/plain': ['.txt'], 'application/octet-stream': [] },
    multiple: true,
  });

  const handleSaveCustom = async () => {
    if (!editorContent.trim()) return showToast('Content is empty', 'danger');
    const name = editorName || `custom-${Date.now()}.txt`;
    try {
      await createCustomWl(name, editorContent);
      showToast('✅ Wordlist saved', 'success');
      setShowEditor(false); setEditorName(''); setEditorContent('');
      await load();
    } catch { showToast('Save failed', 'danger'); }
  };

  const handleDelete = async (id, name, isBuiltin) => {
    if (isBuiltin) return showToast('Cannot delete built-in wordlists', 'danger');
    if (!confirm(`Delete "${name}"?`)) return;
    try {
      await deleteWordlist(id);
      showToast('Deleted', 'success');
      setWordlists(p => p.filter(w => w.id !== id));
    } catch { showToast('Delete failed', 'danger'); }
  };

  const lineCount = editorContent.split('\n').filter(l => l.trim()).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 toast-enter px-5 py-3 rounded-xl border text-sm font-medium shadow-lg
          ${toast.type==='danger' ? 'bg-cyber-red/20 border-cyber-red/40 text-cyber-red'
          : toast.type==='success' ? 'bg-cyber-green/20 border-cyber-green/40 text-cyber-green'
          : 'bg-cyber-accent/20 border-cyber-accent/40 text-cyber-accent'}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Payload Manager</h1>
          <p className="text-cyber-muted text-sm mt-1">Manage wordlists for bucket enumeration</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => setShowEditor(true)}>
          <Plus className="w-4 h-4" /> New Wordlist
        </button>
      </div>

      {/* Drop zone */}
      <div {...getRootProps()} className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all
        ${isDragActive ? 'border-cyber-accent bg-cyber-accent/10' : 'border-cyber-border hover:border-cyber-accent/40 hover:bg-cyber-card'}`}>
        <input {...getInputProps()} />
        <Upload className={`w-10 h-10 mx-auto mb-3 ${isDragActive ? 'text-cyber-accent' : 'text-cyber-muted'}`} />
        {uploading ? (
          <p className="text-cyber-accent text-sm font-medium">Uploading…</p>
        ) : isDragActive ? (
          <p className="text-cyber-accent text-sm font-medium">Drop files here!</p>
        ) : (
          <>
            <p className="text-cyber-text text-sm font-medium">Drag & drop wordlists here</p>
            <p className="text-cyber-muted text-xs mt-1">or click to browse — supports .txt files (rockyou.txt, etc.)</p>
          </>
        )}
      </div>

      {/* Custom editor */}
      {showEditor && (
        <div className="card space-y-4 border-cyber-accent/30">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white flex items-center gap-2">
              <Edit3 className="w-4 h-4 text-cyber-accent" /> Custom Wordlist Editor
            </h2>
            <button className="text-cyber-muted hover:text-cyber-red" onClick={() => setShowEditor(false)}>
              <X className="w-4 h-4" />
            </button>
          </div>
          <div>
            <label className="label">Wordlist Name</label>
            <input className="input" placeholder="my-custom-list.txt"
              value={editorName} onChange={e=>setEditorName(e.target.value)} />
          </div>
          <div>
            <div className="flex justify-between mb-1">
              <label className="label">Bucket Names (one per line)</label>
              <span className="text-xs text-cyber-muted mono">{lineCount.toLocaleString()} entries</span>
            </div>
            <textarea className="input font-mono text-xs resize-none" rows={12}
              placeholder={"company-backup\ncompany-data\ncompany-files\ndev-bucket\n..."}
              value={editorContent} onChange={e=>setEditorContent(e.target.value)} />
          </div>
          <div className="flex gap-3">
            <button className="btn-primary flex items-center gap-2" onClick={handleSaveCustom}>
              <Save className="w-4 h-4" /> Save Wordlist
            </button>
            <button className="btn-ghost" onClick={() => { setShowEditor(false); setEditorContent(''); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Wordlist table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <ListChecks className="w-4 h-4 text-cyber-accent" /> Saved Wordlists
            <span className="ml-1 text-xs bg-cyber-accent/20 text-cyber-accent px-2 py-0.5 rounded-full">{wordlists.length}</span>
          </h2>
          <button className="btn-ghost text-xs" onClick={load}>Refresh</button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-10">
            <div className="w-6 h-6 border-2 border-cyber-accent/40 border-t-cyber-accent rounded-full animate-spin" />
          </div>
        ) : wordlists.length === 0 ? (
          <div className="text-center py-10">
            <FileText className="w-10 h-10 text-cyber-muted mx-auto mb-3" />
            <p className="text-cyber-muted text-sm">No wordlists yet. Upload one or create custom.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {wordlists.map(w => (
              <div key={w.id} className="flex items-center gap-4 px-4 py-3 bg-cyber-panel
                rounded-lg border border-cyber-border hover:border-cyber-accent/20 transition-all group">
                <FileText className="w-4 h-4 text-cyber-muted flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate mono">{w.name}</p>
                  <p className="text-xs text-cyber-muted mt-0.5">
                    {w.line_count.toLocaleString()} lines · {formatBytes(w.size_bytes)} · {w.is_builtin ? '✦ Built-in' : 'Custom'}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {w.is_builtin
                    ? <CheckCircle className="w-4 h-4 text-cyber-green" />
                    : <span className="text-xs text-cyber-accent border border-cyber-accent/30 px-2 py-0.5 rounded">Custom</span>
                  }
                  <button className="opacity-0 group-hover:opacity-100 transition-opacity text-cyber-muted hover:text-cyber-red"
                    onClick={() => handleDelete(w.id, w.name, w.is_builtin)}>
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
