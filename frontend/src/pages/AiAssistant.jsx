import { useState, useEffect, useRef, useCallback } from 'react';
import { Bot, Send, Sparkles, Wand2, AlertCircle, CheckCircle, RefreshCw, ChevronRight } from 'lucide-react';
import { getAiStatus, aiChat, aiSuggestConfig, retestBucket } from '../services/api';

const SUGGESTED_PROMPTS = [
  'What are the most common S3 bucket misconfigurations?',
  'How can attackers exploit publicly readable S3 buckets?',
  'What regex patterns should I use to detect AWS secrets?',
  'Explain the risk of write access to an S3 bucket',
  'What is the remediation for a public S3 bucket?',
  'How do I detect if sensitive files were accessed in S3?',
];

export default function AiAssistant() {
  const [messages, setMessages]     = useState([]);
  const [input, setInput]           = useState('');
  const [loading, setLoading]       = useState(false);
  const [aiStatus, setAiStatus]     = useState(null);
  const [configDesc, setConfigDesc] = useState('');
  const [configResult, setConfigResult] = useState(null);
  const [configLoading, setConfigLoading] = useState(false);
  const [activeTab, setActiveTab]   = useState('chat'); // chat | config
  const messagesEndRef = useRef(null);

  useEffect(() => {
    getAiStatus().then(r => setAiStatus(r.data)).catch(() =>
      setAiStatus({ running: false, models: [], preferred_model: null })
    );
    // Welcome message
    setMessages([{
      role: 'assistant',
      content: `👋 Hello! I'm **S3-Hunter AI**, your embedded security analyst powered by local LLM (Ollama on your RTX 4050).\n\nI can help you:\n• Analyze S3 bucket findings and risk\n• Suggest optimal scan configurations\n• Explain attack scenarios and mitigations\n• Generate executive report narratives\n\nStart by asking a security question or use the **Config Advisor** tab!`,
      ts: new Date(),
    }]);
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = useCallback(async (text) => {
    const msg = text || input.trim();
    if (!msg) return;
    setInput('');
    setMessages(p => [...p, { role:'user', content:msg, ts:new Date() }]);
    setLoading(true);
    
    // Auto Retest Interceptor
    const lowerMsg = msg.toLowerCase();
    if (lowerMsg.startsWith('retest ') || lowerMsg.includes('retest bucket')) {
       // extract the target which is likely the last word or the word after retest
       const words = msg.split(' ');
       let target = words[words.findIndex(w => w.toLowerCase() === 'retest') + 1];
       if (target) {
         try {
            const res = await retestBucket(target);
            setMessages(p => [...p, { role:'assistant', content:`⚡ **Retest Initiated automatically!**\n\nI have started a focused deep scan against **${target}**. The scanner is currently bypassing limitations to hunt for endpoints. You can monitor the progress on the **Dashboard** (Scan ID: #${res.data.scan_id}).`, ts:new Date() }]);
         } catch(e) {
            setMessages(p => [...p, { role:'error', content:`Failed to initiate retest for ${target}. Ensure the backend is running.`, ts:new Date() }]);
         }
         setLoading(false);
         return;
       }
    }

    try {
      const r = await aiChat(msg);
      setMessages(p => [...p, { role:'assistant', content:r.data.response || r.data.message || 'No response.', ts:new Date() }]);
    } catch(e) {
      setMessages(p => [...p, {
        role:'error',
        content: e.response?.data?.detail || 'AI unavailable. Start Ollama: `ollama serve`',
        ts:new Date()
      }]);
    }
    setLoading(false);
  }, [input]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  const handleSuggestConfig = async () => {
    if (!configDesc.trim()) return;
    setConfigLoading(true); setConfigResult(null);
    try {
      const r = await aiSuggestConfig(configDesc);
      setConfigResult(r.data);
    } catch(e) {
      setConfigResult({ error: e.response?.data?.detail || 'AI unavailable' });
    }
    setConfigLoading(false);
  };

  const formatMsg = (text) => {
    // Basic markdown-lite rendering
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code class="mono bg-cyber-bg px-1 rounded text-cyber-accent text-xs">$1</code>')
      .replace(/•/g, '•')
      .split('\n').join('<br/>');
  };

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-purple-400"/> AI Assistant
          </h1>
          <p className="text-cyber-muted text-sm mt-1">Local LLM security analyst — powered by Ollama on your RTX 4050</p>
        </div>
        {/* AI Status pill */}
        {aiStatus && (
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium
            ${aiStatus.running
              ? 'bg-cyber-green/10 border-cyber-green/30 text-cyber-green'
              : 'bg-cyber-red/10 border-cyber-red/30 text-cyber-red'}`}>
            {aiStatus.running ? <CheckCircle className="w-3.5 h-3.5"/> : <AlertCircle className="w-3.5 h-3.5"/>}
            {aiStatus.running
              ? `Ollama · ${aiStatus.preferred_model || 'model ready'}`
              : 'Ollama offline — run: ollama serve'}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-cyber-panel rounded-lg p-1 border border-cyber-border mb-4 w-fit">
        {[
          { id:'chat',   label:'Chat',           icon:Bot },
          { id:'config', label:'Config Advisor', icon:Wand2 },
        ].map(({id,label,icon:Icon})=>(
          <button key={id} onClick={()=>setActiveTab(id)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded text-sm font-medium transition-all
              ${activeTab===id?'bg-cyber-accent/20 text-cyber-accent':'text-cyber-muted hover:text-cyber-text'}`}>
            <Icon className="w-3.5 h-3.5"/> {label}
          </button>
        ))}
      </div>

      {activeTab === 'chat' ? (
        <div className="flex gap-4 flex-1 min-h-0">
          {/* Suggested prompts sidebar */}
          <div className="w-56 flex-shrink-0 space-y-2">
            <p className="label">Suggested prompts</p>
            {SUGGESTED_PROMPTS.map((p,i)=>(
              <button key={i} onClick={()=>sendMessage(p)}
                className="w-full text-left text-xs text-cyber-muted hover:text-cyber-text
                  px-3 py-2.5 rounded-lg border border-cyber-border hover:border-cyber-accent/30
                  hover:bg-cyber-card transition-all flex items-start gap-2 group">
                <ChevronRight className="w-3 h-3 mt-0.5 flex-shrink-0 group-hover:text-cyber-accent"/>
                {p}
              </button>
            ))}
          </div>

          {/* Chat panel */}
          <div className="flex-1 flex flex-col card min-h-0">
            {/* Messages */}
            <div className="flex-1 overflow-y-auto space-y-4 mb-4 pr-1">
              {messages.map((m,i)=>(
                <div key={i} className={`flex ${m.role==='user'?'justify-end':'justify-start'} animate-slide-up`}>
                  {m.role!=='user' && (
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mr-2 mt-0.5
                      ${m.role==='error'?'bg-cyber-red/20':'bg-purple-500/20'}`}>
                      {m.role==='error'
                        ? <AlertCircle className="w-3.5 h-3.5 text-cyber-red"/>
                        : <Bot className="w-3.5 h-3.5 text-purple-400"/>}
                    </div>
                  )}
                  <div className={`max-w-[80%] px-4 py-3 rounded-xl text-sm leading-6
                    ${m.role==='user'
                      ? 'bg-cyber-accent/15 text-cyber-text border border-cyber-accent/20 rounded-br-sm'
                      : m.role==='error'
                        ? 'bg-cyber-red/10 text-cyber-red border border-cyber-red/20 rounded-bl-sm'
                        : 'bg-cyber-panel border border-cyber-border text-cyber-text rounded-bl-sm'}`}
                    dangerouslySetInnerHTML={{__html: formatMsg(m.content)}} />
                </div>
              ))}
              {loading && (
                <div className="flex justify-start animate-slide-up">
                  <div className="w-7 h-7 rounded-full bg-purple-500/20 flex items-center justify-center mr-2">
                    <Bot className="w-3.5 h-3.5 text-purple-400"/>
                  </div>
                  <div className="bg-cyber-panel border border-cyber-border rounded-xl rounded-bl-sm px-4 py-3">
                    <div className="flex gap-1.5 items-center">
                      {[0,150,300].map(d=>(
                        <div key={d} className="w-2 h-2 rounded-full bg-purple-400 animate-bounce" style={{animationDelay:`${d}ms`}}/>
                      ))}
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef}/>
            </div>
            {/* Input */}
            <div className="flex gap-3 border-t border-cyber-border pt-4">
              <textarea className="input flex-1 resize-none text-sm" rows={2}
                placeholder="Ask about S3 security, findings analysis, attack techniques…"
                value={input} onChange={e=>setInput(e.target.value)} onKeyDown={handleKeyDown}/>
              <button className="btn-primary px-4 self-end flex items-center gap-2"
                onClick={()=>sendMessage()} disabled={loading||!input.trim()}>
                {loading
                  ? <div className="w-4 h-4 border-2 border-cyber-accent/40 border-t-cyber-accent rounded-full animate-spin"/>
                  : <Send className="w-4 h-4"/>}
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* Config Advisor tab */
        <div className="card flex-1 overflow-y-auto space-y-6">
          <div>
            <h2 className="font-semibold text-white flex items-center gap-2 mb-1">
              <Wand2 className="w-4 h-4 text-purple-400"/> Smart Scan Configuration
            </h2>
            <p className="text-cyber-muted text-sm">Describe your target and AI will suggest optimal scan settings</p>
          </div>

          <div className="space-y-3">
            <label className="label">Target Description</label>
            <textarea className="input resize-none" rows={4}
              placeholder="Example: E-commerce company in Europe, likely using AWS for media storage, product images, user uploads. Tech company with multiple dev/staging environments..."
              value={configDesc} onChange={e=>setConfigDesc(e.target.value)}/>
            <button className="btn flex items-center gap-2 bg-purple-500/20 text-purple-300 border border-purple-500/30 hover:bg-purple-500/30"
              onClick={handleSuggestConfig} disabled={configLoading||!configDesc.trim()}>
              {configLoading
                ? <div className="w-4 h-4 border-2 border-purple-400/40 border-t-purple-400 rounded-full animate-spin"/>
                : <Sparkles className="w-4 h-4"/>}
              Generate Config
            </button>
          </div>

          {configResult && !configResult.error && (
            <div className="space-y-4 animate-slide-up border-t border-cyber-border pt-4">
              <h3 className="font-semibold text-white flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-cyber-green"/> Recommended Configuration
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-cyber-panel rounded-lg p-4 border border-cyber-border space-y-3">
                  <div>
                    <p className="label">Prefixes</p>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {(configResult.prefixes||[]).map((p,i)=>(
                        <span key={i} className="text-xs mono px-2 py-0.5 bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20 rounded">{p}</span>
                      ))}
                      {!configResult.prefixes?.length && <span className="text-xs text-cyber-muted">None</span>}
                    </div>
                  </div>
                  <div>
                    <p className="label">Suffixes</p>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {(configResult.suffixes||[]).map((s,i)=>(
                        <span key={i} className="text-xs mono px-2 py-0.5 bg-cyber-green/10 text-cyber-green border border-cyber-green/20 rounded">{s}</span>
                      ))}
                      {!configResult.suffixes?.length && <span className="text-xs text-cyber-muted">None</span>}
                    </div>
                  </div>
                  <div>
                    <p className="label">Regions</p>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {(configResult.recommended_regions||[]).map((r,i)=>(
                        <span key={i} className="text-xs mono px-2 py-0.5 bg-cyber-purple/10 text-purple-300 border border-purple-500/20 rounded">{r}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="bg-cyber-panel rounded-lg p-4 border border-cyber-border space-y-3">
                  <div>
                    <p className="label">Concurrency</p>
                    <p className="text-2xl font-bold text-cyber-accent">{configResult.concurrency}</p>
                  </div>
                  <div>
                    <p className="label">Wordlist Type</p>
                    <span className="badge badge-info">{configResult.wordlist_type}</span>
                  </div>
                  <div>
                    <p className="label">Additional Names to Try</p>
                    <div className="space-y-0.5 mt-1">
                      {(configResult.additional_names||[]).slice(0,5).map((n,i)=>(
                        <p key={i} className="text-xs mono text-cyber-text">{n}</p>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              {configResult.reasoning && (
                <div className="bg-cyber-panel rounded-lg p-4 border border-cyber-border">
                  <p className="label mb-1">AI Reasoning</p>
                  <p className="text-sm text-cyber-text">{configResult.reasoning}</p>
                </div>
              )}
              {configResult.estimated_risk_areas?.length > 0 && (
                <div>
                  <p className="label mb-2">Estimated Risk Areas</p>
                  <div className="flex flex-wrap gap-2">
                    {configResult.estimated_risk_areas.map((a,i)=>(
                      <span key={i} className="text-xs px-3 py-1 rounded-full bg-cyber-red/10 text-cyber-red border border-cyber-red/20">{a}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          {configResult?.error && (
            <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-lg p-4 text-cyber-red text-sm animate-slide-up">
              ⚠ {configResult.error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
