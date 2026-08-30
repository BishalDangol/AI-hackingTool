import React, { useEffect, useMemo, useRef, useState } from 'react';

const SOURCES = ['anubis', 'baidu', 'bevigil', 'bing', 'bitbucket', 'brave', 'bufferoverun', 'builtwith', 'censys', 'certspotter', 'chaos', 'commoncrawl', 'criminalip', 'crtsh', 'dehashed', 'dnsdumpster', 'duckduckgo', 'dymo', 'fofa', 'fullhunt', 'github-code', 'gitlab', 'hackertarget', 'haveibeenpwned', 'hudsonrock', 'hunter', 'hunterhow', 'intelx', 'leakix', 'leaklookup', 'linkedin', 'mojeek', 'netcraft', 'netlas', 'onyphe', 'otx', 'pentesttools', 'projectdiscovery', 'rapiddns', 'robtex', 'rocketreach', 'securityscorecard', 'securityTrails', 'shodan', 'shodanInternetDB', 'subdomaincenter', 'subdomainfinderc99', 'threatminer', 'tomba', 'urlscan', 'venacus', 'virustotal', 'waybackarchive', 'whoisxml', 'windvane', 'yahoo', 'zoomeye'];
const RECOMMENDED = ['crtsh', 'dnsdumpster', 'duckduckgo', 'hackertarget', 'otx', 'urlscan', 'rapiddns'];

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: '⌂' },
  { id: 'domain', label: 'Domain OSINT', icon: '◎' },
  { id: 'dns', label: 'DNS & Certificates', icon: '⌁' },
  { id: 'shodan', label: 'Shodan Assets', icon: '◈' },
  { id: 'camera', label: 'Camera Audit', icon: '▣' },
  { id: 'reports', label: 'Reports', icon: '▤' },
  { id: 'findings', label: 'Findings', icon: '△' },
];

function unique(values) { return [...new Set(values)].sort((a, b) => a.localeCompare(b)); }

function extractEntities(logs) {
  const text = logs.join('\n');
  const emails = unique(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
  const ips = unique(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []);
  const urls = unique(text.match(/https?:\/\/[^\s<>"']+/gi) || []).map(url => url.replace(/[),.;]+$/, ''));
  const hosts = unique(text.match(/\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || [])
    .filter(host => !emails.some(email => email.endsWith(host)) && !urls.some(url => url.includes(host)));
  const services = unique(logs.flatMap(line => {
    const matches = line.match(/\b(?:port\s*\d{1,5}|https?|ssh|ftp|smtp|dns|rdp|mysql|postgres(?:ql)?|mongodb|redis|telnet)\b[^\n]*/gi) || [];
    return matches.map(value => value.trim()).filter(value => value.length < 120);
  }));
  const people = unique(logs.flatMap(line => {
    const match = line.match(/^(?:[-*]\s*)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s*$/);
    return match ? [match[1]] : [];
  }));
  return { emails, hosts, ips, people, urls, services };
}

function deriveFindings(logs) {
  const text = logs.join('\n');
  const findings = [];
  if (/missing api key|api key/i.test(text)) findings.push({ severity: 'medium', title: 'Provider credentials are incomplete', evidence: 'One or more configured providers reported a missing API key.', fix: 'Configure only the provider keys required for authorized assessments.' });
  if (/invalid response format|work item.*error|exception occurred|traceback/i.test(text)) findings.push({ severity: 'low', title: 'Provider returned an unexpected response', evidence: 'The captured output contains a provider or parser diagnostic.', fix: 'Review the provider log, update the dependency, or disable the provider for this scan.' });
  if (/websocket.*unavailable|live stream unavailable|unsupported upgrade request/i.test(text)) findings.push({ severity: 'low', title: 'Live stream transport was unavailable', evidence: 'The frontend used the REST result fallback.', fix: 'Install the project WebSocket dependency in the active virtual environment.' });
  if (/no (?:ips|hosts|emails) found/i.test(text)) findings.push({ severity: 'info', title: 'The current scan returned no matching entities', evidence: 'TheHarvester reported an empty result for one or more entity types.', fix: 'Compare additional authorized passive sources and review provider coverage.' });
  return findings;
}

function summarize(logs) {
  const text = logs.join('\n');
  const count = patterns => patterns.reduce((total, pattern) => total + (text.match(pattern) || []).length, 0);
  const tagged = logs.filter(line => /\[(SUCCESS|ERROR|WARNING|STDERR)\]/i.test(line));
  return {
    entities: [
      { label: 'EMAILS', value: count([/emails? found/gi, /email addresses?/gi]) },
      { label: 'HOSTS', value: count([/hosts? found/gi, /subdomains? found/gi, /hostnames? found/gi]) },
      { label: 'IPS', value: count([/ips? found/gi, /ip addresses?/gi]) },
      { label: 'URLS', value: count([/urls? found/gi, /urls? discovered/gi]) },
    ],
    events: [
      { label: 'SUCCESS', value: tagged.filter(line => /\[SUCCESS\]/i.test(line)).length, color: 'var(--success)' },
      { label: 'WARNING', value: tagged.filter(line => /\[WARNING\]/i.test(line)).length, color: 'var(--warning)' },
      { label: 'ERROR', value: tagged.filter(line => /\[(ERROR|STDERR)\]/i.test(line)).length, color: 'var(--danger)' },
    ],
    totalLines: logs.length,
  };
}

function BarChart({ items }) {
  const max = Math.max(...items.map(item => item.value), 1);
  return <div className="bar-chart">{items.map(item => <div className="bar-row" key={item.label}><span>{item.label}</span><div className="bar-track"><div className="bar-fill" style={{ width: `${item.value ? Math.max((item.value / max) * 100, 7) : 0}%`, background: item.color || 'var(--accent)' }} /></div><strong>{item.value}</strong></div>)}</div>;
}

function EntityPanel({ title, icon, values }) {
  return <article className="entity-panel"><div className="entity-panel-title"><span className="entity-icon">{icon}</span><h3>{title}</h3><b>{values.length}</b></div>{values.length ? <div className="entity-values">{values.slice(0, 30).map(value => <code key={value}>{value}</code>)}</div> : <p className="empty-state">No values captured in this report.</p>}{values.length > 30 && <small>Showing 30 of {values.length}</small>}</article>;
}

function App() {
  const [module, setModule] = useState('overview');
  const [apiOnline, setApiOnline] = useState(false);
  const [apiStatus, setApiStatus] = useState('Checking backend');
  const [diagnostics, setDiagnostics] = useState(null);
  const [domain, setDomain] = useState('');
  const [domainError, setDomainError] = useState('');
  const [limit, setLimit] = useState(500);
  const [dnsBrute, setDnsBrute] = useState(false);
  const [selectedSources, setSelectedSources] = useState(RECOMMENDED);
  const [availableSources, setAvailableSources] = useState(SOURCES);
  const [sourceSearch, setSourceSearch] = useState('');
  const [activePreset, setActivePreset] = useState('recommended');
  const [currentJobId, setCurrentJobId] = useState(null);
  const [currentCommand, setCurrentCommand] = useState('theHarvester -h');
  const [currentStatus, setCurrentStatus] = useState('Idle');
  const [exitCode, setExitCode] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [consoleLogs, setConsoleLogs] = useState(['Ready for an authorized passive collection job.']);
  const [recentJobs, setRecentJobs] = useState([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [cameraChecks, setCameraChecks] = useState({ ownership: false, exposure: false, auth: false, firmware: false, tls: false, network: false });
  const [shodanAuthorized, setShodanAuthorized] = useState(false);
  const terminalRef = useRef(null);
  const wsRef = useRef(null);

  const host = typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1';
  const apiHost = host && host !== 'localhost' ? host : '127.0.0.1';
  const API = `http://${apiHost}:8000`;
  const WS = `ws://${apiHost}:8000`;
  const filteredSources = useMemo(() => availableSources.filter(source => source.toLowerCase().includes(sourceSearch.toLowerCase())), [availableSources, sourceSearch]);
  const cleanLogs = useMemo(() => consoleLogs.filter(line => !line.startsWith('[CONNECTION]')), [consoleLogs]);
  const stats = useMemo(() => summarize(cleanLogs), [cleanLogs]);
  const entities = useMemo(() => extractEntities(cleanLogs), [cleanLogs]);
  const entityCount = Object.values(entities).reduce((sum, values) => sum + values.length, 0);
  const findings = useMemo(() => deriveFindings(cleanLogs), [cleanLogs]);

  useEffect(() => {
    checkBackend();
    loadJobs();
    const timer = window.setInterval(checkBackend, 15000);
    return () => { window.clearInterval(timer); if (wsRef.current) wsRef.current.close(); };
  }, []);

  useEffect(() => { if (autoScroll && terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight; }, [consoleLogs, autoScroll]);

  async function checkBackend() {
    try {
      const health = await fetch(`${API}/api/health`);
      setApiOnline(health.ok);
      setApiStatus(health.ok ? 'Backend connected' : 'Backend error');
      const sourceResponse = await fetch(`${API}/api/sources`);
      if (sourceResponse.ok) setAvailableSources((await sourceResponse.json()).sources || SOURCES);
      const diagResponse = await fetch(`${API}/api/diagnostics`);
      if (diagResponse.ok) setDiagnostics(await diagResponse.json());
    } catch { setApiOnline(false); setApiStatus('Backend offline'); }
  }

  async function loadJobs() {
    try { const response = await fetch(`${API}/api/jobs`); if (response.ok) setRecentJobs((await response.json()).jobs || []); } catch { /* in-memory history is optional */ }
  }

  function validate(value) {
    if (!value.trim()) return 'Enter a target domain.';
    return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value.trim()) ? '' : 'Use a valid domain such as example.com.';
  }

  function toggleSource(source) {
    setActivePreset('custom');
    if (source === 'all') { setSelectedSources(selectedSources.includes('all') ? RECOMMENDED : ['all']); setActivePreset(selectedSources.includes('all') ? 'recommended' : 'all'); return; }
    setSelectedSources(current => current.includes('all') ? [source] : current.includes(source) ? current.filter(item => item !== source) : [...current, source]);
  }

  function preset(value) { setActivePreset(value); setSelectedSources(value === 'recommended' ? RECOMMENDED : value === 'all' ? ['all'] : []); }

  async function pollResult(jobId, attempt = 0) {
    const maxAttempts = 900; // Match the backend’s 15-minute passive-job timeout.
    if (attempt >= maxAttempts) { setCurrentStatus('Error'); setErrorMessage('Result polling exceeded 15 minutes. Check the backend terminal and captured job log.'); setIsSubmitting(false); return; }
    try {
      const response = await fetch(`${API}/api/scan/${jobId}/result`, { cache: 'no-store' });
      if (!response.ok) throw new Error(`Result endpoint returned ${response.status}`);
      const data = await response.json();
      setConsoleLogs(data.output_lines || []); setCurrentStatus(data.status); setExitCode(data.exit_code); setErrorMessage(data.error_message || null);
      if (data.status === 'Running' || data.status === 'Queued') window.setTimeout(() => pollResult(jobId, attempt + 1), 1000); else { setIsSubmitting(false); loadJobs(); }
    } catch (error) {
      // A transient browser/backend request failure should not turn a live job into a false Error state.
      setErrorMessage(`Temporary result connection issue: ${error.message}`);
      window.setTimeout(() => pollResult(jobId, attempt + 1), Math.min(5000, 1000 + attempt * 100));
    }
  }

  function connectStream(jobId) {
    if (wsRef.current) wsRef.current.close();
    const socket = new WebSocket(`${WS}/api/scan/${jobId}/stream`); wsRef.current = socket;
    let fallback = false; let finished = false;
    const startFallback = () => { if (fallback || finished) return; fallback = true; setConsoleLogs(previous => [...previous.filter(line => !line.startsWith('[CONNECTION]')), '[CONNECTION] Live stream unavailable; using result polling.']); pollResult(jobId); };
    socket.onmessage = event => { try { const payload = JSON.parse(event.data); if (payload.type === 'command') setCurrentCommand(payload.data); if (payload.type === 'status') setCurrentStatus(payload.status); if (payload.type === 'output') setConsoleLogs(previous => [...previous, payload.data]); if (payload.type === 'done') { finished = true; setCurrentStatus(payload.status); setExitCode(payload.exit_code); setErrorMessage(payload.error_message || null); setIsSubmitting(false); loadJobs(); } } catch { setConsoleLogs(previous => [...previous, event.data]); } };
    socket.onerror = startFallback; socket.onclose = () => { if (!finished) startFallback(); };
  }

  async function runScan(event) {
    event.preventDefault(); const validation = validate(domain); setDomainError(validation); if (validation || !selectedSources.length) return;
    setModule('domain'); setIsSubmitting(true); setCurrentStatus('Queued'); setExitCode(null); setErrorMessage(null); setConsoleLogs([]);
    try {
      const response = await fetch(`${API}/api/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: domain.trim(), sources: selectedSources, limit: Number(limit), dns_brute: Boolean(dnsBrute) }) });
      if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.detail || `Backend returned ${response.status}`); }
      const data = await response.json(); setCurrentJobId(data.job_id); setCurrentCommand(data.command_str || `theHarvester -d ${domain.trim()}`); connectStream(data.job_id);
    } catch (error) { setCurrentStatus('Error'); setErrorMessage(error.message); setConsoleLogs([`[ERROR] ${error.message}`]); setIsSubmitting(false); }
  }

  async function openJob(job) {
    setModule('domain'); setCurrentJobId(job.job_id); setDomain(job.domain); setSelectedSources(job.sources); setLimit(job.limit); setDnsBrute(job.dns_brute); setCurrentCommand(job.command_str || `theHarvester -d ${job.domain}`); setCurrentStatus(job.status); setExitCode(job.exit_code);
    try { const data = await (await fetch(`${API}/api/scan/${job.job_id}/result`)).json(); setConsoleLogs(data.output_lines || []); if (data.status === 'Running' || data.status === 'Queued') connectStream(job.job_id); } catch { setConsoleLogs(['[ERROR] Could not load this report.']); }
  }

  function logClass(line) { if (/\[(ERROR|STDERR)\]/i.test(line)) return 'log-danger'; if (/\[WARNING\]|\[!\]/i.test(line)) return 'log-warning'; if (/\[SUCCESS\]|\[\+\]|Found /i.test(line)) return 'log-success'; return ''; }
  function exportReport() { if (currentJobId) window.open(`${API}/api/scan/${currentJobId}/download`, '_blank'); }

  const moduleTitle = NAV_ITEMS.find(item => item.id === module)?.label || 'Settings';

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand-block"><div className="brand-mark">H</div><div><strong>Harvester</strong><span>Security workspace</span></div></div><div className="sidebar-section-label">Modules</div><nav className="main-nav">{NAV_ITEMS.map(item => <button key={item.id} className={module === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setModule(item.id)}><span>{item.icon}</span>{item.label}</button>)}</nav><button className={module === 'settings' ? 'nav-item settings-link active' : 'nav-item settings-link'} onClick={() => setModule('settings')}><span>⚙</span>Settings</button><div className="sidebar-bottom"><div className="scope-note"><span className="scope-dot" />Authorized use only</div><p>Passive metadata collection for approved domains and assets.</p><div className="sidebar-version">Local operator console <span>v2.0</span></div></div></aside>
    <main className="main-shell"><header className="topbar"><div className="breadcrumb">Harvester <span>/</span> {moduleTitle}</div><div className={apiOnline ? 'connection-pill online' : 'connection-pill'}><span />{apiStatus}</div></header>
      <section className="page-intro"><div><div className="overline">Security intelligence workspace</div><h1>{module === 'overview' ? 'Understand your public footprint.' : moduleTitle}</h1><p>{module === 'overview' ? 'Run focused, passive assessments and turn public signals into clear evidence.' : module === 'camera' ? 'Review hardening controls for cameras in your approved inventory.' : 'A focused workspace for authorized, evidence-based assessment.'}</p></div><div className="intro-stat"><span>Active target</span><strong>{domain || 'No target selected'}</strong><small>{currentStatus}{currentJobId ? ` · ${currentJobId.slice(0, 8)}` : ''}</small></div></section>
      {module === 'overview' && <Overview recentJobs={recentJobs} stats={stats} entityCount={entityCount} apiOnline={apiOnline} onNavigate={setModule} onJob={openJob} />}
      {module === 'domain' && <DomainModule domain={domain} setDomain={value => { setDomain(value); setDomainError(validate(value)); }} domainError={domainError} limit={limit} setLimit={setLimit} dnsBrute={dnsBrute} setDnsBrute={setDnsBrute} selectedSources={selectedSources} toggleSource={toggleSource} sourceSearch={sourceSearch} setSourceSearch={setSourceSearch} filteredSources={filteredSources} activePreset={activePreset} preset={preset} runScan={runScan} isSubmitting={isSubmitting} currentCommand={currentCommand} currentStatus={currentStatus} exitCode={exitCode} errorMessage={errorMessage} consoleLogs={consoleLogs} terminalRef={terminalRef} autoScroll={autoScroll} setAutoScroll={setAutoScroll} logClass={logClass} stats={stats} entities={entities} exportReport={exportReport} />}
      {module === 'dns' && <DnsModule target={domain} setTarget={setDomain} onOpenDomain={() => setModule('domain')} />}
      {module === 'shodan' && <ShodanModule target={domain} setTarget={setDomain} authorized={apiOnline && shodanAuthorized} setAuthorized={setShodanAuthorized} onReview={() => { setSelectedSources(['shodan']); setActivePreset('custom'); setModule('domain'); }} diagnostics={diagnostics} />}
      {module === 'camera' && <CameraModule checks={cameraChecks} setChecks={setCameraChecks} />}
      {module === 'reports' && <ReportsModule recentJobs={recentJobs} onJob={openJob} stats={stats} entities={entities} exportReport={exportReport} />}
      {module === 'findings' && <FindingsModule findings={findings} /> }
      {module === 'settings' && <SettingsModule apiOnline={apiOnline} apiStatus={apiStatus} diagnostics={diagnostics} onRefresh={checkBackend} />}
      <footer className="app-footer">Harvester <span>·</span> Passive authorized collection <span>·</span> Local session</footer>
    </main>
  </div>;
}

function Overview({ recentJobs, stats, entityCount, apiOnline, onNavigate, onJob }) {
  return <section className="overview-page"><div className="overview-hero card-surface"><div><span className="overline">Workspace overview</span><h2>One place for public evidence.</h2><p>Start with a domain assessment, review authorized assets, or inspect a previous report.</p></div><button className="button primary" onClick={() => onNavigate('domain')}>Start a domain scan <b>→</b></button></div><div className="overview-metrics"><Metric label="Unique entities" value={entityCount} note="Current report" /><Metric label="Captured lines" value={stats.totalLines} note="Live evidence" /><Metric label="Jobs this session" value={recentJobs.length} note="In-memory history" /><Metric label="Backend" value={apiOnline ? 'Ready' : 'Offline'} note="Connection state" /></div><div className="overview-grid"><section className="card-surface overview-card"><div className="section-heading"><div><span className="overline">Choose a workflow</span><h2>Assessment modules</h2></div></div><div className="workflow-grid"><Workflow icon="◎" title="Domain OSINT" text="Emails, hosts, IPs, URLs and provider evidence." onClick={() => onNavigate('domain')} /><Workflow icon="◈" title="Shodan assets" text="Passive service metadata for approved assets." onClick={() => onNavigate('shodan')} /><Workflow icon="⌁" title="DNS & certificates" text="Inventory public DNS and certificate signals." onClick={() => onNavigate('dns')} /><Workflow icon="▣" title="Camera audit" text="Review hardening controls in your inventory." onClick={() => onNavigate('camera')} /></div></section><section className="card-surface overview-card"><div className="section-heading"><div><span className="overline">Recent activity</span><h2>Latest jobs</h2></div><button className="text-button" onClick={() => onNavigate('reports')}>View all →</button></div>{recentJobs.length ? <div className="mini-job-list">{recentJobs.slice(0, 5).map(job => <button className="mini-job" key={job.job_id} onClick={() => onJob(job)}><span><b>{job.domain}</b><small>{new Date(job.created_at * 1000).toLocaleString()}</small></span><span className={`status-tag ${job.status.toLowerCase()}`}>{job.status}</span></button>)}</div> : <div className="large-empty">No scan jobs in this session.</div>}</section></div></section>;
}
function Metric({ label, value, note }) { return <div className="metric-card"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>; }
function Workflow({ icon, title, text, onClick }) { return <button className="workflow-card" onClick={onClick}><span className="workflow-icon">{icon}</span><span><b>{title}</b><small>{text}</small></span><i>→</i></button>; }

function DomainModule({ domain, setDomain, domainError, limit, setLimit, dnsBrute, setDnsBrute, selectedSources, toggleSource, sourceSearch, setSourceSearch, filteredSources, activePreset, preset, runScan, isSubmitting, currentCommand, currentStatus, exitCode, errorMessage, consoleLogs, terminalRef, autoScroll, setAutoScroll, logClass, stats, entities, exportReport }) {
  return <section className="domain-page"><div className="module-banner card-surface"><div><span className="overline">Domain OSINT</span><h2>Collect public domain intelligence.</h2><p>Use passive sources to build a reviewable evidence set for an authorized target.</p></div><div className="banner-note"><span className="scope-dot" />No active exploitation</div></div><div className="domain-layout"><form className="card-surface config-card" onSubmit={runScan}><div className="section-heading compact"><div><span className="overline">Step 01</span><h2>Collection setup</h2></div><span className="step-badge">Passive</span></div><label className="field-label">Target domain <span>Required</span></label><input className={domainError ? 'field-input invalid' : 'field-input'} value={domain} onChange={event => setDomain(event.target.value)} placeholder="example.com" />{domainError && <p className="field-error">{domainError}</p>}<div className="field-row"><div><label className="field-label">Result limit</label><input className="field-input" type="number" min="1" max="5000" value={limit} onChange={event => setLimit(event.target.value)} /></div><label className={dnsBrute ? 'toggle-card checked' : 'toggle-card'}><input type="checkbox" checked={dnsBrute} onChange={event => setDnsBrute(event.target.checked)} /><span><b>DNS brute force</b><small>Enumerate likely subdomains</small></span><i>{dnsBrute ? 'On' : 'Off'}</i></label></div><div className="sources-heading"><label className="field-label">Sources <span>{selectedSources.includes('all') ? 'All selected' : `${selectedSources.length} selected`}</span></label><div className="preset-row"><button type="button" className={activePreset === 'recommended' ? 'preset active' : 'preset'} onClick={() => preset('recommended')}>Recommended</button><button type="button" className={activePreset === 'all' ? 'preset active' : 'preset'} onClick={() => preset('all')}>All</button><button type="button" className="preset" onClick={() => preset('clear')}>Clear</button></div></div><input className="search-input" value={sourceSearch} onChange={event => setSourceSearch(event.target.value)} placeholder="Search sources" /><div className="source-list"><label className={selectedSources.includes('all') ? 'source-option selected' : 'source-option'}><input type="checkbox" checked={selectedSources.includes('all')} onChange={() => toggleSource('all')} /><span>All supported sources</span></label>{filteredSources.map(source => <label className={selectedSources.includes('all') || selectedSources.includes(source) ? 'source-option selected' : 'source-option'} key={source}><input type="checkbox" checked={selectedSources.includes('all') || selectedSources.includes(source)} disabled={selectedSources.includes('all')} onChange={() => toggleSource(source)} /><span>{source}</span></label>)}</div><button className="button primary launch-button" type="submit" disabled={isSubmitting || !!domainError || !domain.trim() || !selectedSources.length}>{isSubmitting ? 'Running collection…' : 'Start passive collection'}<b>↗</b></button></form><div className="domain-results"><div className="result-header card-surface"><div><span className="overline">Step 02 · Evidence</span><h2>{domain || 'Awaiting target'}</h2><div className="command-line"><span>$</span>{currentCommand}</div></div><div className="result-actions"><span className={`status-tag ${currentStatus.toLowerCase()}`}>{currentStatus}{exitCode !== null ? ` · ${exitCode}` : ''}</span><button className="button secondary small" onClick={exportReport}>Export report</button></div></div>{errorMessage && <div className="alert-card"><span>!</span><div><b>Collection needs attention</b><p>{errorMessage}</p></div></div>}<div className="metric-grid"><Metric label="Entities" value={Object.values(entities).reduce((sum, values) => sum + values.length, 0)} note="Unique values" /><Metric label="Output lines" value={stats.totalLines} note="Captured report" /><Metric label="Sources" value={selectedSources.includes('all') ? 'All' : selectedSources.length} note="Configured engines" /><Metric label="Status" value={currentStatus} note="Current job" /></div><div className="terminal-card card-surface"><div className="terminal-heading"><div><span className="overline">Live output</span><h3>Collection stream</h3></div><span className="terminal-meta">{stats.totalLines} lines</span></div><div className="terminal-body" ref={terminalRef} onScroll={() => { if (!terminalRef.current) return; setAutoScroll(terminalRef.current.scrollHeight - terminalRef.current.scrollTop - terminalRef.current.clientHeight < 45); }}>{consoleLogs.map((line, index) => <div className={`log-line ${logClass(line)}`} key={`${index}-${line}`}>{line}</div>)}{currentStatus === 'Running' && <div className="log-line log-live"><span />Waiting for provider output…</div>}</div>{!autoScroll && <button className="resume-button" onClick={() => { setAutoScroll(true); terminalRef.current.scrollTop = terminalRef.current.scrollHeight; }}>Resume live view</button>}</div><div className="insights-heading"><div><span className="overline">Step 03 · Review</span><h2>Collected intelligence</h2></div><span className="insight-note">Only values found in the report are shown</span></div><div className="entity-grid"><EntityPanel title="Email addresses" icon="@" values={entities.emails} /><EntityPanel title="Hosts & domains" icon="◇" values={entities.hosts} /><EntityPanel title="IP addresses" icon="#" values={entities.ips} /><EntityPanel title="People" icon="◌" values={entities.people} /><EntityPanel title="URLs" icon="↗" values={entities.urls} /><EntityPanel title="Services" icon="◈" values={entities.services} /></div><div className="analytics-grid"><div className="analytics-card card-surface"><div className="analytics-title"><span className="overline">Distribution</span><h3>Report indicators</h3></div><BarChart items={stats.entities} /></div><div className="analytics-card card-surface"><div className="analytics-title"><span className="overline">Health</span><h3>Provider events</h3></div><BarChart items={stats.events} /></div></div></div></div></section>;
}

function FindingsModule({ findings }) {
  const severityCounts = findings.reduce((counts, finding) => ({ ...counts, [finding.severity]: counts[finding.severity] + 1 }), { high: 0, medium: 0, low: 0, info: 0 });
  return <section className="module-page"><ModuleHeader overline="Evidence findings" title="Turn diagnostics into action." text="Strix-inspired finding cards summarize captured evidence and remediation steps. They do not run exploits or generate proof-of-concept payloads." /><div className="finding-summary"><Metric label="Total findings" value={findings.length} note="Current report" /><Metric label="Medium" value={severityCounts.medium} note="Needs review" /><Metric label="Low" value={severityCounts.low} note="Operational" /><Metric label="Informational" value={severityCounts.info} note="Context" /></div>{findings.length ? <div className="findings-list">{findings.map((finding, index) => <article className="finding-card card-surface" key={`${finding.title}-${index}`}><div className="finding-top"><span className={`finding-severity ${finding.severity}`}>{finding.severity}</span><h3>{finding.title}</h3></div><div className="finding-columns"><div><span className="finding-label">Evidence</span><p>{finding.evidence}</p></div><div><span className="finding-label">Recommended action</span><p>{finding.fix}</p></div></div></article>)}</div> : <div className="card-surface large-empty">No evidence findings have been derived from the current report yet. Run an authorized scan to populate this section.</div>}</section>;
}

function DnsModule({ target, setTarget, onOpenDomain }) { return <section className="module-page"><ModuleHeader overline="DNS & certificates" title="Map public naming signals." text="Review DNS records and certificate names through passive collection workflows." /><div className="module-grid"><div className="card-surface tool-card"><span className="tool-number">01</span><h3>Domain inventory</h3><p>Start a Domain OSINT job with certificate transparency and DNS-focused sources.</p><label className="field-label">Authorized domain</label><input className="field-input" value={target} onChange={event => setTarget(event.target.value)} placeholder="example.com" /><button className="button primary" onClick={onOpenDomain}>Open domain workflow →</button></div><div className="card-surface checklist-card"><span className="tool-number">02</span><h3>Review checklist</h3><Check text="Certificate names and expiry" /><Check text="A, AAAA, MX, NS and TXT records" /><Check text="Unexpected subdomains" /><Check text="Third-party services and vendors" /></div></div></section>; }
function ShodanModule({ target, setTarget, authorized, setAuthorized, onReview, diagnostics }) { return <section className="module-page"><ModuleHeader overline="Shodan assets" title="Review approved internet-facing assets." text="Use passive Shodan metadata to understand services belonging to an authorized organization." /><div className="module-grid"><div className="card-surface tool-card"><span className="tool-number">01</span><h3>Authorized asset review</h3><p>Shodan access is limited to passive host metadata. No feed access, login attempts, or arbitrary camera searching.</p><label className="field-label">Organization domain or asset</label><input className="field-input" value={target} onChange={event => setTarget(event.target.value)} placeholder="authorized.example.com" /><label className="confirm-row"><input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} /><span>I confirm this asset is owned by or authorized for assessment.</span></label><button className="button primary" disabled={!authorized} onClick={onReview}>Configure Shodan review →</button></div><div className="card-surface checklist-card"><span className="tool-number">02</span><h3>Passive evidence collected</h3><Check text="IP, ASN, organization and hostnames" /><Check text="Open service ports and banners" /><Check text="Product and server metadata" /><Check text="Remediation notes for exposed services" /><p className="small-note">Key status: {diagnostics?.shodan_key_configured ? 'configured' : 'not detected'}</p></div></div></section>; }
function CameraModule({ checks, setChecks }) { const items = [['ownership', 'Asset ownership confirmed'], ['exposure', 'Public exposure reviewed'], ['auth', 'Authentication settings reviewed'], ['firmware', 'Firmware support status checked'], ['tls', 'HTTPS/TLS configuration reviewed'], ['network', 'Network segmentation reviewed']]; return <section className="module-page"><ModuleHeader overline="Camera security audit" title="Harden cameras in your inventory." text="This checklist is for cameras you own or are explicitly authorized to assess. It never opens feeds or attempts access." /><div className="camera-audit card-surface"><div className="audit-intro"><div><span className="overline">Local audit checklist</span><h2>Security posture</h2></div><span className="audit-score">{Object.values(checks).filter(Boolean).length}/{items.length} reviewed</span></div><div className="audit-list">{items.map(([id, label]) => <label className={checks[id] ? 'audit-row checked' : 'audit-row'} key={id}><input type="checkbox" checked={checks[id]} onChange={() => setChecks(previous => ({ ...previous, [id]: !previous[id] }))} /><span><b>{label}</b><small>{checks[id] ? 'Marked reviewed for this session' : 'Mark after verifying in your authorized inventory'}</small></span><i>{checks[id] ? 'Reviewed' : 'Pending'}</i></label>)}</div></div></section>; }
function ReportsModule({ recentJobs, onJob, stats, entities, exportReport }) { return <section className="module-page"><ModuleHeader overline="Report center" title="Review and export evidence." text="Reopen session jobs and export the current report for your authorized assessment record." /><div className="report-summary"><Metric label="Current entities" value={Object.values(entities).reduce((sum, values) => sum + values.length, 0)} note="Unique extracted values" /><Metric label="Current lines" value={stats.totalLines} note="Captured output" /><Metric label="Session jobs" value={recentJobs.length} note="In-memory only" /><button className="button primary" onClick={exportReport}>Export current report →</button></div><div className="card-surface reports-card"><div className="section-heading"><div><span className="overline">Session history</span><h2>Recent scan jobs</h2></div></div>{recentJobs.length ? <div className="history-list">{recentJobs.map(job => <button className="history-row" key={job.job_id} onClick={() => onJob(job)}><span className="history-domain">{job.domain}<small>{new Date(job.created_at * 1000).toLocaleString()}</small></span><span>{job.sources.includes('all') ? 'All sources' : `${job.sources.length} sources`}</span><span className={`status-tag ${job.status.toLowerCase()}`}>{job.status}</span><span className="history-arrow">→</span></button>)}</div> : <div className="large-empty">No scan jobs are stored in memory yet.</div>}</div></section>; }
function SettingsModule({ apiOnline, apiStatus, diagnostics, onRefresh }) { return <section className="module-page"><ModuleHeader overline="Workspace settings" title="Check local runtime readiness." text="Review non-sensitive connection details before starting an authorized assessment." /><div className="settings-grid"><div className="card-surface settings-card"><span className="tool-number">Runtime</span><h3>Backend connection</h3><div className="setting-line"><span>Status</span><b className={apiOnline ? 'setting-good' : 'setting-bad'}>{apiStatus}</b></div><div className="setting-line"><span>Python</span><b>{diagnostics?.python || 'Unavailable'}</b></div><div className="setting-line"><span>Executable</span><b className="setting-path">{diagnostics?.theharvester_executable || 'Not detected'}</b></div><button className="button secondary" onClick={onRefresh}>Refresh diagnostics</button></div><div className="card-surface settings-card"><span className="tool-number">Safety</span><h3>Configuration boundaries</h3><Check text="Passive collection workflow" /><Check text="Authorized target reminder" /><Check text="API keys never shown in UI" /><Check text="No camera feed access" /><p className="small-note">Shodan status: {diagnostics?.shodan_key_configured ? 'configured' : 'not configured'}</p></div></div></section>; }
function ModuleHeader({ overline, title, text }) { return <div className="module-header"><span className="overline">{overline}</span><h2>{title}</h2><p>{text}</p></div>; }
function Check({ text }) { return <div className="check-line"><span>✓</span>{text}</div>; }

export default App;
