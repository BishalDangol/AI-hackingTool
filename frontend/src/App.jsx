import React, { useEffect, useMemo, useRef, useState } from 'react';

const FALLBACK_SUPPORTED_SOURCES = [
  'anubis', 'baidu', 'bevigil', 'bing', 'bitbucket', 'brave', 'bufferoverun', 'builtwith',
  'censys', 'certspotter', 'chaos', 'commoncrawl', 'criminalip', 'crtsh', 'dehashed',
  'dnsdumpster', 'duckduckgo', 'dymo', 'fofa', 'fullhunt', 'github-code', 'gitlab',
  'hackertarget', 'haveibeenpwned', 'hudsonrock', 'hunter', 'hunterhow', 'intelx', 'leakix',
  'leaklookup', 'linkedin', 'linkedin_links', 'mojeek', 'netcraft', 'netlas', 'omnisint',
  'onyphe', 'otx', 'pentesttools', 'projectdiscovery', 'rapiddns', 'robtex', 'rocketreach',
  'securityscorecard', 'securityTrails', 'sherlockeye', 'shodan', 'shodanInternetDB',
  'subdomaincenter', 'subdomainfinderc99', 'sublist3r', 'thc', 'threatcrowd', 'threatminer',
  'tomba', 'urlscan', 'venacus', 'virustotal', 'waybackarchive', 'whoisxml', 'windvane',
  'yahoo', 'zoomeye', 'zoomeyeapi'
];

const RECOMMENDED_PRESET = ['crtsh', 'dnsdumpster', 'duckduckgo', 'hackertarget', 'otx', 'urlscan', 'rapiddns'];

function unique(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function extractEntities(logs) {
  const text = logs.join('\n');
  const emails = unique(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
  const ips = unique(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []);
  const urls = unique(text.match(/https?:\/\/[^\s<>"']+/gi) || []).map(url => url.replace(/[),.;]+$/, ''));
  const hosts = unique(text.match(/\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || [])
    .filter(host => !emails.some(email => email.endsWith(host)) && !urls.some(url => url.includes(host)));
  const people = unique(logs.flatMap(line => {
    const match = line.match(/^(?:[-*]\s*)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s*$/);
    return match ? [match[1]] : [];
  }));
  return { emails, hosts, ips, people, urls };
}

function summarizeLogs(logs) {
  const text = logs.join('\n');
  const count = (patterns) => patterns.reduce((total, pattern) => total + (text.match(pattern) || []).length, 0);
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
  return (
    <div className="bar-chart">
      {items.map(item => (
        <div className="bar-row" key={item.label}>
          <span>{item.label}</span>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${item.value ? Math.max((item.value / max) * 100, 7) : 0}%`, background: item.color || 'var(--accent)' }} /></div>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

function EntityPanel({ title, icon, values }) {
  return (
    <article className="entity-panel">
      <div className="entity-panel-title"><span className="entity-icon">{icon}</span><h3>{title}</h3><b>{values.length}</b></div>
      {values.length ? (
        <div className="entity-values">{values.slice(0, 30).map(value => <code key={value}>{value}</code>)}</div>
      ) : <p className="empty-state">No values captured in this report.</p>}
      {values.length > 30 && <small>Showing 30 of {values.length}</small>}
    </article>
  );
}

function App() {
  const [apiOnline, setApiOnline] = useState(false);
  const [apiStatusText, setApiStatusText] = useState('Checking connection');
  const [domain, setDomain] = useState('');
  const [domainError, setDomainError] = useState('');
  const [limit, setLimit] = useState(500);
  const [dnsBrute, setDnsBrute] = useState(false);
  const [selectedSources, setSelectedSources] = useState(RECOMMENDED_PRESET);
  const [availableSources, setAvailableSources] = useState(FALLBACK_SUPPORTED_SOURCES);
  const [sourceSearch, setSourceSearch] = useState('');
  const [activePreset, setActivePreset] = useState('recommended');
  const [currentJobId, setCurrentJobId] = useState(null);
  const [currentCommand, setCurrentCommand] = useState('theHarvester -h');
  const [currentStatus, setCurrentStatus] = useState('Idle');
  const [exitCode, setExitCode] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [consoleLogs, setConsoleLogs] = useState(['Ready for a passive collection job.']);
  const [recentJobs, setRecentJobs] = useState([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [activeView, setActiveView] = useState('scan');
  const [isAutoScrollEnabled, setIsAutoScrollEnabled] = useState(true);
  const terminalBodyRef = useRef(null);
  const wsRef = useRef(null);

  const host = typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1';
  const apiHost = host && host !== 'localhost' ? host : '127.0.0.1';
  const API_BASE = `http://${apiHost}:8000`;
  const WS_BASE = `ws://${apiHost}:8000`;

  const chartLogs = useMemo(() => consoleLogs.filter(line => !line.startsWith('[CONNECTION]')), [consoleLogs]);
  const chartStats = useMemo(() => summarizeLogs(chartLogs), [chartLogs]);
  const extractedEntities = useMemo(() => extractEntities(chartLogs), [chartLogs]);
  const filteredSources = useMemo(() => availableSources.filter(source => source.toLowerCase().includes(sourceSearch.toLowerCase())), [availableSources, sourceSearch]);
  const totalEntities = Object.values(extractedEntities).reduce((sum, values) => sum + values.length, 0);

  useEffect(() => {
    checkHealthAndSources();
    fetchRecentJobs();
    const timer = window.setInterval(checkHealthAndSources, 15000);
    return () => {
      window.clearInterval(timer);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (isAutoScrollEnabled && terminalBodyRef.current) terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
  }, [consoleLogs, isAutoScrollEnabled]);

  async function checkHealthAndSources() {
    try {
      const response = await fetch(`${API_BASE}/api/health`);
      setApiOnline(response.ok);
      setApiStatusText(response.ok ? 'API connected' : 'API returned an error');
    } catch {
      setApiOnline(false);
      setApiStatusText('API offline');
    }
    try {
      const response = await fetch(`${API_BASE}/api/sources`);
      if (response.ok) {
        const data = await response.json();
        if (data.sources) setAvailableSources(data.sources);
      }
    } catch {
      // Keep the local fallback list when the API is unavailable.
    }
  }

  async function fetchRecentJobs() {
    try {
      const response = await fetch(`${API_BASE}/api/jobs`);
      if (response.ok) {
        const data = await response.json();
        setRecentJobs(data.jobs || []);
      }
    } catch {
      // History is in-memory and is optional to the scan workspace.
    }
  }

  function validateDomain(value) {
    const candidate = value.trim().toLowerCase();
    if (!candidate) return 'Enter a target domain.';
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(candidate)) return 'Use a valid domain such as example.com.';
    return '';
  }

  function toggleSource(source) {
    setActivePreset('custom');
    if (source === 'all') {
      if (selectedSources.includes('all')) {
        setSelectedSources(RECOMMENDED_PRESET);
        setActivePreset('recommended');
      } else setSelectedSources(['all']);
      return;
    }
    setSelectedSources(current => current.includes('all') ? [source] : current.includes(source) ? current.filter(item => item !== source) : [...current, source]);
  }

  function applyPreset(preset) {
    setActivePreset(preset);
    if (preset === 'recommended') setSelectedSources(RECOMMENDED_PRESET);
    if (preset === 'all') setSelectedSources(['all']);
    if (preset === 'clear') setSelectedSources([]);
  }

  async function pollJobResult(jobId, attempt = 0) {
    if (attempt >= 120) {
      setCurrentStatus('Error');
      setErrorMessage('Result polling timed out. Check the backend terminal.');
      setIsSubmitting(false);
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/api/scan/${jobId}/result`);
      if (!response.ok) throw new Error(`Result endpoint returned ${response.status}`);
      const data = await response.json();
      setConsoleLogs(data.output_lines || []);
      setCurrentStatus(data.status);
      setExitCode(data.exit_code);
      setErrorMessage(data.error_message || null);
      if (data.status === 'Running' || data.status === 'Queued') window.setTimeout(() => pollJobResult(jobId, attempt + 1), 1000);
      else {
        setIsSubmitting(false);
        fetchRecentJobs();
      }
    } catch (error) {
      setErrorMessage(error.message || 'Could not retrieve the scan result.');
      setIsSubmitting(false);
    }
  }

  function connectWebSocket(jobId) {
    if (wsRef.current) wsRef.current.close();
    const socket = new WebSocket(`${WS_BASE}/api/scan/${jobId}/stream`);
    wsRef.current = socket;
    let settled = false;
    let fallbackStarted = false;
    const startFallback = () => {
      if (fallbackStarted || settled) return;
      fallbackStarted = true;
      setConsoleLogs(previous => [...previous.filter(line => !line.startsWith('[CONNECTION]')), '[CONNECTION] Live stream unavailable; using result polling.']);
      pollJobResult(jobId);
    };
    socket.onmessage = event => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'command') setCurrentCommand(payload.data);
        if (payload.type === 'status') setCurrentStatus(payload.status);
        if (payload.type === 'output') setConsoleLogs(previous => [...previous, payload.data]);
        if (payload.type === 'done') {
          settled = true;
          setCurrentStatus(payload.status);
          setExitCode(payload.exit_code);
          setErrorMessage(payload.error_message || null);
          setIsSubmitting(false);
          fetchRecentJobs();
        }
      } catch {
        setConsoleLogs(previous => [...previous, event.data]);
      }
    };
    socket.onerror = startFallback;
    socket.onclose = () => { if (!settled) startFallback(); };
  }

  async function handleStartScan(event) {
    event.preventDefault();
    const validationError = validateDomain(domain);
    setDomainError(validationError);
    if (validationError || !selectedSources.length) return;
    setIsSubmitting(true);
    setActiveView('scan');
    setCurrentStatus('Queued');
    setExitCode(null);
    setErrorMessage(null);
    setConsoleLogs([]);
    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim(), sources: selectedSources, limit: Number(limit), dns_brute: Boolean(dnsBrute) })
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `Backend returned ${response.status}`);
      }
      const data = await response.json();
      setCurrentJobId(data.job_id);
      setCurrentCommand(data.command_str || `theHarvester -d ${domain.trim()}`);
      connectWebSocket(data.job_id);
    } catch (error) {
      setCurrentStatus('Error');
      setErrorMessage(error.message || 'Could not start the scan.');
      setConsoleLogs([`[ERROR] ${error.message || 'Could not start the scan.'}`]);
      setIsSubmitting(false);
    }
  }

  async function selectJob(job) {
    setActiveView('scan');
    setCurrentJobId(job.job_id);
    setDomain(job.domain);
    setSelectedSources(job.sources);
    setLimit(job.limit);
    setDnsBrute(job.dns_brute);
    setCurrentCommand(job.command_str || `theHarvester -d ${job.domain}`);
    setCurrentStatus(job.status);
    setExitCode(job.exit_code);
    setErrorMessage(null);
    try {
      const response = await fetch(`${API_BASE}/api/scan/${job.job_id}/result`);
      const data = await response.json();
      setConsoleLogs(data.output_lines || []);
      if (data.status === 'Running' || data.status === 'Queued') connectWebSocket(job.job_id);
    } catch {
      setConsoleLogs(['[ERROR] Could not load this scan result.']);
    }
  }

  function downloadReport() {
    if (currentJobId) window.open(`${API_BASE}/api/scan/${currentJobId}/download`, '_blank');
    else {
      const blob = new Blob([consoleLogs.join('\n')], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `theHarvester_${domain || 'report'}.txt`;
      link.click();
      URL.revokeObjectURL(url);
    }
  }

  function copyCommand() {
    navigator.clipboard?.writeText(currentCommand);
  }

  function logClass(line) {
    if (/\[(ERROR|STDERR)\]/i.test(line)) return 'log-danger';
    if (/\[WARNING\]|\[!\]/i.test(line)) return 'log-warning';
    if (/\[SUCCESS\]|\[\+\]|Found /i.test(line)) return 'log-success';
    if (/^theHarvester|^\$/i.test(line)) return 'log-command';
    return '';
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block"><div className="brand-mark">H</div><div><strong>Harvester</strong><span>OSINT workspace</span></div></div>
        <div className="sidebar-section-label">Workspace</div>
        <nav className="main-nav">
          <button className={activeView === 'scan' ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView('scan')}><span>⌁</span>Scan workspace</button>
          <button className={activeView === 'history' ? 'nav-item active' : 'nav-item'} onClick={() => { setActiveView('history'); fetchRecentJobs(); }}><span>◷</span>Scan history</button>
        </nav>
        <div className="sidebar-bottom">
          <div className="scope-note"><span className="scope-dot" />Passive collection only</div>
          <p>Use this workspace only for domains and assets you own or are authorized to assess.</p>
          <div className="sidebar-version">Local operator console <span>v1.0</span></div>
        </div>
      </aside>

      <main className="main-shell">
        <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> {activeView === 'scan' ? 'Scan' : 'History'}</div><div className={apiOnline ? 'connection-pill online' : 'connection-pill'}><span />{apiStatusText}</div></header>

        <section className="page-intro">
          <div><div className="overline">Passive intelligence console</div><h1>{activeView === 'scan' ? 'Investigate an external footprint.' : 'Review recent investigations.'}</h1><p>{activeView === 'scan' ? 'Collect public domain intelligence from approved sources, then review the evidence in one focused workspace.' : 'Select a completed job to reopen its captured output and extracted entities.'}</p></div>
          <div className="intro-stat"><span>Current target</span><strong>{domain || 'No target selected'}</strong><small>{currentStatus} {currentJobId ? `· ${currentJobId.slice(0, 8)}` : ''}</small></div>
        </section>

        {activeView === 'history' ? (
          <section className="history-view card-surface"><div className="section-heading"><div><span className="overline">Stored in this session</span><h2>Recent scan jobs</h2></div><button className="button secondary" onClick={fetchRecentJobs}>Refresh</button></div>{recentJobs.length ? <div className="history-list">{recentJobs.map(job => <button className="history-row" key={job.job_id} onClick={() => selectJob(job)}><span className="history-domain">{job.domain}<small>{new Date(job.created_at * 1000).toLocaleString()}</small></span><span>{job.sources.includes('all') ? 'All sources' : `${job.sources.length} sources`}</span><span className={`status-tag ${job.status.toLowerCase()}`}>{job.status}</span><span className="history-arrow">→</span></button>)}</div> : <div className="large-empty">No scan jobs are stored in memory yet.</div>}</section>
        ) : (
          <div className="workspace-grid">
            <section className="config-column">
              <div className="card-surface config-card"><div className="section-heading compact"><div><span className="overline">Step 01</span><h2>Configure collection</h2></div><span className="step-badge">Passive</span></div>
                <form onSubmit={handleStartScan}>
                  <label className="field-label">Target domain <span>Required</span></label>
                  <input className={domainError ? 'field-input invalid' : 'field-input'} value={domain} onChange={event => { setDomain(event.target.value); setDomainError(validateDomain(event.target.value)); }} placeholder="example.com" autoComplete="off" />
                  {domainError && <p className="field-error">{domainError}</p>}
                  <div className="field-row"><div><label className="field-label">Result limit</label><input className="field-input" type="number" min="1" max="5000" value={limit} onChange={event => setLimit(event.target.value)} /></div><label className={dnsBrute ? 'toggle-card checked' : 'toggle-card'}><input type="checkbox" checked={dnsBrute} onChange={event => setDnsBrute(event.target.checked)} /><span><b>DNS brute force</b><small>Enumerate likely subdomains</small></span><i>{dnsBrute ? 'On' : 'Off'}</i></label></div>
                  <div className="sources-heading"><label className="field-label">Sources <span>{selectedSources.includes('all') ? 'All selected' : `${selectedSources.length} selected`}</span></label><div className="preset-row"><button type="button" className={activePreset === 'recommended' ? 'preset active' : 'preset'} onClick={() => applyPreset('recommended')}>Recommended</button><button type="button" className={activePreset === 'all' ? 'preset active' : 'preset'} onClick={() => applyPreset('all')}>All</button><button type="button" className="preset" onClick={() => applyPreset('clear')}>Clear</button></div></div>
                  <input className="search-input" value={sourceSearch} onChange={event => setSourceSearch(event.target.value)} placeholder="Search sources" />
                  <div className="source-list"><label className={selectedSources.includes('all') ? 'source-option selected' : 'source-option'}><input type="checkbox" checked={selectedSources.includes('all')} onChange={() => toggleSource('all')} /><span>All supported sources</span></label>{filteredSources.map(source => <label className={selectedSources.includes('all') || selectedSources.includes(source) ? 'source-option selected' : 'source-option'} key={source}><input type="checkbox" checked={selectedSources.includes('all') || selectedSources.includes(source)} disabled={selectedSources.includes('all')} onChange={() => toggleSource(source)} /><span>{source}</span></label>)}</div>
                  <button className="button primary launch-button" type="submit" disabled={isSubmitting || !!domainError || !domain.trim() || !selectedSources.length}><span>{isSubmitting ? 'Running collection…' : 'Start passive collection'}</span><b>↗</b></button>
                </form>
              </div>
            </section>

            <section className="results-column">
              <div className="result-header card-surface"><div><span className="overline">Step 02 · Live evidence</span><h2>{domain || 'Awaiting a target'}</h2><div className="command-line"><span>$</span>{currentCommand}</div></div><div className="result-actions"><span className={`status-tag ${currentStatus.toLowerCase()}`}>{currentStatus}{exitCode !== null ? ` · ${exitCode}` : ''}</span><button className="icon-button" onClick={copyCommand} title="Copy command">Copy</button><button className="button secondary small" onClick={downloadReport}>Export report</button></div></div>
              {errorMessage && <div className="alert-card"><span>!</span><div><b>Collection needs attention</b><p>{errorMessage}</p></div></div>}
              <div className="metric-grid"><div className="metric-card"><span>Captured entities</span><strong>{totalEntities}</strong><small>Unique values</small></div><div className="metric-card"><span>Output lines</span><strong>{chartStats.totalLines}</strong><small>From live report</small></div><div className="metric-card"><span>Sources selected</span><strong>{selectedSources.includes('all') ? 'All' : selectedSources.length}</strong><small>Configured engines</small></div><div className="metric-card"><span>Scan state</span><strong className="metric-state">{currentStatus}</strong><small>{apiOnline ? 'Backend reachable' : 'Check backend'}</small></div></div>

              <div className="terminal-card card-surface"><div className="terminal-heading"><div><span className="overline">Live output</span><h3>Collection stream</h3></div><span className="terminal-meta">{chartStats.totalLines} lines</span></div><div className="terminal-body" ref={terminalBodyRef} onScroll={() => { if (!terminalBodyRef.current) return; const distance = terminalBodyRef.current.scrollHeight - terminalBodyRef.current.scrollTop - terminalBodyRef.current.clientHeight; setIsAutoScrollEnabled(distance < 45); }}>{consoleLogs.map((line, index) => <div className={`log-line ${logClass(line)}`} key={`${index}-${line}`}>{line}</div>)}{currentStatus === 'Running' && <div className="log-line log-live"><span />Waiting for provider output…</div>}</div>{!isAutoScrollEnabled && <button className="resume-button" onClick={() => { setIsAutoScrollEnabled(true); terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight; }}>Resume live view</button>}</div>

              <div className="insights-heading"><div><span className="overline">Step 03 · Review</span><h2>Collected intelligence</h2></div><span className="insight-note">Only values found in the report are shown</span></div>
              <div className="entity-grid"><EntityPanel title="Email addresses" icon="@" values={extractedEntities.emails} /><EntityPanel title="Hosts & domains" icon="◇" values={extractedEntities.hosts} /><EntityPanel title="IP addresses" icon="#" values={extractedEntities.ips} /><EntityPanel title="People" icon="◌" values={extractedEntities.people} /><EntityPanel title="URLs" icon="↗" values={extractedEntities.urls} /></div>
              <div className="analytics-grid"><div className="analytics-card card-surface"><div className="analytics-title"><div><span className="overline">Distribution</span><h3>Report indicators</h3></div></div><BarChart items={chartStats.entities} /></div><div className="analytics-card card-surface"><div className="analytics-title"><div><span className="overline">Health</span><h3>Provider events</h3></div></div><BarChart items={chartStats.events} /></div></div>
            </section>
          </div>
        )}
        <footer className="app-footer">Harvester OSINT workspace <span>·</span> Passive, authorized collection only <span>·</span> Local session</footer>
      </main>
    </div>
  );
}

export default App;
