import React, { useState, useEffect, useRef } from 'react';

const FALLBACK_SUPPORTED_SOURCES = [
  'baidu', 'bevigil', 'bitbucket', 'brave', 'bufferoverun', 'builtwith', 'censys',
  'certspotter', 'chaos', 'commoncrawl', 'criminalip', 'crtsh', 'dehashed', 'dnsdumpster',
  'duckduckgo', 'dymo', 'fofa', 'fullhunt', 'github-code', 'gitlab', 'hackertarget',
  'haveibeenpwned', 'hudsonrock', 'hunter', 'hunterhow', 'intelx', 'leakix', 'leaklookup',
  'linkedin', 'linkedin_links', 'mojeek', 'netcraft', 'netlas', 'omnisint', 'onyphe',
  'otx', 'pentesttools', 'projectdiscovery', 'rapiddns', 'robtex', 'rocketreach',
  'securityscorecard', 'securityTrails', 'sherlockeye', 'shodan', 'shodanInternetDB',
  'subdomaincenter', 'subdomainfinderc99', 'sublist3r', 'thc', 'threatcrowd', 'tomba',
  'urlscan', 'venacus', 'virustotal', 'waybackarchive', 'whoisxml', 'windvane', 'yahoo',
  'zoomeye', 'zoomeyeapi', 'anubis', 'bing', 'threatminer'
];

const RECOMMENDED_PRESET = [
  'crtsh', 'dnsdumpster', 'duckduckgo', 'hackertarget', 'otx', 'urlscan', 'rapiddns', 'bevigil', 'brave'
];

function summarizeLogs(logs) {
  const text = logs.join('\n');
  const countMatches = (patterns) => patterns.reduce((total, pattern) => total + (text.match(pattern) || []).length, 0);
  const sourceLines = logs.filter(line => /\[(SUCCESS|ERROR|WARNING|STDERR)\]/i.test(line));
  const counts = {
    emails: countMatches([/emails? found/gi, /email addresses?/gi]),
    hosts: countMatches([/hosts? found/gi, /subdomains? found/gi, /hostnames? found/gi]),
    ips: countMatches([/ips? found/gi, /ip addresses?/gi]),
    urls: countMatches([/urls? found/gi, /urls? discovered/gi]),
  };
  return {
    entities: Object.entries(counts).map(([label, value]) => ({ label: label.toUpperCase(), value })),
    events: [
      { label: 'SUCCESS', value: sourceLines.filter(line => /\[SUCCESS\]/i.test(line)).length, color: 'var(--success)' },
      { label: 'WARNING', value: sourceLines.filter(line => /\[WARNING\]/i.test(line)).length, color: 'var(--warning)' },
      { label: 'ERROR', value: sourceLines.filter(line => /\[(ERROR|STDERR)\]/i.test(line)).length, color: 'var(--error)' },
    ],
    sources: [...new Set(logs.flatMap(line => {
      const match = line.match(/(?:source|engine)[:=]\s*([a-z0-9_-]+)/i);
      return match ? [match[1]] : [];
    }))].slice(0, 8),
    totalLines: logs.length,
  };
}

function extractEntities(logs) {
  const text = logs.join('\n');
  const unique = (values) => [...new Set(values)].sort((a, b) => a.localeCompare(b));
  const emails = unique(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []);
  const ips = unique(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []);
  const urls = unique(text.match(/https?:\/\/[^\s<>"']+/gi) || []).map(url => url.replace(/[),.;]+$/, ''));
  const hosts = unique(text.match(/\b(?=[a-z0-9.-]{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || [])
    .filter(host => !emails.some(email => email.endsWith(host)) && !urls.some(url => url.includes(host)));
  const people = unique(logs.flatMap(line => {
    const match = line.match(/^(?:[-*]\s*)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\s*$/);
    return match ? [match[1]] : [];
  }));
  return { emails, hosts, ips, urls, people };
}

function EntityList({ title, values, emptyLabel = 'None captured' }) {
  return (
    <div className="entity-card">
      <div className="entity-card-heading"><h3>{title}</h3><span>{values.length}</span></div>
      {values.length ? (
        <div className="entity-list">{values.slice(0, 30).map(value => <code key={value}>{value}</code>)}</div>
      ) : <div className="chart-empty">{emptyLabel}</div>}
      {values.length > 30 && <small className="entity-more">Showing 30 of {values.length}</small>}
    </div>
  );
}

function BarChart({ items, emptyLabel = 'No captured data yet.' }) {
  const max = Math.max(...items.map(item => item.value), 1);
  if (!items.length || items.every(item => item.value === 0)) {
    return <div className="chart-empty">{emptyLabel}</div>;
  }
  return (
    <div className="bar-chart">
      {items.map(item => (
        <div className="bar-row" key={item.label}>
          <span className="bar-label">{item.label}</span>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${Math.max((item.value / max) * 100, item.value ? 6 : 0)}%`, background: item.color || 'linear-gradient(90deg, var(--accent), var(--cyan))' }} /></div>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

function App() {
  // Backend connection state
  const [apiOnline, setApiOnline] = useState(false);
  const [apiStatusText, setApiStatusText] = useState('Checking API...');

  // Form input state
  const [domain, setDomain] = useState('');
  const [domainError, setDomainError] = useState('');
  const [limit, setLimit] = useState(500);
  const [dnsBrute, setDnsBrute] = useState(false);
  const [selectedSources, setSelectedSources] = useState(RECOMMENDED_PRESET);
  const [availableSources, setAvailableSources] = useState(FALLBACK_SUPPORTED_SOURCES);
  const [sourceSearch, setSourceSearch] = useState('');
  const [activePreset, setActivePreset] = useState('recommended');

  // Job execution & terminal state
  const [currentJobId, setCurrentJobId] = useState(null);
  const [currentCommand, setCurrentCommand] = useState('$ theHarvester -h');
  const [currentStatus, setCurrentStatus] = useState('Idle'); // Idle | Queued | Running | Finished | Error
  const [exitCode, setExitCode] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [consoleLogs, setConsoleLogs] = useState([
    '# Welcome to theHarvester OSINT Studio.',
    '# Enter a target domain and select your passive intelligence sources on the left.',
    '# Live reconnaissance output will stream directly into this console.'
  ]);

  const [isAutoScrollEnabled, setIsAutoScrollEnabled] = useState(true);
  const terminalBodyRef = useRef(null);
  const wsRef = useRef(null);

  // History state
  const [activeTab, setActiveTab] = useState('terminal'); // terminal | history
  const [recentJobs, setRecentJobs] = useState([]);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Determine API base URL dynamically or fallback to localhost:8000
  const getApiHost = () => {
    const host = window.location.hostname;
    return host && host !== 'localhost' ? host : '127.0.0.1';
  };
  const API_BASE = `http://${getApiHost()}:8000`;
  const WS_BASE = `ws://${getApiHost()}:8000`;

  // Check health and fetch sources on mount
  useEffect(() => {
    checkHealthAndSources();
    const interval = setInterval(checkHealthAndSources, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkHealthAndSources = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      if (res.ok) {
        setApiOnline(true);
        setApiStatusText('API Online');
      } else {
        setApiOnline(false);
        setApiStatusText('API Error');
      }
    } catch {
      setApiOnline(false);
      setApiStatusText('API Offline');
    }

    try {
      const srcRes = await fetch(`${API_BASE}/api/sources`);
      if (srcRes.ok) {
        const data = await srcRes.json();
        if (data && data.sources) {
          setAvailableSources(data.sources);
        }
      }
    } catch {
      // Use fallback already set
    }
  };

  const fetchRecentJobs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/jobs`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.jobs) {
          setRecentJobs(data.jobs);
        }
      }
    } catch {
      // Ignore errors when listing jobs
    }
  };

  // Handle Terminal Auto-scroll with Pause-on-Scroll-Up behavior
  const handleTerminalScroll = () => {
    if (!terminalBodyRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = terminalBodyRef.current;
    const distanceToBottom = scrollHeight - scrollTop - clientHeight;
    if (distanceToBottom > 45) {
      if (isAutoScrollEnabled) setIsAutoScrollEnabled(false);
    } else {
      if (!isAutoScrollEnabled) setIsAutoScrollEnabled(true);
    }
  };

  useEffect(() => {
    if (isAutoScrollEnabled && terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [consoleLogs, isAutoScrollEnabled]);

  // Domain Regex validation
  const validateDomain = (val) => {
    const trimmed = val.trim().toLowerCase();
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!trimmed) {
      return 'Domain is required.';
    }
    if (!domainRegex.test(trimmed)) {
      return 'Invalid domain format (e.g. example.com). No spaces or symbols allowed.';
    }
    return '';
  };

  const handleDomainChange = (e) => {
    const val = e.target.value;
    setDomain(val);
    if (val) {
      setDomainError(validateDomain(val));
    } else {
      setDomainError('');
    }
  };

  // Toggle single source checkbox
  const handleSourceToggle = (src) => {
    setActivePreset('custom');
    if (src === 'all') {
      if (selectedSources.includes('all')) {
        setSelectedSources(RECOMMENDED_PRESET);
        setActivePreset('recommended');
      } else {
        setSelectedSources(['all']);
        setActivePreset('all');
      }
      return;
    }

    let nextSources;
    if (selectedSources.includes('all')) {
      nextSources = [src];
    } else if (selectedSources.includes(src)) {
      nextSources = selectedSources.filter(s => s !== src);
    } else {
      nextSources = [...selectedSources, src];
    }
    setSelectedSources(nextSources);
  };

  const applyPreset = (presetType) => {
    setActivePreset(presetType);
    if (presetType === 'recommended') {
      setSelectedSources(RECOMMENDED_PRESET);
    } else if (presetType === 'all') {
      setSelectedSources(['all']);
    } else if (presetType === 'clear') {
      setSelectedSources([]);
    }
  };

  // Poll the REST result endpoint when WebSocket support is unavailable.
  const pollJobResult = async (jobId, attempt = 0) => {
    if (attempt >= 120) {
      setCurrentStatus('Error');
      setErrorMessage('Live stream unavailable and REST polling timed out. Check the backend log.');
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
      if (data.status === 'Running' || data.status === 'Queued') {
        window.setTimeout(() => pollJobResult(jobId, attempt + 1), 1000);
      } else {
        setIsSubmitting(false);
        fetchRecentJobs();
      }
    } catch (error) {
      setErrorMessage(error.message || 'Could not retrieve scan results.');
      setIsSubmitting(false);
    }
  };

  // Connect to WebSocket to stream live output
  const connectWebSocket = (jobId) => {
    if (wsRef.current) {
      wsRef.current.close();
    }

    const wsUrl = `${WS_BASE}/api/scan/${jobId}/stream`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    let fallbackStarted = false;
    const startFallback = () => {
      if (fallbackStarted) return;
      fallbackStarted = true;
      setConsoleLogs(prev => [...prev.filter(line => !line.startsWith('[CONNECTION]')), '[CONNECTION] WebSocket unavailable; using REST result polling.']);
      pollJobResult(jobId);
    };

    ws.onopen = () => {
      // Connected successfully
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'command') {
          setCurrentCommand(payload.data);
        } else if (payload.type === 'status') {
          setCurrentStatus(payload.status);
        } else if (payload.type === 'output') {
          setConsoleLogs(prev => [...prev, payload.data]);
        } else if (payload.type === 'done') {
          setCurrentStatus(payload.status);
          setExitCode(payload.exit_code);
          setErrorMessage(payload.error_message);
          setIsSubmitting(false);
          fetchRecentJobs();
        }
      } catch {
        // If raw string
        setConsoleLogs(prev => [...prev, event.data]);
      }
    };

    ws.onerror = () => {
      startFallback();
    };

    ws.onclose = () => {
      if (currentStatus === 'Running' || currentStatus === 'Queued') {
        startFallback();
      }
    };
  };

  // Submit scan job
  const handleStartScan = async (e) => {
    e.preventDefault();
    const err = validateDomain(domain);
    if (err) {
      setDomainError(err);
      return;
    }
    if (!selectedSources || selectedSources.length === 0) {
      alert('Please select at least one data source.');
      return;
    }

    setIsSubmitting(true);
    setCurrentStatus('Queued');
    setExitCode(null);
    setErrorMessage(null);
    setActiveTab('terminal');
    setIsAutoScrollEnabled(true);
    setConsoleLogs([
      `# Initializing recon scan for domain: ${domain.trim()}`,
      `# Selected sources: ${selectedSources.join(', ')}`,
      `# Limit: ${limit} | DNS Brute: ${dnsBrute ? 'Enabled (-c)' : 'Disabled'}`,
      `# Connecting to backend executor...`
    ]);

    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          domain: domain.trim(),
          sources: selectedSources,
          limit: Number(limit),
          dns_brute: Boolean(dnsBrute)
        })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error (${response.status})`);
      }

      const data = await response.json();
      setCurrentJobId(data.job_id);
      if (data.command_str) {
        setCurrentCommand(data.command_str);
      }

      // Connect to WebSocket stream immediately
      setConsoleLogs([]); // Clear initialization messages to show pure command & stream
      connectWebSocket(data.job_id);

    } catch (error) {
      setCurrentStatus('Error');
      setErrorMessage(error.message || 'Failed to trigger scan job.');
      setConsoleLogs(prev => [...prev, `[ERROR] ${error.message}`]);
      setIsSubmitting(false);
    }
  };

  // View historical job details
  const handleSelectRecentJob = async (job) => {
    setCurrentJobId(job.job_id);
    setDomain(job.domain);
    setSelectedSources(job.sources);
    setLimit(job.limit);
    setDnsBrute(job.dns_brute);
    setCurrentCommand(job.command_str || `theHarvester -d ${job.domain}`);
    setCurrentStatus(job.status);
    setExitCode(job.exit_code);
    setErrorMessage(null);
    setActiveTab('terminal');
    setIsAutoScrollEnabled(true);

    try {
      const res = await fetch(`${API_BASE}/api/scan/${job.job_id}/result`);
      if (res.ok) {
        const data = await res.json();
        setConsoleLogs(data.output_lines || []);
        if (data.status === 'Running') {
          connectWebSocket(job.job_id);
        }
      }
    } catch {
      setConsoleLogs([`[ERROR] Could not load results for Job ${job.job_id}`]);
    }
  };

  // Download Output .txt file
  const handleDownloadOutput = async () => {
    if (!currentJobId) {
      // Fallback blob download if no jobId yet
      const blob = new Blob([consoleLogs.join('\n')], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `theHarvester_${domain || 'recon'}_output.txt`;
      link.click();
      return;
    }

    // Use clean backend attachment endpoint
    window.open(`${API_BASE}/api/scan/${currentJobId}/download`, '_blank');
  };

  // Copy command string to clipboard
  const handleCopyCommand = () => {
    navigator.clipboard.writeText(currentCommand);
    alert('Command copied to clipboard!');
  };

  // Filter sources for display
  const chartLogs = consoleLogs.filter(line => !line.startsWith('[CONNECTION]'));
  const chartStats = summarizeLogs(chartLogs);
  const extractedEntities = extractEntities(chartLogs);
  const filteredSources = availableSources.filter(s =>
    s.toLowerCase().includes(sourceSearch.toLowerCase())
  );

  // Helper for terminal log coloring
  const getLogClass = (line) => {
    if (line.includes('[SUCCESS]') || line.includes('[+]') || line.includes('Found ')) return 'line-success';
    if (line.includes('[ERROR]') || line.includes('[-]')) return 'line-error';
    if (line.includes('[WARNING]') || line.includes('[!]')) return 'line-warning';
    if (line.includes('[STDERR]')) return 'line-stderr';
    if (line.startsWith('$') || line.startsWith('theHarvester')) return 'line-command';
    if (line.includes('[*]') || line.includes('[INFO]')) return 'line-info';
    return '';
  };

  return (
    <div className="app-wrapper">
      {/* Top Header */}
      <header className="top-header">
        <div className="brand">
          <div className="brand-icon">CS</div>
          <div className="brand-text">
            <h1>Cyber Shield</h1>

            
            <p>Passive Reconnaissance & Domain Intelligence Console</p>
          </div>
        </div>
        <div className="header-status">
          <div className={`status-pill ${apiOnline ? 'online' : 'offline'}`}>
            <span className="pulse-dot"></span>
            <span>{apiStatusText}</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="main-container">
        {/* Left Column: Form Setup */}
        <section className="glass-card form-section">
          <div className="card-heading">
            <h2>Recon Configuration</h2>
          </div>

          <form onSubmit={handleStartScan} className="form-section">
            {/* Target Domain Input */}
            <div className="field-group">
              <label className="field-label">
                <span>Target Domain</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Strict Validated</span>
              </label>
              <div className="input-with-icon">
                <span className="input-icon"></span>
                <input
                  type="text"
                  className={`text-input ${domainError ? 'input-error' : ''}`}
                  placeholder="example.com"
                  value={domain}
                  onChange={handleDomainChange}
                  required
                />
              </div>
              {domainError && <div className="error-hint">{domainError}</div>}
            </div>

            {/* Limit Input & DNS Brute Checkbox */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="field-group">
                <label className="field-label"><span>Result Limit (-l)</span></label>
                <input
                  type="number"
                  className="number-input"
                  min="1"
                  max="5000"
                  step="1"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                  required
                />
              </div>

              <div className="field-group" style={{ justifyContent: 'flex-end' }}>
                <div
                  className={`checkbox-card ${dnsBrute ? 'active' : ''}`}
                  onClick={() => setDnsBrute(!dnsBrute)}
                >
                  <div className="checkbox-info">
                    <h4>DNS Brute (-c)</h4>
                    <p>Subdomain brute force</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={dnsBrute}
                    onChange={() => setDnsBrute(!dnsBrute)}
                    style={{ accentColor: 'var(--cyan)', width: '18px', height: '18px' }}
                  />
                </div>
              </div>
            </div>

            {/* Data Sources Multi-Select Box */}
            <div className="field-group">
              <div className="sources-header-bar">
                <label className="field-label">
                  <span>Data Sources (-b)</span>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>
                    {selectedSources.includes('all') ? 'ALL Sources' : `${selectedSources.length} Selected`}
                  </span>
                </label>
                <div className="preset-buttons">
                  <button
                    type="button"
                    className={`preset-btn ${activePreset === 'recommended' ? 'active' : ''}`}
                    onClick={() => applyPreset('recommended')}
                  >
                    Recommended
                  </button>
                  <button
                    type="button"
                    className={`preset-btn ${activePreset === 'all' ? 'active' : ''}`}
                    onClick={() => applyPreset('all')}
                  >
                    All (-b all)
                  </button>
                  <button
                    type="button"
                    className="preset-btn"
                    onClick={() => applyPreset('clear')}
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Source Search Bar */}
              <input
                type="text"
                className="sources-search-input"
                placeholder="Filter sources (e.g. crtsh, shodan, urlscan)..."
                value={sourceSearch}
                onChange={(e) => setSourceSearch(e.target.value)}
              />

              {/* Sources Grid Checkboxes */}
              <div className="sources-grid-box">
                <label
                  key="source-all"
                  className={`source-checkbox-label ${selectedSources.includes('all') ? 'selected' : ''}`}
                >
                  <input
                    type="checkbox"
                    checked={selectedSources.includes('all')}
                    onChange={() => handleSourceToggle('all')}
                  />
                  <span>ALL SOURCES (-b all)</span>
                </label>

                {filteredSources.map(src => {
                  const isChecked = selectedSources.includes('all') || selectedSources.includes(src);
                  return (
                    <label
                      key={src}
                      className={`source-checkbox-label ${isChecked ? 'selected' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleSourceToggle(src)}
                        disabled={selectedSources.includes('all')}
                      />
                      <span>{src}</span>
                    </label>
                  );
                })}
                {filteredSources.length === 0 && (
                  <div style={{ padding: '10px', color: 'var(--text-dim)', fontSize: '0.8rem', gridColumn: '1 / -1' }}>
                    No matching sources found.
                  </div>
                )}
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              className="submit-btn"
              disabled={isSubmitting || !!domainError || !domain.trim() || selectedSources.length === 0}
            >
              {isSubmitting ? (
                <>
                  <span className="spinner"></span>
                  <span>Executing Scan Job...</span>
                </>
              ) : (
                <>
                  <span>▶ Launch Recon Scan</span>
                </>
              )}
            </button>
          </form>
        </section>

        {/* Right Column: Live Output / History */}
        <section className="content-area">
          {/* Command Display Box */}
          <div className="command-box-card">
            <div className="command-content">
              <span className="prompt-symbol">❯</span>
              <span className="command-text" title={currentCommand}>
                {currentCommand}
              </span>
            </div>
            <button type="button" className="copy-btn" onClick={handleCopyCommand}>
              <span>Copy</span>
            </button>
          </div>

          {/* Status Indicators & View Toggle Bar */}
          <div className="status-bar">
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>Status:</span>
              <span className={`status-badge ${currentStatus}`}>
                {currentStatus === 'Running' && <span className="spinner" style={{ width: '12px', height: '12px', borderWidth: '2px' }}></span>}
                {currentStatus}
                {exitCode !== null && ` (Exit: ${exitCode})`}
              </span>
              {errorMessage && (
                <span style={{ fontSize: '0.82rem', color: 'var(--error)', maxWidth: '400px' }}>
                  {errorMessage}
                </span>
              )}
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <button
                type="button"
                className={`history-toggle-btn ${activeTab === 'terminal' ? 'active' : ''}`}
                onClick={() => setActiveTab('terminal')}
              >
                Live Terminal Output
              </button>
              <button
                type="button"
                className={`history-toggle-btn ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => {
                  setActiveTab('history');
                  fetchRecentJobs();
                }}
              >
                Recent Scan Jobs
              </button>
              {(currentStatus === 'Finished' || currentStatus === 'Error' || consoleLogs.length > 5) && (
                <button
                  type="button"
                  className="download-btn"
                  onClick={handleDownloadOutput}
                  title="Download .txt report"
                >
                  <span>Download Report (.txt)</span>
                </button>
              )}
            </div>
          </div>

          {/* Terminal View */}
          {activeTab === 'terminal' ? (
            <div className="terminal-panel">
              <div className="terminal-top-bar">
                <div className="mac-buttons">
                  <span className="mac-btn close"></span>
                  <span className="mac-btn minimize"></span>
                  <span className="mac-btn maximize"></span>
                </div>
                <div className="terminal-tab-title">
                  <span>bash — theHarvester — {currentStatus}</span>
                </div>
                <div className="terminal-actions">
                  <button
                    type="button"
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: '0.75rem', cursor: 'pointer' }}
                    onClick={() => setConsoleLogs([])}
                  >
                    Clear Console
                  </button>
                </div>
              </div>

              {/* Terminal Logs Body */}
              <div
                className="terminal-body"
                ref={terminalBodyRef}
                onScroll={handleTerminalScroll}
              >
                {consoleLogs.map((line, idx) => (
                  <div key={idx} className={`log-entry ${getLogClass(line)}`}>
                    {line}
                  </div>
                ))}
                {currentStatus === 'Running' && (
                  <div className="log-entry line-info" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
                    <span className="spinner" style={{ width: '12px', height: '12px' }}></span>
                    <span>Reconnaissance process active... waiting for stream output...</span>
                  </div>
                )}
              </div>

              {/* Floating Resume Auto-Scroll Button */}
              {!isAutoScrollEnabled && currentStatus === 'Running' && (
                <button
                  type="button"
                  className="scroll-resume-toast"
                  onClick={() => {
                    setIsAutoScrollEnabled(true);
                    if (terminalBodyRef.current) {
                      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
                    }
                  }}
                >
                  <span>↓ Resume Auto-scroll</span>
                </button>
              )}
              <div className="results-dashboard">
                <div className="results-dashboard-heading">
                  <div>
                    <span className="eyebrow">Captured intelligence</span>
                    <h2>Scan result charts</h2>
                  </div>
                  <span className="result-line-count">{chartStats.totalLines} captured lines</span>
                </div>
                <div className="chart-grid">
                  <div className="chart-card">
                    <h3>Entity indicators</h3>
                    <BarChart items={chartStats.entities} emptyLabel="Counts appear as providers report entities." />
                  </div>
                  <div className="chart-card">
                    <h3>Event severity</h3>
                    <BarChart items={chartStats.events} emptyLabel="No tagged events yet." />
                  </div>
                  <div className="chart-card chart-card-wide">
                    <h3>Sources reported in output</h3>
                    {chartStats.sources.length ? (
                      <div className="source-chips">{chartStats.sources.map(source => <span key={source}>{source}</span>)}</div>
                    ) : (
                      <div className="chart-empty">Source labels will appear when the engine reports them.</div>
                    )}
                  </div>
                </div>
                <div className="entity-grid">
                  <EntityList title="Emails" values={extractedEntities.emails} />
                  <EntityList title="Hosts / Domains" values={extractedEntities.hosts} />
                  <EntityList title="IP Addresses" values={extractedEntities.ips} />
                  <EntityList title="People" values={extractedEntities.people} />
                  <EntityList title="URLs" values={extractedEntities.urls} />
                </div>
              </div>
            </div>
          ) : (
            /* History Table View */
            <div className="glass-card">
              <div className="card-heading">
                <h2>Recent Scans History</h2>
                <button
                  type="button"
                  className="copy-btn"
                  onClick={fetchRecentJobs}
                >
                  Refresh
                </button>
              </div>

              {recentJobs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                  No previous scan jobs found in memory yet.
                </div>
              ) : (
                <div className="history-table-container">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Domain</th>
                        <th>Sources</th>
                        <th>Limit</th>
                        <th>Status</th>
                        <th>Date</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentJobs.map(job => (
                        <tr key={job.job_id} onClick={() => handleSelectRecentJob(job)}>
                          <td style={{ fontWeight: 600, color: 'var(--text-main)' }}>{job.domain}</td>
                          <td>
                            {job.sources.includes('all') ? (
                              <span style={{ color: 'var(--cyan)', fontWeight: 600 }}>ALL</span>
                            ) : (
                              `${job.sources.length} sources`
                            )}
                          </td>
                          <td>{job.limit}</td>
                          <td>
                            <span className={`status-badge ${job.status}`} style={{ padding: '0.2rem 0.6rem', fontSize: '0.74rem' }}>
                              {job.status}
                            </span>
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                            {new Date(job.created_at * 1000).toLocaleTimeString()}
                          </td>
                          <td>
                            <button
                              type="button"
                              style={{ background: 'transparent', border: 'none', color: 'var(--accent)', fontWeight: 600, cursor: 'pointer' }}
                            >
                              View Logs ➔
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>theHarvester Web UI & Local OSINT Console — Built with Python FastAPI, WebSockets & React</p>
        <p style={{ marginTop: '4px', fontSize: '0.76rem', color: '#475569' }}>
          Security Guarantee: Strict input regex validation | Whitelisted flags | No shell=True execution | Subprocess auto-kill timeouts
        </p>
      </footer>
    </div>
  );
}

export default App;
