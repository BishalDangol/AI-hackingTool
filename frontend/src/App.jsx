import { useState, useEffect } from 'react'

function App() {
  const [apiStatus, setApiStatus] = useState('Connecting...')
  const [apiOnline, setApiOnline] = useState(false)
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  
  // Available passive sources
  const passiveSources = [
    'crt.sh', 'duckduckgo', 'subdomaincenter', 'hackertarget', 'rapiddns', 'dnsdumpster'
  ]
  const [selectedSources, setSelectedSources] = useState(['crt.sh', 'dnsdumpster'])
  
  const [activeTab, setActiveTab] = useState('A')
  const [result, setResult] = useState(null)

  // Verify backend health check on load
  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/health')
      .then(res => {
        if (!res.ok) throw new Error('API server returned error')
        return res.json()
      })
      .then(() => {
        setApiStatus('API Online')
        setApiOnline(true)
      })
      .catch(err => {
        console.error(err)
        setApiStatus('API Offline')
        setApiOnline(false)
      })
  }, [])

  const handleSourceChange = (src) => {
    if (selectedSources.includes(src)) {
      setSelectedSources(selectedSources.filter(s => s !== src))
    } else {
      setSelectedSources([...selectedSources, src])
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!domain.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch('http://127.0.0.1:8000/api/domain-info', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: domain.trim() })
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || 'Failed to fetch domain configuration')
      }

      const data = await response.json()
      setResult(data)
      // Pick first key from dns_records if exists
      if (data.dns_records && Object.keys(data.dns_records).length > 0) {
        setActiveTab(Object.keys(data.dns_records)[0])
      }
    } catch (err) {
      console.error(err)
      setError(err.message || 'An unexpected error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="dashboard-container">
      <header>
        <div className="logo-container">
          <img src="https://raw.githubusercontent.com/laramies/theHarvester/master/theHarvester-logo.webp" alt="theHarvester Logo" />
          <h1>Passive Asset Monitoring</h1>
        </div>
        <div>
          <span 
            className="status-indicator" 
            style={{
              padding: '0.5rem 1rem', 
              borderRadius: '8px',
              backgroundColor: apiOnline ? 'rgba(48, 209, 88, 0.15)' : 'rgba(255, 69, 58, 0.15)',
              color: apiOnline ? '#30d158' : '#ff453a',
              border: 'none'
            }}
          >
            {apiStatus}
          </span>
        </div>
      </header>

      <main>
        {/* Sidebar */}
        <section className="card">
          <div className="card-title">Asset Setup</div>
          <form onSubmit={handleSubmit}>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label htmlFor="domain-input">Target Domain</label>
              <input 
                type="text" 
                id="domain-input" 
                placeholder="example.com" 
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required 
              />
            </div>

            <div className="form-group" style={{ marginBottom: '1.25rem' }}>
              <label>Passive API Sources</label>
              <div className="sources-list">
                {passiveSources.map(src => (
                  <label key={src} className="source-item">
                    <input 
                      type="checkbox" 
                      value={src} 
                      checked={selectedSources.includes(src)}
                      onChange={() => handleSourceChange(src)}
                    />
                    <span>{src}</span>
                  </label>
                ))}
              </div>
            </div>

            <button type="submit" className="btn" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Querying...' : 'Fetch Asset Config'}
            </button>
          </form>
        </section>

        {/* Display Area */}
        <section className="results-area">
          <div className="card" style={{ flex: 1 }}>
            {loading && (
              <div style={{ textAlign: 'center', padding: '3rem 0' }}>
                <div className="loader"></div>
                <p style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
                  Gathering passive configuration records...
                </p>
              </div>
            )}

            {!loading && error && (
              <div className="status-indicator" style={{ borderColor: '#ff453a', color: '#ff453a' }}>
                {error}
              </div>
            )}

            {!loading && !error && !result && (
              <div className="status-indicator">
                Enter a domain on the left and fetch its configurations to populate the asset catalog.
              </div>
            )}

            {!loading && !error && result && (
              <>
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 600 }}>Domain: {result.domain}</h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                    Status: <span style={{ color: 'var(--success)' }}>{result.status}</span>
                  </p>
                </div>

                <div className="tabs">
                  {Object.keys(result.dns_records).map(type => (
                    <button 
                      key={type}
                      className={`tab ${activeTab === type ? 'active' : ''}`}
                      onClick={() => setActiveTab(type)}
                    >
                      {type} Records ({result.dns_records[type].length})
                    </button>
                  ))}
                  <button 
                    className={`tab ${activeTab === 'sources' ? 'active' : ''}`}
                    onClick={() => setActiveTab('sources')}
                  >
                    Enabled Sources ({result.passive_sources.length})
                  </button>
                </div>

                {activeTab === 'sources' ? (
                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Passive Resource Engine</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.passive_sources.map(src => (
                          <tr key={src}>
                            <td>{src}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Record Content</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.dns_records[activeTab]?.map((rec, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: 'monospace' }}>{rec}</td>
                          </tr>
                        )) || (
                          <tr>
                            <td style={{ color: 'var(--text-secondary)' }}>No records found.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        </section>
      </main>

      <footer>
        <p>College Asset Security Project Dashboard | React Frontend & Python FastAPI Backend</p>
      </footer>
    </div>
  )
}

export default App
