// App Logic for Passive Asset Management Dashboard

document.addEventListener('DOMContentLoaded', () => {
    const statusIndicator = document.getElementById('api-status');
    const sourcesContainer = document.getElementById('sources-container');
    const harvestForm = document.getElementById('harvest-form');
    const submitBtn = document.getElementById('submit-btn');
    const loaderWrapper = document.getElementById('loader-wrapper');
    const statusMessage = document.getElementById('status-message');
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');

    let availableSources = [];
    let activeTab = 'hosts';
    let currentData = {
        hosts: [],
        ips: [],
        emails: [],
        asns: [],
        interesting_urls: []
    };

    // Check backend connection and fetch supported engines
    fetch('/sources')
        .then(res => {
            if (!res.ok) throw new Error('API server returned error status');
            return res.json();
        })
        .then(data => {
            statusIndicator.textContent = 'API Online';
            statusIndicator.style.backgroundColor = 'rgba(48, 209, 88, 0.2)';
            statusIndicator.style.color = '#30d158';
            
            availableSources = data.sources || [];
            renderSources(availableSources);
        })
        .catch(err => {
            console.error('Error connecting to backend API:', err);
            statusIndicator.textContent = 'API Offline';
            statusIndicator.style.backgroundColor = 'rgba(255, 69, 58, 0.2)';
            statusIndicator.style.color = '#ff453a';
        });

    // Render sources checkboxes
    function renderSources(sources) {
        sourcesContainer.innerHTML = '';
        
        // Select some common default passive sources to be pre-checked
        const defaults = ['duckduckgo', 'crtsh', 'anubis', 'hackertarget', 'rapiddns', 'subdomaincenter'];

        sources.forEach(src => {
            const wrapper = document.createElement('label');
            wrapper.className = 'source-item';
            
            const isChecked = defaults.includes(src);
            wrapper.innerHTML = `
                <input type="checkbox" name="source" value="${src}" ${isChecked ? 'checked' : ''}>
                <span>${src}</span>
            `;
            sourcesContainer.appendChild(wrapper);
        });
    }

    // Handle form submit (Query passive public assets)
    harvestForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const domain = document.getElementById('domain').value.trim();
        const limit = document.getElementById('limit').value;
        const checkedBoxes = document.querySelectorAll('input[name="source"]:checked');
        
        const selectedSources = Array.from(checkedBoxes).map(cb => cb.value);

        if (!domain) {
            alert('Please specify a domain.');
            return;
        }

        if (selectedSources.length === 0) {
            alert('Please select at least one passive source.');
            return;
        }

        // Show loading state
        submitBtn.disabled = true;
        submitBtn.firstElementChild.textContent = 'Loading...';
        loaderWrapper.style.display = 'block';
        statusMessage.style.display = 'none';

        // Clear previous results visually
        clearTables();

        try {
            // Construct query parameters
            const params = new URLSearchParams();
            selectedSources.forEach(src => params.append('source', src));
            params.append('domain', domain);
            params.append('limit', limit);

            const response = await fetch(`/query?${params.toString()}`);
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Server returned an error');
            }

            const data = await response.json();
            currentData = {
                hosts: data.hosts || [],
                ips: data.ips || [],
                emails: data.emails || [],
                asns: data.asns || [],
                interesting_urls: data.interesting_urls || []
            };

            updateTabsCount();
            renderAllTables();

            loaderWrapper.style.display = 'none';
            if (getTotalCount() === 0) {
                statusMessage.textContent = 'No records found for the domain with selected sources.';
                statusMessage.style.display = 'block';
            } else {
                statusMessage.style.display = 'none';
            }

        } catch (err) {
            console.error('Request failed:', err);
            loaderWrapper.style.display = 'none';
            statusMessage.textContent = `Error: ${err.message || 'Failed to fetch public details.'}`;
            statusMessage.style.display = 'block';
        } finally {
            submitBtn.disabled = false;
            submitBtn.firstElementChild.textContent = 'Fetch Public Data';
        }
    });

    // Helper functions to manage visual lists
    function clearTables() {
        ['hosts', 'ips', 'emails', 'asns', 'interesting_urls'].forEach(key => {
            const body = document.getElementById(`${key}-body`);
            if (body) {
                body.innerHTML = `<tr><td style="color: var(--text-secondary);">Querying...</td></tr>`;
            }
        });
    }

    function getTotalCount() {
        return currentData.hosts.length + 
               currentData.ips.length + 
               currentData.emails.length + 
               currentData.asns.length + 
               currentData.interesting_urls.length;
    }

    function updateTabsCount() {
        tabs.forEach(tab => {
            const type = tab.getAttribute('data-tab');
            const count = currentData[type] ? currentData[type].length : 0;
            const cleanName = type === 'interesting_urls' ? 'URLs' : type.charAt(0).toUpperCase() + type.slice(1);
            tab.textContent = `${cleanName} (${count})`;
        });
    }

    function renderAllTables() {
        Object.keys(currentData).forEach(key => {
            const body = document.getElementById(`${key}-body`);
            if (!body) return;

            body.innerHTML = '';
            const items = currentData[key];

            if (items.length === 0) {
                body.innerHTML = `<tr><td style="color: var(--text-secondary);">No records returned.</td></tr>`;
                return;
            }

            items.forEach(val => {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                if (typeof val === 'object' && val !== null) {
                    td.textContent = JSON.stringify(val);
                } else {
                    td.textContent = val;
                }
                tr.appendChild(td);
                body.appendChild(tr);
            });
        });
    }

    // Tabs switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            activeTab = tab.getAttribute('data-tab');
            document.getElementById(`tab-${activeTab}`).classList.add('active');
        });
    });
});
