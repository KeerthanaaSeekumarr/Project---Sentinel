let isFetching = false;
let intervalId; // Store the interval ID

// Function to control the traffic generation engine
async function controlTraffic(action) {
    try {
        const res = await fetch('/api/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action})
        });
        const data = await res.json();
        console.log(`[Engine] ${data.message}`);
    } catch (e) {
        console.error("Control Error:", e);
    }
}

// NEW FEATURE: Function to handle packet export (Now handles JSON and CSV)
async function exportPackets(type = 'json') {
    try {
        const endpoint = type === 'csv' ? '/api/export_packets_csv' : '/api/export_packets';
        
        const res = await fetch(endpoint);
        
        if (res.status === 404) {
            alert('Error: No packets in buffer to export.');
            return;
        }

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        // Extract the suggested filename from the response header
        const contentDisposition = res.headers.get('Content-Disposition');
        let filename = type === 'csv' ? 'export.csv' : 'export.json';
        if (contentDisposition) {
            const match = contentDisposition.match(/filename="(.+?)"/);
            if (match && match[1]) {
                filename = match[1];
            }
        }

        // Create a blob from the response body and trigger a download
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        console.log(`[Export] Successfully downloaded ${filename}`);

    } catch (e) {
        console.error("Export Error:", e);
        alert('Failed to export data. See console for details.');
    }
}

// Function to fetch and update the packet list (Updated for Filtering and new fields)
async function updatePackets() {
    if(isFetching) return;
    isFetching = true;

    try {
        const res = await fetch('/api/packets');
        const packets = await res.json();
        
        // --- 1. Update Monitor Table (if on monitor page) ---
        const tbody = document.getElementById('packetBody');
        const filterSelect = document.getElementById('attackFilter');
        
        if (tbody) {
            // Get current filter values
            const selectedAttackType = filterSelect ? filterSelect.value : 'ALL';
            
            // Filter packets based on selection
            const filteredPackets = packets.filter(p => {
                if (selectedAttackType === 'ALL') return true;
                if (selectedAttackType === 'THREATS') return p.severity !== 'Low';
                if (selectedAttackType === 'SUCCESSFUL') return p.is_successful === true;
                if (selectedAttackType === 'Normal') return p.type === 'Normal';
                return p.type === selectedAttackType;
            });

            // Reverse and map the packets to table rows
            tbody.innerHTML = filteredPackets.slice().reverse().map(p => {
                const isMalicious = p.severity !== 'Low';
                const isSuccessful = p.is_successful === true;
                
                // Use a different row class for confirmed successful exploits
                let rowClass = isMalicious ? 'row-malicious' : '';
                if (isSuccessful) {
                    rowClass = 'row-successful-exploit'; // New class for confirmed success
                }

                // Append status icon to severity cell
                const successIcon = isSuccessful ? `<i class="fas fa-flag-checkered" style="margin-left:5px;" title="Successful Exploit"></i>` : '';

                return `
                    <tr class="${rowClass}">
                        <td>${p.id}</td>
                        <td>${p.timestamp}</td>
                        <td>${p.source}</td>
                        <td>${p.destination}</td>
                        <td>${p.protocol}</td>
                        <td>${p.info}</td>
                        <td class="severity-${p.severity}">${p.severity} ${successIcon}</td>
                    </tr>
                `;
            }).join('');
            
            // Populate the filter dropdown with unique attack types
            if(filterSelect) { 
                const staticOptionsCount = 4; // ALL, THREATS, SUCCESSFUL, Normal
                const attackTypes = [...new Set(packets.filter(p => p.type !== 'Normal' && p.type !== 'IPDR').map(p => p.type))].sort();
                
                // Clear existing dynamic options (starting from index 4)
                while (filterSelect.options.length > staticOptionsCount) {
                    filterSelect.remove(staticOptionsCount);
                }

                attackTypes.forEach(type => {
                    // Check if option already exists to prevent duplication on multiple calls
                    if (![...filterSelect.options].some(opt => opt.value === type)) {
                        const option = document.createElement('option');
                        option.value = type;
                        option.text = type;
                        filterSelect.appendChild(option);
                    }
                });
                
                // Restore the selected option if it was set
                filterSelect.value = selectedAttackType;
            }
        }

        // --- 2. Update Dashboard Stats (if on dashboard) ---
        const totalElem = document.getElementById('totalPackets');
        if (totalElem) {
            totalElem.innerText = packets.length;
            const threats = packets.filter(p => p.severity !== 'Low').length;
            document.getElementById('totalThreats').innerText = threats;
            
            // Update Alert List
            const threatsList = packets.filter(p => p.severity !== 'Low').slice(-5).reverse();
            const alertList = document.getElementById('alertList');
            
            if(alertList) {
                // Helper to map severity name to CSS variable name
                const getCssColorVar = (severity) => {
                    if (severity === 'CRITICAL') return 'critical-red';
                    if (severity === 'HIGH') return 'high-orange';
                    if (severity === 'MEDIUM') return 'medium-yellow';
                    return 'low-green'; // Fallback
                };

                if(threatsList.length > 0) {
                    alertList.innerHTML = threatsList.map(t => {
                        const successFlag = t.is_successful ? ' [SUCCESS]' : ''; 
                        return `<li style="border-left-color: var(--${getCssColorVar(t.severity)}); background:#1c2128; margin-bottom:5px;">
                            <strong>${t.timestamp}</strong> - ${t.info} 
                            <span style="float:right; color:var(--${getCssColorVar(t.severity)})">[${t.type}${successFlag}]</span>
                        </li>`
                    }).join('');
                } else {
                    alertList.innerHTML = '<li style="border-left: 3px solid var(--low-green); background:#1c2128; margin-bottom:5px;">No active threats detected. System operating normally.</li>';
                }
            }
        }

    } catch (e) {
        console.error("Fetch error", e);
    } finally {
        isFetching = false;
    }
}

// Start the continuous packet updates when the page loads
function startUpdates() {
    // Run once immediately
    updatePackets(); 
    // Set up interval (e.g., every 1 second)
    if (!intervalId) {
        intervalId = setInterval(updatePackets, 1000);
    }
}

window.onload = startUpdates;
