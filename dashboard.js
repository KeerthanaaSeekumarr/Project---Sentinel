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

// NEW FEATURE: Function to handle packet export
async function exportPackets() {
    try {
        const res = await fetch('/api/export_packets');
        
        if (res.status === 404) {
            alert('Error: No packets in buffer to export.');
            return;
        }

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        // Extract the suggested filename from the response header
        const contentDisposition = res.headers.get('Content-Disposition');
        let filename = 'export.json';
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

// Function to fetch and update the packet list
async function updatePackets() {
    if(isFetching) return;
    isFetching = true;

    try {
        const res = await fetch('/api/packets');
        const packets = await res.json();
        
        // --- 1. Update Monitor Table (if on monitor page) ---
        const tbody = document.getElementById('packetBody');
        if (tbody) {
            // Reverse and map the packets to table rows
            tbody.innerHTML = packets.slice().reverse().map(p => `
                <tr class="${p.severity !== 'Low' ? 'row-malicious' : ''}">
                    <td>${p.id}</td>
                    <td>${p.timestamp}</td>
                    <td>${p.source}</td>
                    <td>${p.destination}</td>
                    <td>${p.protocol}</td>
                    <td>${p.info}</td>
                    <td class="severity-${p.severity}">${p.severity}</td>
                </tr>
            `).join('');
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
                // Helper to map severity name to CSS variable name (e.g., CRITICAL -> critical-red)
                const getCssColorVar = (severity) => {
                    if (severity === 'CRITICAL') return 'critical-red';
                    if (severity === 'HIGH') return 'high-orange';
                    if (severity === 'MEDIUM') return 'medium-yellow';
                    return 'low-green'; // Fallback
                };

                if(threatsList.length > 0) {
                    alertList.innerHTML = threatsList.map(t => 
                        `<li style="border-left-color: var(--${getCssColorVar(t.severity)}); background:#1c2128; margin-bottom:5px;">
                            <strong>${t.timestamp}</strong> - ${t.info} 
                            <span style="float:right; color:var(--${getCssColorVar(t.severity)})">[${t.type}]</span>
                        </li>`
                    ).join('');
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