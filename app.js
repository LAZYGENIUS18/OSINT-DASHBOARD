// --- GLOBAL SYSTEM STATE ---
const state = {
    activeTab: 'dashboard',
    leafletMap: null,
    mapMarker: null,
    currentExifData: {}
};

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    lucide.createIcons();

    // Start Clock Update
    updateClock();
    setInterval(updateClock, 1000);

    // Initialize Navigation Router
    setupNavigation();

    // Initialize URL Analyzer
    setupUrlAnalyzer();

    // Initialize EXIF Extractor
    setupExifAnalyzer();

    // Initialize Phone Lookup
    setupPhoneAnalyzer();

    // Log initialization message to hub console
    consoleLogHub('OSINT analysis modules loaded. Standing by...', 'info');
});

// --- CORE TELEMETRY / WIDGETS ---
function updateClock() {
    const clockEl = document.getElementById('utc-clock');
    if (clockEl) {
        const now = new Date();
        const timeStr = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        clockEl.textContent = timeStr;
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    // Choose icon based on type
    let iconName = 'info';
    if (type === 'success') iconName = 'check-circle';
    if (type === 'error') iconName = 'alert-triangle';

    toast.innerHTML = `
        <i data-lucide="${iconName}"></i>
        <span class="toast-message">${message}</span>
    `;
    
    container.appendChild(toast);
    lucide.createIcons();

    // Animate out and remove after 4 seconds
    setTimeout(() => {
        toast.style.animation = 'toastSlideIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.15) reverse forwards';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

function consoleLogHub(message, status = 'system') {
    const consoleBody = document.querySelector('.console-body');
    if (!consoleBody) return;

    const line = document.createElement('div');
    line.className = 'console-line';
    
    let statusSpan = '';
    if (status === 'success') statusSpan = '<span class="text-green">[SUCCESS]</span>';
    else if (status === 'info') statusSpan = '<span class="text-cyan">[INFO]</span>';
    else if (status === 'warning') statusSpan = '<span class="text-purple">[ALERT]</span>';
    else statusSpan = '<span class="text-secondary">[SYSTEM]</span>';

    line.innerHTML = `${statusSpan} ${message}`;
    consoleBody.appendChild(line);

    // Keep console scrolled to bottom
    consoleBody.scrollTop = consoleBody.scrollHeight;
}

// --- CLIENT-SIDE NAVIGATION (TAB ROUTER) ---
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    if (!tabId) return;

    // Toggle nav items active state
    document.querySelectorAll('.nav-item').forEach(btn => {
        if (btn.getAttribute('data-tab') === tabId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Toggle panels visibility
    document.querySelectorAll('.tab-panel').forEach(panel => {
        if (panel.id === `tab-${tabId}`) {
            panel.classList.add('active');
        } else {
            panel.classList.remove('active');
        }
    });

    // Update Header Metadata
    const titleEl = document.getElementById('page-title');
    const subtitleEl = document.getElementById('page-subtitle');
    
    if (tabId === 'dashboard') {
        titleEl.textContent = 'Control Panel';
        subtitleEl.textContent = 'System telemetry and quick access portals.';
    } else if (tabId === 'url-analyzer') {
        titleEl.textContent = 'URL Intelligence';
        subtitleEl.textContent = 'Deconstruct web parameters and query reputation engines.';
    } else if (tabId === 'exif-analyzer') {
        titleEl.textContent = 'EXIF Extractor';
        subtitleEl.textContent = 'Decrypt photographic metadata and view capture coordinates.';
        // Leaflet maps sometimes don't render properly when loaded hidden. Resize standard check:
        if (state.leafletMap) {
            setTimeout(() => {
                state.leafletMap.invalidateSize();
            }, 100);
        }
    } else if (tabId === 'phone-analyzer') {
        titleEl.textContent = 'Phone Registry Auditor';
        subtitleEl.textContent = 'Validate international formats and generate OSINT directories.';
    } else if (tabId === 'documentation') {
        titleEl.textContent = 'Intel Docs';
        subtitleEl.textContent = 'Guidelines, OPSEC details, and operation framework.';
    }

    state.activeTab = tabId;
    consoleLogHub(`Navigated to view: ${tabId}`, 'system');
}

// --- URL ANALYZER COMPONENT ---
function setupUrlAnalyzer() {
    const btn = document.getElementById('btn-analyze-url');
    const input = document.getElementById('url-input');

    if (!btn || !input) return;

    btn.addEventListener('click', () => {
        executeUrlAnalysis(input.value.trim());
    });

    // Handle Enter Keypress
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            executeUrlAnalysis(input.value.trim());
        }
    });
}

function executeUrlAnalysis(rawUrl) {
    if (!rawUrl) {
        showToast('Please enter a target URL to analyze.', 'error');
        return;
    }

    // Attempt clean parser fix
    let urlString = rawUrl;
    if (!/^https?:\/\//i.test(urlString)) {
        urlString = 'http://' + urlString; // default fallback prefix
    }

    try {
        const urlObj = new URL(urlString);
        displayUrlResults(urlObj, rawUrl);
        showToast('URL successfully deconstructed.', 'success');
        consoleLogHub(`Target URL analyzed: ${urlObj.hostname}`, 'success');
    } catch (err) {
        showToast('Failed to parse URL. Ensure formatting matches standard addresses.', 'error');
        consoleLogHub(`Invalid URL payload: "${rawUrl}"`, 'warning');
    }
}

function displayUrlResults(urlObj, originalInput) {
    const resultsContainer = document.getElementById('url-results');
    const componentsTable = document.getElementById('url-components-table');
    const safetyPortals = document.getElementById('url-safety-portals');
    const queryCard = document.getElementById('url-query-card');
    const queryList = document.getElementById('url-query-list');

    if (!resultsContainer || !componentsTable || !safetyPortals) return;

    // 1. Populate URL details
    const cleanDomain = urlObj.hostname;
    componentsTable.innerHTML = `
        <tr><td>Domain / Host</td><td>${cleanDomain}</td></tr>
        <tr><td>Protocol</td><td>${urlObj.protocol}</td></tr>
        <tr><td>Path</td><td>${urlObj.pathname || '/'}</td></tr>
        <tr><td>Port</td><td>${urlObj.port || '(Default)'}</td></tr>
        <tr><td>Hash/Anchor</td><td>${urlObj.hash || '(None)'}</td></tr>
    `;

    // 2. Generate security OSINT links
    const escDomain = encodeURIComponent(cleanDomain);
    const escUrl = encodeURIComponent(urlObj.href);

    safetyPortals.innerHTML = `
        <a href="https://www.virustotal.com/gui/search/${escDomain}" target="_blank" class="portal-item danger-hover">
            <div class="portal-meta">
                <span class="portal-title">VirusTotal Reputation</span>
                <span class="portal-url">virustotal.com</span>
            </div>
            <i data-lucide="shield-alert" class="text-red"></i>
        </a>
        <a href="https://www.urlvoid.com/scan/${cleanDomain}/" target="_blank" class="portal-item danger-hover">
            <div class="portal-meta">
                <span class="portal-title">URLVoid Domain Scan</span>
                <span class="portal-url">urlvoid.com</span>
            </div>
            <i data-lucide="external-link" class="text-secondary"></i>
        </a>
        <a href="https://web.archive.org/web/*/${urlObj.href}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Wayback Machine Archives</span>
                <span class="portal-url">web.archive.org</span>
            </div>
            <i data-lucide="clock" class="text-purple"></i>
        </a>
        <a href="https://www.shodan.io/search?query=${escDomain}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Shodan Port Check</span>
                <span class="portal-url">shodan.io</span>
            </div>
            <i data-lucide="cpu" class="text-cyan"></i>
        </a>
        <a href="https://whois.domaintools.com/${cleanDomain}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">WHOIS Registrar details</span>
                <span class="portal-url">whois.domaintools.com</span>
            </div>
            <i data-lucide="search" class="text-secondary"></i>
        </a>
        <a href="https://dnsdumpster.com/" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">DNSDumpster Record Audit</span>
                <span class="portal-url">dnsdumpster.com</span>
            </div>
            <i data-lucide="database" class="text-green"></i>
        </a>
    `;

    // 3. Populate query parameters if present
    const params = Array.from(urlObj.searchParams.entries());
    if (params.length > 0) {
        queryCard.classList.remove('hidden');
        queryList.innerHTML = params.map(([key, val]) => `
            <div class="query-param-item">
                <span class="query-key">${escapeHtml(key)}:</span>
                <span class="query-val">${escapeHtml(val)}</span>
            </div>
        `).join('');
    } else {
        queryCard.classList.add('hidden');
    }

    // Refresh icons inside dynamic nodes
    lucide.createIcons();
    resultsContainer.classList.remove('hidden');
}

// --- EXIF METADATA COMPONENT ---
function setupExifAnalyzer() {
    const dropzone = document.getElementById('image-dropzone');
    const fileInput = document.getElementById('image-input');
    const btnClear = document.getElementById('btn-clear-image');
    const searchInput = document.getElementById('exif-search');
    const btnDemo = document.getElementById('btn-load-demo-exif');

    if (!dropzone || !fileInput) return;

    // Trigger file select click
    dropzone.addEventListener('click', () => fileInput.click());

    // Drag-and-drop triggers
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('active');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('active');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('active');
        if (e.dataTransfer.files.length > 0) {
            handleUploadedImage(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleUploadedImage(e.target.files[0]);
        }
    });

    if (btnDemo) {
        btnDemo.addEventListener('click', (e) => {
            e.stopPropagation();
            loadDemoExif();
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            resetExifState();
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            filterExifTable(e.target.value.toLowerCase());
        });
    }
}

function handleUploadedImage(file) {
    if (!file) return;
    
    // Safety check file type
    if (!file.type.match('image/jpeg') && !file.type.match('image/tiff')) {
        showToast('Only JPEG and TIFF image formats are supported for EXIF data.', 'error');
        return;
    }

    showToast('Extracting image metadata...', 'info');
    consoleLogHub(`Processing file: ${file.name} (${formatBytes(file.size)})`, 'system');

    // Render Preview
    const reader = new FileReader();
    reader.onload = (e) => {
        const previewContainer = document.getElementById('image-preview-container');
        const previewImg = document.getElementById('image-preview');
        const previewFilename = document.getElementById('preview-filename');
        const previewSize = document.getElementById('preview-size');
        const previewType = document.getElementById('preview-type');
        const previewRes = document.getElementById('preview-resolution');

        if (previewImg) previewImg.src = e.target.result;
        if (previewFilename) previewFilename.textContent = file.name;
        if (previewSize) previewSize.textContent = formatBytes(file.size);
        if (previewType) previewType.textContent = file.type;

        // Calculate resolution dimensions
        const img = new Image();
        img.src = e.target.result;
        img.onload = () => {
            if (previewRes) previewRes.textContent = `${img.naturalWidth} x ${img.naturalHeight} px`;
        };

        // Hide dropzone, show preview card
        document.getElementById('image-dropzone').classList.add('hidden');
        if (previewContainer) previewContainer.classList.remove('hidden');
    };
    reader.readAsDataURL(file);

    // Extract EXIF Tags
    EXIF.getData(file, function() {
        const allTags = EXIF.getAllTags(this);
        state.currentExifData = allTags;

        const resultsPanel = document.getElementById('exif-results-panel');
        const emptyState = document.getElementById('exif-empty-state');
        const resultsScroll = document.getElementById('exif-results');

        if (resultsPanel) resultsPanel.classList.remove('hidden');
        if (emptyState) emptyState.classList.add('hidden');
        if (resultsScroll) resultsScroll.classList.remove('hidden');

        // Check GPS coordinates
        const lat = EXIF.getTag(this, "GPSLatitude");
        const latRef = EXIF.getTag(this, "GPSLatitudeRef");
        const lng = EXIF.getTag(this, "GPSLongitude");
        const lngRef = EXIF.getTag(this, "GPSLongitudeRef");

        const gpsBadge = document.getElementById('exif-gps-badge');
        const mapContainer = document.getElementById('gps-map-container');

        if (lat && lng && latRef && lngRef) {
            const decLat = convertExifGpsToDecimal(lat, latRef);
            const decLng = convertExifGpsToDecimal(lng, lngRef);

            // Update GPS Badge
            if (gpsBadge) {
                gpsBadge.textContent = 'GPS DECODED';
                gpsBadge.className = 'badge badge-active';
            }

            // Draw Leaflet Map
            if (mapContainer) {
                mapContainer.classList.remove('hidden');
                initLeafletMap(decLat, decLng);
            }

            consoleLogHub(`GPS Coordinates Extracted: ${decLat.toFixed(5)}°, ${decLng.toFixed(5)}°`, 'success');
        } else {
            if (gpsBadge) {
                gpsBadge.textContent = 'No GPS Data';
                gpsBadge.className = 'badge badge-inactive';
            }
            if (mapContainer) mapContainer.classList.add('hidden');
            consoleLogHub('No GPS metadata found in target payload.', 'warning');
        }

        // Render Table Body
        renderExifTable(allTags);
        showToast('EXIF analysis completed successfully.', 'success');
    });
}

function loadDemoExif() {
    showToast('Loading sample EXIF payload...', 'info');
    consoleLogHub('Loading simulation payload (Eiffel Tower, Paris)', 'system');

    // Simulate image properties
    const previewContainer = document.getElementById('image-preview-container');
    const previewImg = document.getElementById('image-preview');
    const previewFilename = document.getElementById('preview-filename');
    const previewSize = document.getElementById('preview-size');
    const previewType = document.getElementById('preview-type');
    const previewRes = document.getElementById('preview-resolution');

    if (previewImg) {
        previewImg.src = 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34?auto=format&fit=crop&w=600&q=80';
    }
    if (previewFilename) previewFilename.textContent = 'paris_eiffel_tower.jpg';
    if (previewSize) previewSize.textContent = '1.84 MB';
    if (previewType) previewType.textContent = 'image/jpeg';
    if (previewRes) previewRes.textContent = '4000 x 3000 px';

    // Hide dropzone and show preview card
    document.getElementById('image-dropzone').classList.add('hidden');
    if (previewContainer) previewContainer.classList.remove('hidden');

    // Define simulated tags
    const mockTags = {
        Make: "Apple",
        Model: "iPhone 15 Pro",
        Software: "iOS 17.4",
        DateTime: "2024:05:12 14:32:08",
        ExposureTime: "1/120",
        FNumber: 1.78,
        ISOSpeedRatings: 80,
        FocalLength: "24 mm",
        LensModel: "iPhone 15 Pro back triple camera 6.86mm f/1.78",
        GPSLatitude: [48, 51, 30.24],
        GPSLatitudeRef: "N",
        GPSLongitude: [2, 17, 40.2],
        GPSLongitudeRef: "E"
    };

    state.currentExifData = mockTags;

    const resultsPanel = document.getElementById('exif-results-panel');
    const emptyState = document.getElementById('exif-empty-state');
    const resultsScroll = document.getElementById('exif-results');

    if (resultsPanel) resultsPanel.classList.remove('hidden');
    if (emptyState) emptyState.classList.add('hidden');
    if (resultsScroll) resultsScroll.classList.remove('hidden');

    const gpsBadge = document.getElementById('exif-gps-badge');
    const mapContainer = document.getElementById('gps-map-container');

    // Eiffel Tower Coordinates: 48.8584, 2.2945
    const decLat = 48.8584;
    const decLng = 2.2945;

    if (gpsBadge) {
        gpsBadge.textContent = 'GPS DECODED (DEMO)';
        gpsBadge.className = 'badge badge-active';
    }

    if (mapContainer) {
        mapContainer.classList.remove('hidden');
        initLeafletMap(decLat, decLng);
    }

    consoleLogHub(`GPS Coordinates Extracted: ${decLat.toFixed(5)}°, ${decLng.toFixed(5)}°`, 'success');
    renderExifTable(mockTags);
    showToast('Demo EXIF loaded successfully.', 'success');
}

function convertExifGpsToDecimal(gpsArr, ref) {
    if (!gpsArr || gpsArr.length < 3) return 0;
    
    // Degrees, minutes, seconds parsing
    const deg = parseFloat(gpsArr[0].numerator / gpsArr[0].denominator) || gpsArr[0];
    const min = parseFloat(gpsArr[1].numerator / gpsArr[1].denominator) || gpsArr[1];
    const sec = parseFloat(gpsArr[2].numerator / gpsArr[2].denominator) || gpsArr[2];

    let decimal = deg + (min / 60) + (sec / 3600);

    // Southern / Western hemis are negative
    if (ref === 'S' || ref === 'W') {
        decimal *= -1;
    }
    return decimal;
}

function initLeafletMap(lat, lng) {
    const mapCoordsDisplay = document.getElementById('map-coords-display');
    const gmapsLink = document.getElementById('gmaps-link');

    if (mapCoordsDisplay) {
        mapCoordsDisplay.textContent = `${lat.toFixed(5)}°, ${lng.toFixed(5)}°`;
    }
    if (gmapsLink) {
        gmapsLink.href = `https://www.google.com/maps/search/?api=1&query=${lat},${lng}`;
    }

    // Recreate Map Container if exists
    if (state.leafletMap) {
        state.leafletMap.remove();
        state.leafletMap = null;
    }

    // Initialize Map on `#map`
    state.leafletMap = L.map('map', {
        zoomControl: false,
        attributionControl: false
    }).setView([lat, lng], 13);

    // CartoDB Dark Matter tile service (perfect dark theme match!)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 20
    }).addTo(state.leafletMap);

    // Custom Neon glowing map indicator dot
    const neonDotIcon = L.divIcon({
        className: 'custom-leaflet-marker',
        html: '<div style="width: 16px; height: 16px; border: 2.5px solid #00f0ff; background-color: #06070a; border-radius: 50%; box-shadow: 0 0 10px #00f0ff; transform: translate(-4px, -4px);"></div>',
        iconSize: [16, 16]
    });

    state.mapMarker = L.marker([lat, lng], { icon: neonDotIcon }).addTo(state.leafletMap);
    
    // Invalidate map layout to draw correctly
    setTimeout(() => {
        state.leafletMap.invalidateSize();
    }, 200);
}

function renderExifTable(tags) {
    const tableBody = document.getElementById('exif-data-body');
    if (!tableBody) return;

    if (Object.keys(tags).length === 0) {
        tableBody.innerHTML = '<tr><td colspan="2" class="text-muted" style="text-align: center;">No tags parsed.</td></tr>';
        return;
    }

    let rowsHtml = '';
    for (const [tag, val] of Object.entries(tags)) {
        // Skip binary array streams or extremely large outputs for visual clarity
        if (typeof val === 'object' && !(val instanceof Number) && !(val instanceof Array)) continue;
        
        let displayVal = val;
        if (val instanceof Array) {
            displayVal = val.join(', ');
        }
        rowsHtml += `
            <tr class="exif-row" data-tag-name="${tag.toLowerCase()}" data-tag-val="${String(displayVal).toLowerCase()}">
                <td>${tag}</td>
                <td>${escapeHtml(String(displayVal))}</td>
            </tr>
        `;
    }
    tableBody.innerHTML = rowsHtml;
}

function filterExifTable(query) {
    const rows = document.querySelectorAll('.exif-row');
    rows.forEach(row => {
        const tagName = row.getAttribute('data-tag-name');
        const tagVal = row.getAttribute('data-tag-val');
        if (tagName.includes(query) || tagVal.includes(query)) {
            row.classList.remove('hidden');
        } else {
            row.classList.add('hidden');
        }
    });
}

function resetExifState() {
    // Reset inputs
    document.getElementById('image-input').value = '';
    document.getElementById('exif-search').value = '';

    // Show dropzone, hide results panels
    document.getElementById('image-dropzone').classList.remove('hidden');
    document.getElementById('image-preview-container').classList.add('hidden');
    document.getElementById('exif-empty-state').classList.remove('hidden');
    document.getElementById('exif-results').classList.add('hidden');
    
    // Reset Map instance
    if (state.leafletMap) {
        state.leafletMap.remove();
        state.leafletMap = null;
    }
    
    state.currentExifData = {};
    showToast('EXIF workspace cleared.', 'info');
    consoleLogHub('EXIF Extractor cleared for new targets.', 'system');
}

// --- PHONE LOOKUP COMPONENT ---
function setupPhoneAnalyzer() {
    const select = document.getElementById('country-select');
    const btn = document.getElementById('btn-analyze-phone');
    const input = document.getElementById('phone-input');

    if (!select || !btn || !input) return;

    // Popular countries with ISO codes
    const countries = [
        { code: 'US', name: 'United States (+1)' },
        { code: 'IN', name: 'India (+91)' },
        { code: 'GB', name: 'United Kingdom (+44)' },
        { code: 'CA', name: 'Canada (+1)' },
        { code: 'AU', name: 'Australia (+61)' },
        { code: 'DE', name: 'Germany (+49)' },
        { code: 'FR', name: 'France (+33)' },
        { code: 'BR', name: 'Brazil (+55)' },
        { code: 'ZA', name: 'South Africa (+27)' },
        { code: 'SG', name: 'Singapore (+65)' },
        { code: 'JP', name: 'Japan (+81)' },
        { code: 'RU', name: 'Russia (+7)' }
    ];

    // Populate dropdown
    select.innerHTML = `<option value="" disabled selected>Select Region</option>` + 
        countries.map(c => `<option value="${c.code}">${c.name}</option>`).join('');

    // Preselect US as default comfort option
    select.value = 'US';

    btn.addEventListener('click', () => {
        executePhoneLookup(input.value.trim(), select.value);
    });

    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            executePhoneLookup(input.value.trim(), select.value);
        }
    });
}

function executePhoneLookup(phoneVal, countryIso) {
    if (!phoneVal) {
        showToast('Please enter a target phone number.', 'error');
        return;
    }

    if (!countryIso) {
        showToast('Please select a country region code.', 'error');
        return;
    }

    try {
        // libphonenumber-js globally exposed object
        const phoneData = libphonenumber.parsePhoneNumberFromString(phoneVal, countryIso);

        if (!phoneData) {
            throw new Error("Parser output null");
        }

        const isValid = phoneData.isValid();
        displayPhoneResults(phoneData, isValid);

        if (isValid) {
            showToast('Phone structure decrypted successfully.', 'success');
            consoleLogHub(`Phone signature analyzed: ${phoneData.format('E.164')}`, 'success');
        } else {
            showToast('Potential format discrepancy detected. Validating layout failed.', 'warning');
            consoleLogHub(`Phone structure mismatch on number: "${phoneVal}" (${countryIso})`, 'warning');
        }

    } catch (err) {
        showToast('Failed to parse phone number structure.', 'error');
        consoleLogHub(`Invalid Phone payload: "${phoneVal}"`, 'warning');
    }
}

function displayPhoneResults(phone, isValid) {
    const resultsContainer = document.getElementById('phone-results');
    const detailsTable = document.getElementById('phone-details-table');
    const portalsGrid = document.getElementById('phone-portals-grid');

    if (!resultsContainer || !detailsTable || !portalsGrid) return;

    const e164 = phone.format('E.164');
    const intFormat = phone.formatInternational();
    const natFormat = phone.formatNational();
    const rawNumberOnly = e164.replace('+', '');

    // 1. Populate Telemetry details
    detailsTable.innerHTML = `
        <tr><td>Valid Record</td><td class="${isValid ? 'text-green' : 'text-purple'}">${isValid ? 'YES' : 'NO / Mismatched Layout'}</td></tr>
        <tr><td>Standard E.164</td><td>${e164}</td></tr>
        <tr><td>International Format</td><td>${intFormat}</td></tr>
        <tr><td>National Format</td><td>${natFormat}</td></tr>
        <tr><td>Carrier Region</td><td>${phone.country || 'Unknown'}</td></tr>
        <tr><td>Device Type</td><td>${phone.getType() || 'Unspecified (Landline/Mobile)'}</td></tr>
    `;

    // 2. Generate OSINT Search Links
    const escRaw = encodeURIComponent(rawNumberOnly);
    const escE164 = encodeURIComponent(e164);
    const escSpaced = encodeURIComponent(intFormat);

    portalsGrid.innerHTML = `
        <a href="https://www.truecaller.com/search?q=${escRaw}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Truecaller Identity Search</span>
                <span class="portal-url">truecaller.com</span>
            </div>
            <i data-lucide="search" class="text-cyan"></i>
        </a>
        <a href="https://wa.me/${rawNumberOnly}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Direct WhatsApp API Portal</span>
                <span class="portal-url">wa.me</span>
            </div>
            <i data-lucide="message-square" class="text-green"></i>
        </a>
        <a href="https://www.google.com/search?q=%22${escE164}%22+OR+%22${escSpaced}%22" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Google Footprint Search</span>
                <span class="portal-url">google.com</span>
            </div>
            <i data-lucide="globe" class="text-purple"></i>
        </a>
        <a href="https://sync.me/search?number=${rawNumberOnly}" target="_blank" class="portal-item">
            <div class="portal-meta">
                <span class="portal-title">Sync.Me Profile Lookup</span>
                <span class="portal-url">sync.me</span>
            </div>
            <i data-lucide="external-link" class="text-secondary"></i>
        </a>
    `;

    // US specific portals fallback
    if (phone.country === 'US') {
        portalsGrid.innerHTML += `
            <a href="https://www.spokeo.com/reverse-phone-lookup?phone=${escRaw}" target="_blank" class="portal-item">
                <div class="portal-meta">
                    <span class="portal-title">Spokeo Registry Search</span>
                    <span class="portal-url">spokeo.com</span>
                </div>
                <i data-lucide="user" class="text-cyan"></i>
            </a>
        `;
    }

    lucide.createIcons();
    resultsContainer.classList.remove('hidden');
}

// --- UTILITIES ---
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
