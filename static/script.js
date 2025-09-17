// GenieACS WiFi Manager - JavaScript CON PAGINACIÓN COMPLETA

// Variables globales
let devices = { all: [], configured: [], unconfigured: [] };
let currentUser = null;
let currentFilter = 'all';
let currentPage = 1;
let totalPages = 1;
let isLoading = false;
let currentSearch = '';
let devicesPerPage = 20;

// Configuración de la API
const API_BASE = '/api';

// Archivo CSV seleccionado para importación
let selectedFile = null;

// Inicializar aplicación
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

async function initializeApp() {
    try {
        console.log('🚀 Iniciando aplicación con paginación...');
        
        // Verificar autenticación
        const authCheck = await checkAuthentication();
        if (!authCheck) {
            console.log('❌ No autenticado, redirigiendo a login');
            window.location.href = '/login';
            return;
        }
        
        console.log('✅ Usuario autenticado:', currentUser.username);
        
        // Configurar event listeners
        setupEventListeners();
        
        // Cargar primera página
        await loadDevicesPage(1);
        
    } catch (error) {
        console.error('❌ Error inicializando app:', error);
        showErrorState();
    }
}

async function checkAuthentication() {
    try {
        const response = await fetch('/api/current-user');
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.user) {
                currentUser = data.user;
                updateUserInfo(data.user);
                return true;
            }
        }
        return false;
    } catch (error) {
        console.error('❌ Error verificando autenticación:', error);
        return false;
    }
}

function updateUserInfo(user) {
    const userInfoElement = document.getElementById('currentUser');
    if (userInfoElement) {
        userInfoElement.innerHTML = `
            ${user.username} (${user.role_name})
        `;
    }
}

function setupEventListeners() {
    console.log('🔧 Configurando event listeners con paginación...');
    
    // Sidebar toggle
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const sidebarClose = document.getElementById('sidebarClose');
    
    if (menuToggle) {
        menuToggle.addEventListener('click', toggleSidebar);
    }
    
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }
    
    if (sidebarClose) {
        sidebarClose.addEventListener('click', closeSidebar);
    }
    
    // Search con debounce
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                handleSearch();
            }, 500); // Debounce de 500ms
        });
        
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                clearTimeout(searchTimeout);
                handleSearch();
            }
        });
    }
    
    if (searchClear) {
        searchClear.addEventListener('click', clearSearch);
    }
    
    // Filter tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const filter = this.dataset.filter;
            setActiveFilter(filter);
        });
    });
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', forceRefreshDevices);
    }
    
    // Retry button
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) {
        retryBtn.addEventListener('click', () => loadDevicesPage(1));
    }
    
    // Modal close handlers
    document.querySelectorAll('.modal-close').forEach(closeBtn => {
        closeBtn.addEventListener('click', closeModals);
    });
    
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', function(e) {
            if (e.target === this) {
                closeModals();
            }
        });
    });
    
    // Sidebar buttons
    const csvUploadBtn = document.getElementById('csvUploadBtn');
    if (csvUploadBtn) {
        csvUploadBtn.addEventListener('click', function() {
            closeSidebar();
            openCSVImportModal();
        });
    }
    
    // Configurar drag & drop y file input del modal
    const dropArea = document.getElementById('dropArea');
    const csvFileInput = document.getElementById('csvFileInput');
    
    if (dropArea && csvFileInput) {
        dropArea.addEventListener('click', () => csvFileInput.click());
        
        dropArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropArea.classList.add('dragover');
        });
        
        dropArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropArea.classList.remove('dragover');
        });
        
        dropArea.addEventListener('drop', (e) => {
            e.preventDefault();
            dropArea.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            handleDroppedFile(file);
        });
        
        csvFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            handleDroppedFile(file);
        });
    }
    
    const showHistoryBtn = document.getElementById('showHistoryBtn');
    if (showHistoryBtn) {
        showHistoryBtn.addEventListener('click', function() {
            closeSidebar();
            showNotification('Historial próximamente', 'info');
        });
    }
    
    const showImportHistoryBtn = document.getElementById('showImportHistoryBtn');
    if (showImportHistoryBtn) {
        showImportHistoryBtn.addEventListener('click', function() {
            closeSidebar();
            showNotification('Historial importaciones próximamente', 'info');
        });
    }

    // NUEVO: Event listeners para modal técnico
    setupTechnicalModalListeners();
}

// NUEVA FUNCIÓN: Configurar listeners del modal técnico
function setupTechnicalModalListeners() {
    // Modal técnico submit
    const technicalForm = document.getElementById('ssidPasswordForm');
    if (technicalForm) {
        technicalForm.addEventListener('submit', handleTechnicalFormSubmit);
    }

    // Botón de LAN hosts
    const loadLanHostsBtn = document.getElementById('loadLanHostsBtn');
    if (loadLanHostsBtn) {
        loadLanHostsBtn.addEventListener('click', loadLanHosts);
    }

    // Cerrar modal técnico
    const closeTechModal = document.getElementById('closeTechModal');
    if (closeTechModal) {
        closeTechModal.addEventListener('click', closeTechnicalModal);
    }

    // Dentro de la función setupTechnicalModalListeners
    document.querySelectorAll('.password-toggle-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = this.dataset.target;
            const targetInput = document.getElementById(targetId);
            const icon = this.querySelector('i');

            if (targetInput.type === 'password') {
                targetInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                targetInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

// NUEVA FUNCIÓN: Abrir modal técnico
async function openTechnicalModal(serialNumber) {
    try {
        const response = await fetch(`/api/device-info/${encodeURIComponent(serialNumber)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || 'Error obteniendo info');
        
        const device = data.device;
        const form = document.getElementById('ssidPasswordForm');

        // Llenar info estática (sección mejorada)
        document.getElementById('techSerial').textContent = device.serial_number || 'N/A';
        document.getElementById('techMac').textContent = device.mac_address || device.mac || 'N/A';
        document.getElementById('techProductClass').textContent = device.product_class || 'N/A';
        document.getElementById('techSoftware').textContent = device.software_version || 'N/A';
        document.getElementById('techHardware').textContent = device.hardware_version || 'N/A';
        document.getElementById('techIP').textContent = device.ip_address || device.ip || 'N/A';
        document.getElementById('techLastInform').textContent = device.last_inform || 'N/A';
        document.getElementById('techTags').textContent = device.tags ? (Array.isArray(device.tags) ? device.tags.join(', ') : device.tags) : 'Ninguna';
        

        let network24 = null, network5 = null;
        if (device.wifi_networks && Array.isArray(device.wifi_networks)) {
            network24 = device.wifi_networks.find(n => n.band === '2.4GHz');
            network5 = device.wifi_networks.find(n => n.band === '5GHz');
        }

        // Prellenar SSIDs y contraseñas actuales
        document.getElementById('ssid24Input').value = network24 ? (network24.ssid || '') : '';
        document.getElementById('currentPassword24').value = network24 ? (network24.password || 'No disponible') : 'No disponible';
        
        document.getElementById('ssid5Input').value = network5 ? (network5.ssid || '') : '';
        document.getElementById('currentPassword5').value = network5 ? (network5.password || 'No disponible') : 'No disponible';
        
        // Limpiar campos de nueva contraseña
        document.getElementById('newPassword24').value = '';
        document.getElementById('newPassword5').value = '';

        // Guardar valores originales
        form.dataset.originalSsid24 = network24 ? (network24.ssid || '') : '';
        form.dataset.originalSsid5 = network5 ? (network5.ssid || '') : '';
        form.dataset.serialNumber = serialNumber;

        document.getElementById('lanHostsContainer').innerHTML = '';
        document.getElementById('technicalInfoModal').classList.remove('hidden');

    } catch (error) {
        console.error('Error abriendo modal técnico:', error);
        showNotification(`Error cargando información: ${error.message}`, 'error');
    }
}

// NUEVA FUNCIÓN: Cerrar modal técnico
function closeTechnicalModal() {
    const modal = document.getElementById('technicalInfoModal');
    if (modal) {
        modal.classList.add('hidden');
    }
    
    // Limpiar formulario
    const form = document.getElementById('ssidPasswordForm');
    if (form) {
        form.reset();
        delete form.dataset.serialNumber;
    }
    
    // Limpiar container de LAN hosts
    const lanHostsContainer = document.getElementById('lanHostsContainer');
    if (lanHostsContainer) {
        lanHostsContainer.innerHTML = '';
    }
}

// NUEVA FUNCIÓN: Manejar submit del formulario técnico
async function handleTechnicalFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const serialNumber = form.dataset.serialNumber;
    const saveBtn = document.getElementById('saveTechnicalInfoBtn');

    const newValues = {
        ssid24: document.getElementById('ssid24Input').value,
        password24: document.getElementById('newPassword24').value, // <-- Cambio clave
        ssid5: document.getElementById('ssid5Input').value,
        password5: document.getElementById('newPassword5').value, // <-- Cambio clave
    };

    const originalValues = {
        ssid24: form.dataset.originalSsid24,
        ssid5: form.dataset.originalSsid5,
    };

    const tasks = [];
    if (newValues.ssid24 !== originalValues.ssid24) {
        tasks.push({ endpoint: '/api/device/update-ssid', payload: { serial_number: serialNumber, ssid: newValues.ssid24, band: '2.4GHz' }, name: 'SSID 2.4GHz' });
    }
    if (newValues.password24) { // <-- Lógica simplificada
        tasks.push({ endpoint: '/api/device/update-password', payload: { serial_number: serialNumber, password: newValues.password24, band: '2.4GHz' }, name: 'Contraseña 2.4GHz' });
    }
    if (newValues.ssid5 !== originalValues.ssid5) {
        tasks.push({ endpoint: '/api/device/update-ssid', payload: { serial_number: serialNumber, ssid: newValues.ssid5, band: '5GHz' }, name: 'SSID 5GHz' });
    }
    if (newValues.password5) { // <-- Lógica simplificada
        tasks.push({ endpoint: '/api/device/update-password', payload: { serial_number: serialNumber, password: newValues.password5, band: '5GHz' }, name: 'Contraseña 5GHz' });
    }

    if (tasks.length === 0) {
        showNotification('No hay cambios para guardar.', 'info');
        return;
    }

    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualizando...';

}

// NUEVA FUNCIÓN: Cargar LAN hosts
async function loadLanHosts() {
    const form = document.getElementById('ssidPasswordForm');
    const serialNumber = form.dataset.serialNumber;
    
    if (!serialNumber) {
        showNotification('Error: No se encontró el número de serie del dispositivo', 'error');
        return;
    }
    
    const lanHostsContainer = document.getElementById('lanHostsContainer');
    const loadBtn = document.getElementById('loadLanHostsBtn');
    
    try {
        // Mostrar loading
        loadBtn.disabled = true;
        loadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cargando...';
        lanHostsContainer.innerHTML = '<p>Cargando hosts LAN...</p>';
        
        const response = await fetch(`/api/device/${encodeURIComponent(serialNumber)}/lan-hosts`);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.message || 'Error obteniendo hosts LAN');
        }
        
        const lanHosts = data.lan_hosts || [];
        
        if (lanHosts.length === 0) {
            lanHostsContainer.innerHTML = '<p>No se encontraron hosts LAN conectados.</p>';
        } else {
            let hostListHTML = '<h4>Hosts LAN Conectados:</h4><div class="lan-hosts-list">';
            
            lanHosts.forEach(host => {
                hostListHTML += `
                    <div class="lan-host-item">
                        <div><strong>IP:</strong> ${host.ip_address || 'N/A'}</div>
                        <div><strong>MAC:</strong> ${host.mac_address || 'N/A'}</div>
                        <div><strong>Hostname:</strong> ${host.hostname || 'N/A'}</div>
                        <div><strong>Tipo:</strong> ${host.interface_type || 'N/A'}</div>
                        <div><strong>Activo:</strong> ${host.active === 'true' ? 'Sí' : 'No'}</div>
                    </div>
                `;
            });
            
            hostListHTML += '</div>';
            lanHostsContainer.innerHTML = hostListHTML;
        }
        
    } catch (error) {
        console.error('Error cargando LAN hosts:', error);
        lanHostsContainer.innerHTML = `<p style="color: var(--color-error);">Error cargando hosts LAN: ${error.message}</p>`;
    } finally {
        // Restaurar botón
        loadBtn.disabled = false;
        loadBtn.innerHTML = '<i class="fas fa-network-wired"></i> Cargar Hosts LAN';
    }
}

function openCSVImportModal() {
    const modal = document.getElementById('csvImportModal');
    if (modal) {
        modal.classList.remove('hidden');
    }
    clearCSVImportLog();
    clearProgressBar();
    selectedFile = null;
}

function closeCSVImportModal() {
    const modal = document.getElementById('csvImportModal');
    if (modal) {
        modal.classList.add('hidden');
    }
    selectedFile = null;
}

function handleDroppedFile(file) {
    if (!file) return;
    
    if (!file.name.endsWith('.csv')) {
        logCSVImport('❌ Archivo inválido. Debe ser un archivo .csv');
        return;
    }
    
    selectedFile = file;
    const fileInfo = document.getElementById('selectedFileInfo');
    if (fileInfo) {
        fileInfo.textContent = `Archivo seleccionado: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        fileInfo.classList.remove('hidden');
    }
    
    resetProgressBar();
    uploadSelectedCSV();
}

function uploadSelectedCSV() {
    if (!selectedFile) {
        logCSVImport('❌ No hay archivo seleccionado para subir.');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/csv/upload');
    xhr.withCredentials = true;
    
    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percent = (e.loaded / e.total) * 100;
            updateProgressBar(percent);
            logCSVImport(`⏳ Progreso: ${percent.toFixed(1)}%`);
        }
    };
    
    xhr.onload = function() {
        hideProgressBar();
        try {
            const resp = JSON.parse(xhr.responseText);
            if (xhr.status === 200 && resp.success) {
                logCSVImport(`✅ Importación completada. Dispositivos configurados: ${resp.configured || 0}`);
                if (resp.message) logCSVImport(`→ ${resp.message}`);
                if (resp.skipped) logCSVImport(`Filas saltadas: ${resp.skipped}`);
                if (resp.log) logCSVImport(`\n${resp.log}`);
                loadDevicesPage(1);
            } else {
                logCSVImport(`❌ Error en el servidor: ${resp.message || 'Error desconocido'}`);
            }
        } catch {
            logCSVImport(`❌ Error procesando respuesta del servidor.`);
        }
    };
    
    xhr.onerror = function() {
        hideProgressBar();
        logCSVImport('❌ Error durante la solicitud al servidor.');
    };
    
    logCSVImport('⏳ Iniciando importación...');
    xhr.send(formData);
}

function logCSVImport(message) {
    const logDiv = document.getElementById('csvUploadLog');
    if (!logDiv) return;
    
    logDiv.innerHTML += message + '\n';
    logDiv.scrollTop = logDiv.scrollHeight;
}

function clearCSVImportLog() {
    const logDiv = document.getElementById('csvUploadLog');
    if (logDiv) {
        logDiv.innerHTML = '';
    }
}

function updateProgressBar(percent) {
    const progressBar = document.getElementById('csvUploadProgress');
    if (progressBar) {
        progressBar.value = percent;
        progressBar.classList.remove('hidden');
    }
}

function resetProgressBar() {
    const progressBar = document.getElementById('csvUploadProgress');
    if (progressBar) {
        progressBar.value = 0;
        progressBar.classList.remove('hidden');
    }
}

function hideProgressBar() {
    const progressBar = document.getElementById('csvUploadProgress');
    if (progressBar) {
        progressBar.classList.add('hidden');
    }
}

function clearProgressBar() {
    hideProgressBar();
}

async function loadDevicesPage(page) {
    if (isLoading) return;
    
    console.log(`📄 Cargando página ${page} con filtro '${currentFilter}' y búsqueda '${currentSearch}'`);
    
    isLoading = true;
    showLoadingState();
    
    try {
        const params = new URLSearchParams({
            page: page.toString(),
            per_page: devicesPerPage.toString(),
            filter: currentFilter
        });
        
        if (currentSearch) {
            params.append('search', currentSearch);
        }
        
        const response = await fetch(`${API_BASE}/devices?${params}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.message || 'Error desconocido del servidor');
        }
        
        // Actualizar variables globales
        currentPage = data.pagination.page;
        totalPages = data.pagination.pages;
        
        // Actualizar interfaz
        updateDeviceGrid(data.devices);
        updatePagination(data.pagination);
        updateFilterCounts(data.counts);
        updateCacheInfo(data.cache_age, data.last_update);
        
        hideLoadingState();
        
        console.log(`✅ Página ${page} cargada: ${data.devices.length} dispositivos`);
        
    } catch (error) {
        console.error('❌ Error cargando dispositivos:', error);
        showErrorState(error.message);
        isLoading = false;
    }
    
    isLoading = false;
}

function updateDeviceGrid(deviceList) {
    const grid = document.getElementById('devicesGrid');
    if (!grid) return;
    
    if (deviceList.length === 0) {
        showEmptyState();
        return;
    }
    
    grid.innerHTML = '';
    
    deviceList.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        grid.appendChild(deviceCard);
        
        // Animación escalonada
        setTimeout(() => {
            deviceCard.classList.add('slide-up');
        }, index * 50);
    });
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = `device-card ${device.configured ? 'configured' : 'unconfigured'}`;
    card.tabIndex = 0;
    
    const statusIcon = device.configured ? 'fa-check-circle' : 'fa-exclamation-triangle';
    const statusClass = device.configured ? 'configured' : 'unconfigured';
    const statusText = device.configured ? 'Configurado' : 'No configurado';
    
    // Construir redes WiFi sin botones de edición
    let networksHTML = '';
    if (device.wifi_networks && device.wifi_networks.length > 0) {
        device.wifi_networks.forEach(network => {
            const bandClass = network.band === '5GHz' ? 'band-5g' : 'band-2g';
            const ssid = network.ssid || network.ssid_current || 'Sin SSID';
            
            networksHTML += `
                <div class="network-item">
                    <div class="network-header">
                        <span class="network-band ${bandClass}">${network.band}</span>
                        <span class="network-ssid">${ssid}</span>
                    </div>
                </div>
            `;
        });
    } else {
        networksHTML = '<div class="network-item"><span class="network-ssid">No hay redes WiFi disponibles</span></div>';
    }
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-title-section">
                <button class="device-title technical-info-btn" data-serial="${device.serial_number}">
                    ${device.title_ssid || 'Sin SSID'}
                </button>
                <div class="device-contract ${device.contract_number ? 'has-contract' : 'no-contract'}">
                    <i class="fas fa-file-contract"></i>
                    ${device.contract_number || 'Sin contrato'}
                </div>
                <div class="device-customer ${device.customer_name ? 'has-customer' : 'no-customer'}">
                    <i class="fas fa-user"></i>
                    ${device.customer_name || 'Sin cliente'}
                </div>
            </div>
            <div class="device-status ${statusClass}">
                <i class="fas ${statusIcon}"></i>
                ${statusText}
            </div>
        </div>
        
        <div class="device-networks">
            ${networksHTML}
        </div>
        
        <div class="device-info">
            <div class="device-detail">
                <i class="fas fa-barcode"></i>
                ${device.serial_number}
            </div>
            <div class="device-detail">
                <i class="fas fa-network-wired"></i>
                ${device.ip || 'Sin IP'}
            </div>
            <div class="device-detail">
                <i class="fas fa-microchip"></i>
                ${device.product_class || 'N/A'}
            </div>
        </div>
    `;
    
    // Agregar event listener al botón del título
    const titleBtn = card.querySelector('.technical-info-btn');
    if (titleBtn) {
        titleBtn.addEventListener('click', function() {
            const serialNumber = this.dataset.serial;
            openTechnicalModal(serialNumber);
        });
    }
    
    return card;
}

function updatePagination(pagination) {
    const paginationContainer = document.getElementById('paginationContainer');
    if (!paginationContainer) return;
    
    let paginationHTML = '';
    
    if (pagination.pages > 1) {
        paginationHTML = '<div class="pagination">';
        
        // Botón anterior
        if (pagination.has_prev) {
            paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(${pagination.prev_page})">
                <i class="fas fa-chevron-left"></i>
            </button>`;
        }
        
        // Números de página
        const startPage = Math.max(1, pagination.page - 2);
        const endPage = Math.min(pagination.pages, pagination.page + 2);
        
        if (startPage > 1) {
            paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(1)">1</button>`;
            if (startPage > 2) {
                paginationHTML += `<span class="pagination-dots">...</span>`;
            }
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const activeClass = i === pagination.page ? 'active' : '';
            paginationHTML += `<button class="pagination-btn ${activeClass}" onclick="loadDevicesPage(${i})">${i}</button>`;
        }
        
        if (endPage < pagination.pages) {
            if (endPage < pagination.pages - 1) {
                paginationHTML += `<span class="pagination-dots">...</span>`;
            }
            paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(${pagination.pages})">${pagination.pages}</button>`;
        }
        
        // Botón siguiente
        if (pagination.has_next) {
            paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(${pagination.next_page})">
                <i class="fas fa-chevron-right"></i>
            </button>`;
        }
        
        paginationHTML += '</div>';
        
        // Info de paginación
        paginationHTML += `
            <div class="pagination-info">
                Mostrando ${((pagination.page - 1) * pagination.per_page) + 1}-${Math.min(pagination.page * pagination.per_page, pagination.total)} 
                de ${pagination.total} dispositivos
            </div>
        `;
    }
    
    paginationContainer.innerHTML = paginationHTML;
}

function updateFilterCounts(counts) {
    const allTab = document.querySelector('[data-filter="all"] .tab-count');
    const configuredTab = document.querySelector('[data-filter="configured"] .tab-count');
    const unconfiguredTab = document.querySelector('[data-filter="unconfigured"] .tab-count');
    
    if (allTab) allTab.textContent = counts.total || 0;
    if (configuredTab) configuredTab.textContent = counts.configured || 0;
    if (unconfiguredTab) unconfiguredTab.textContent = counts.unconfigured || 0;
}

function updateCacheInfo(cacheAge, lastUpdate) {
    // Actualizar info de cache si existe elemento en la UI
    const cacheInfo = document.getElementById('cacheInfo');
    if (cacheInfo) {
        const ageText = cacheAge < 60 ? `${cacheAge}s` : `${Math.floor(cacheAge/60)}m ${cacheAge%60}s`;
        cacheInfo.textContent = `Cache: ${ageText}`;
    }
}

function showLoadingState() {
    const loadingState = document.getElementById('loadingState');
    const devicesGrid = document.getElementById('devicesGrid');
    const emptyState = document.getElementById('emptyState');
    const errorState = document.getElementById('errorState');
    
    if (loadingState) loadingState.classList.remove('hidden');
    if (devicesGrid) devicesGrid.innerHTML = '';
    if (emptyState) emptyState.classList.add('hidden');
    if (errorState) errorState.classList.add('hidden');
}

function hideLoadingState() {
    const loadingState = document.getElementById('loadingState');
    if (loadingState) loadingState.classList.add('hidden');
}

function showEmptyState() {
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    
    if (emptyState) emptyState.classList.remove('hidden');
    if (loadingState) loadingState.classList.add('hidden');
    if (errorState) errorState.classList.add('hidden');
}

function showErrorState(message = 'Error cargando dispositivos') {
    const errorState = document.getElementById('errorState');
    const loadingState = document.getElementById('loadingState');
    const emptyState = document.getElementById('emptyState');
    
    if (errorState) {
        errorState.classList.remove('hidden');
        const errorText = errorState.querySelector('.error-text p');
        if (errorText) {
            errorText.textContent = message;
        }
    }
    if (loadingState) loadingState.classList.add('hidden');
    if (emptyState) emptyState.classList.add('hidden');
}

function setActiveFilter(filter) {
    // Actualizar filtro activo visualmente
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const activeTab = document.querySelector(`[data-filter="${filter}"]`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    // Actualizar filtro actual y cargar primera página
    currentFilter = filter;
    loadDevicesPage(1);
}

function handleSearch() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        currentSearch = searchInput.value.trim();
        loadDevicesPage(1);
    }
}

function clearSearch() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.value = '';
        currentSearch = '';
        loadDevicesPage(1);
    }
}

async function forceRefreshDevices() {
    try {
        const response = await fetch('/api/devices/refresh', {
            method: 'POST'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                await loadDevicesPage(currentPage);
                showNotification('Dispositivos actualizados correctamente', 'success');
            }
        }
    } catch (error) {
        console.error('Error refrescando dispositivos:', error);
        showNotification('Error actualizando dispositivos', 'error');
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    }
}

function closeModals() {
    // Cerrar CSV import modal
    const csvModal = document.getElementById('csvImportModal');
    if (csvModal && !csvModal.classList.contains('hidden')) {
        closeCSVImportModal();
    }
    
    // Cerrar modal técnico
    const techModal = document.getElementById('technicalInfoModal');
    if (techModal && !techModal.classList.contains('hidden')) {
        closeTechnicalModal();
    }
}

function showNotification(message, type = 'info') {
    // Crear elemento de notificación
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const iconMap = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${iconMap[type]} notification-icon"></i>
            <span class="notification-text">${message}</span>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Agregar al DOM
    document.body.appendChild(notification);
    
    // Mostrar con animación
    setTimeout(() => notification.classList.add('show'), 100);
    
    // Auto-ocultar después de 5 segundos
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 5000);
    
    // Event listener para cerrar manualmente
    const closeBtn = notification.querySelector('.notification-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        });
    }
}
