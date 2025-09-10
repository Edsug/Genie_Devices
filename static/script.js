// GenieACS WiFi Manager - JavaScript Principal

// Variables globales
let devices = { all: [], configured: [], unconfigured: [] };
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;
let sidebarOpen = false;
let currentUser = null;
let currentFilter = 'all';
let currentTheme = 'system';
let currentSearchQuery = '';

// Configuración de la API
const API_BASE = '/api';

// Inicializar aplicación
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

async function initializeApp() {
    try {
        // Verificar autenticación
        const authCheck = await checkAuthentication();
        if (!authCheck) {
            window.location.href = '/login';
            return;
        }

        // Cargar tema del usuario
        await loadUserTheme();

        // Configurar event listeners
        setupEventListeners();
        setupCSVEventListeners();
        
        // Cargar datos iniciales
        await loadDevices();
    } catch (error) {
        console.error('Error inicializando app:', error);
        showError();
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
        console.error('Error verificando autenticación:', error);
        return false;
    }
}

function updateUserInfo(user) {
    const userInfoElement = document.getElementById('currentUser');
    if (userInfoElement) {
        userInfoElement.innerHTML = `
            <i class="fas fa-user-circle"></i>
            <span>${user.username} (${user.role_name})</span>
        `;
    }
}

function setupEventListeners() {
    // Menu toggle
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

    // Search
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    
    if (searchInput) {
        searchInput.addEventListener('input', handleSearch);
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
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
        refreshBtn.addEventListener('click', loadDevices);
    }

    // Theme selector
    document.querySelectorAll('.theme-option').forEach(option => {
        option.addEventListener('click', function() {
            const theme = this.dataset.theme;
            setTheme(theme);
        });
    });

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

    // History button
    const showHistoryBtn = document.getElementById('showHistoryBtn');
    if (showHistoryBtn) {
        showHistoryBtn.addEventListener('click', function() {
            closeSidebar();
            showHistoryModal();
        });
    }

    // Import history button
    const showImportHistoryBtn = document.getElementById('showImportHistoryBtn');
    if (showImportHistoryBtn) {
        showImportHistoryBtn.addEventListener('click', function() {
            closeSidebar();
            showImportHistoryModal();
        });
    }

    // Edit form handlers
    setupEditFormHandlers();
    setupContractFormHandlers();
}

function setupCSVEventListeners() {
    const selectFileBtn = document.getElementById('selectFileBtn');
    const csvFileInput = document.getElementById('csvFileInput');

    if (selectFileBtn && csvFileInput) {
        selectFileBtn.addEventListener('click', () => {
            csvFileInput.click();
        });

        csvFileInput.addEventListener('change', handleFileSelection);
    }
}

function handleFileSelection(event) {
    const file = event.target.files[0];
    const selectedFileDiv = document.getElementById('selectedFile');
    
    if (file && selectedFileDiv) {
        selectedFileDiv.innerHTML = `
            <div class="file-info">
                <i class="fas fa-file-csv"></i>
                <span>${file.name}</span>
                <button class="btn btn-primary btn-sm" onclick="uploadCSV()">
                    <i class="fas fa-upload"></i>
                    Procesar Archivo
                </button>
            </div>
        `;
        selectedFileDiv.classList.remove('hidden');
    }
}

async function uploadCSV() {
    const fileInput = document.getElementById('csvFileInput');
    const file = fileInput.files[0];
    
    if (!file) {
        showNotification('error', 'Por favor selecciona un archivo');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('file_type', 'matched_items');

    try {
        showNotification('info', 'Procesando archivo CSV...');
        
        const response = await fetch('/api/csv/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        
        if (result.success) {
            showNotification('success', `Archivo procesado: ${result.stats.imported} importados, ${result.stats.updated} actualizados`);
            
            // Limpiar selección
            fileInput.value = '';
            document.getElementById('selectedFile').classList.add('hidden');
            
            // Recargar dispositivos para mostrar la nueva información
            await loadDevices();
        } else {
            if (result.code === 'ALREADY_PROCESSED') {
                showNotification('warning', result.message);
            } else {
                showNotification('error', result.message);
            }
        }
    } catch (error) {
        console.error('Error uploading CSV:', error);
        showNotification('error', 'Error procesando el archivo CSV');
    }
}

function toggleSidebar() {
    sidebarOpen = !sidebarOpen;
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebarOpen) {
        sidebar.classList.add('open');
        overlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    } else {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function closeSidebar() {
    sidebarOpen = false;
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    sidebar.classList.remove('open');
    overlay.classList.remove('active');
    document.body.style.overflow = '';
}

function handleSearch() {
    const searchInput = document.getElementById('searchInput');
    currentSearchQuery = searchInput.value.trim();
    applyFiltersAndSearch();
}

function clearSearch() {
    const searchInput = document.getElementById('searchInput');
    searchInput.value = '';
    currentSearchQuery = '';
    applyFiltersAndSearch();
}

function setActiveFilter(filter) {
    // Update active tab
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const activeTab = document.querySelector(`[data-filter="${filter}"]`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    currentFilter = filter;
    applyFiltersAndSearch();
}

function applyFiltersAndSearch() {
    let filteredDevices = [];
    
    // Apply filter first
    switch (currentFilter) {
        case 'configured':
            filteredDevices = devices.configured || [];
            break;
        case 'unconfigured':
            filteredDevices = devices.unconfigured || [];
            break;
        default:
            filteredDevices = devices.all || [];
            break;
    }
    
    // Apply search
    if (currentSearchQuery) {
        const query = currentSearchQuery.toLowerCase();
        filteredDevices = filteredDevices.filter(device => {
            return (
                (device.contract_number && device.contract_number.toLowerCase().includes(query)) ||
                (device.serial_number && device.serial_number.toLowerCase().includes(query)) ||
                (device.ip && device.ip.toLowerCase().includes(query)) ||
                (device.wifi_networks && device.wifi_networks.some(network => 
                    network.ssid && network.ssid.toLowerCase().includes(query)
                )) ||
                (device.customer_name && device.customer_name.toLowerCase().includes(query))
            );
        });
    }
    
    renderDevices(filteredDevices);
}

async function loadDevices() {
    try {
        showLoading();
        
        const response = await fetch('/api/devices');
        const data = await response.json();
        
        if (data.success) {
            devices.all = [...(data.devices.configured || []), ...(data.devices.unconfigured || [])];
            devices.configured = data.devices.configured || [];
            devices.unconfigured = data.devices.unconfigured || [];
            
            updateFilterCounts();
            applyFiltersAndSearch();
            hideLoading();
        } else {
            showError();
        }
    } catch (error) {
        console.error('Error loading devices:', error);
        showError();
    }
}

function updateFilterCounts() {
    // Update counts in filter tabs
    document.getElementById('countAll').textContent = devices.all.length;
    document.getElementById('countConfigured').textContent = devices.configured.length;
    document.getElementById('countUnconfigured').textContent = devices.unconfigured.length;
}

function renderDevices(deviceList) {
    const grid = document.getElementById('devicesGrid');
    
    if (!deviceList || deviceList.length === 0) {
        showEmptyState();
        return;
    }
    
    hideAllStates();
    
    grid.innerHTML = deviceList.map(device => createDeviceCard(device)).join('');
    
    // Add event listeners to new cards
    addDeviceCardListeners();
}

function createDeviceCard(device) {
    const configured = device.configured ? 'configured' : 'unconfigured';
    const statusIcon = device.configured ? 'check-circle' : 'exclamation-triangle';
    const statusText = device.configured ? 'Configurado' : 'Pendiente';
    
    // Get 5GHz network for title
    const primaryNetwork = device.wifi_networks.find(n => n.band === '5GHz') || device.wifi_networks[0];
    const title = primaryNetwork ? primaryNetwork.ssid : device.serial_number;
    
    // Get networks HTML
    const networksHtml = device.wifi_networks.map(network => `
        <div class="network-item">
            <div class="network-header">
                <span class="network-band ${network.band === '5GHz' ? 'band-5g' : 'band-2g'}">${network.band}</span>
                <span class="network-ssid">${network.ssid}</span>
                <button class="password-toggle-btn ${network.password ? 'has-password' : 'no-password'}" 
                        onclick="togglePassword(this)" 
                        data-password="${network.password || ''}"
                        title="${network.password ? 'Ver contraseña' : 'Sin contraseña'}">
                    <i class="fas ${network.password ? 'fa-eye' : 'fa-eye-slash'}"></i>
                </button>
            </div>
            <div class="network-password hidden"></div>
            <button class="network-edit-btn" onclick="editNetwork('${device.serial_number}', '${network.band}', '${network.ssid}', '${network.password || ''}')">
                <i class="fas fa-edit"></i>
                Editar Red
            </button>
        </div>
    `).join('');

    return `
        <div class="device-card ${configured}" data-serial="${device.serial_number}">
            <div class="device-header">
                <div class="device-title-section">
                    <button class="device-title" onclick="showDeviceInfo('${device.serial_number}')" title="Ver información completa">
                        <span>${title}</span>
                        <i class="fas fa-info-circle"></i>
                    </button>
                    <button class="device-contract ${device.contract_number ? 'has-contract' : 'no-contract'}" 
                            onclick="editContract('${device.serial_number}', '${device.contract_number || ''}')"
                            title="Editar contrato">
                        <i class="fas fa-file-contract"></i>
                        <span>${device.contract_number || 'Sin contrato'}</span>
                        <i class="fas fa-edit edit-icon"></i>
                    </button>
                    <div class="device-customer ${device.customer_name ? 'has-customer' : 'no-customer'}">
                        <i class="fas fa-user"></i>
                        <span>${device.customer_name || 'Sin cliente'}</span>
                    </div>
                </div>
                <div class="device-status ${configured}">
                    <i class="fas fa-${statusIcon}"></i>
                    <span>${statusText}</span>
                </div>
            </div>
            <div class="device-networks">
                ${networksHtml}
            </div>
            <div class="device-info">
                <div class="device-detail">
                    <i class="fas fa-microchip"></i>
                    <span>${device.product_class}</span>
                </div>
                <div class="device-detail">
                    <i class="fas fa-network-wired"></i>
                    <span>${device.ip}</span>
                </div>
            </div>
        </div>
    `;
}

function addDeviceCardListeners() {
    // Add animation class after DOM is updated
    setTimeout(() => {
        document.querySelectorAll('.device-card').forEach((card, index) => {
            setTimeout(() => {
                card.classList.add('slide-up');
            }, index * 50);
        });
    }, 10);
}

function togglePassword(button) {
    const password = button.dataset.password;
    const passwordDiv = button.closest('.network-item').querySelector('.network-password');
    const icon = button.querySelector('i');
    
    if (passwordDiv.classList.contains('hidden')) {
        if (password) {
            passwordDiv.textContent = password;
            passwordDiv.classList.remove('hidden');
            icon.className = 'fas fa-eye-slash';
        } else {
            showNotification('warning', 'Esta red no tiene contraseña configurada');
        }
    } else {
        passwordDiv.classList.add('hidden');
        icon.className = 'fas fa-eye';
    }
}

function editNetwork(serialNumber, band, ssid, password) {
    currentDevice = serialNumber;
    currentNetwork = { band, ssid, password };
    
    const modal = document.getElementById('editModal');
    const titleElement = document.getElementById('editModalTitle');
    const ssidInput = document.getElementById('editSSID');
    const passwordInput = document.getElementById('editPassword');
    
    titleElement.textContent = `Editar Red ${band}`;
    ssidInput.value = ssid;
    passwordInput.value = password;
    
    modal.classList.remove('hidden');
}

function editContract(serialNumber, currentContract) {
    currentDevice = serialNumber;
    
    const modal = document.getElementById('contractModal');
    const contractInput = document.getElementById('contractNumber');
    
    contractInput.value = currentContract;
    modal.classList.remove('hidden');
}

function setupEditFormHandlers() {
    const editForm = document.getElementById('editForm');
    const editCancelBtn = document.getElementById('editCancelBtn');
    const editPasswordToggle = document.getElementById('editPasswordToggle');
    
    if (editForm) {
        editForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await saveNetworkChanges();
        });
    }
    
    if (editCancelBtn) {
        editCancelBtn.addEventListener('click', closeModals);
    }
    
    if (editPasswordToggle) {
        editPasswordToggle.addEventListener('click', function() {
            const passwordInput = document.getElementById('editPassword');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                passwordInput.type = 'password';
                icon.className = 'fas fa-eye';
            }
        });
    }
}

function setupContractFormHandlers() {
    const contractForm = document.getElementById('contractForm');
    const contractCancelBtn = document.getElementById('contractCancelBtn');
    
    if (contractForm) {
        contractForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await saveContractChanges();
        });
    }
    
    if (contractCancelBtn) {
        contractCancelBtn.addEventListener('click', closeModals);
    }
}

async function saveNetworkChanges() {
    const ssidInput = document.getElementById('editSSID');
    const passwordInput = document.getElementById('editPassword');
    const saveBtn = document.getElementById('editSaveBtn');
    
    const newSSID = ssidInput.value.trim();
    const newPassword = passwordInput.value.trim();
    
    if (!newSSID) {
        showNotification('error', 'El SSID no puede estar vacío');
        return;
    }
    
    if (newPassword && (newPassword.length < 8 || newPassword.length > 63)) {
        showNotification('error', 'La contraseña debe tener entre 8 y 63 caracteres');
        return;
    }
    
    try {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
        
        // Update SSID if changed
        if (newSSID !== currentNetwork.ssid) {
            const ssidResponse = await fetch(`/api/device/${currentDevice}/wifi/${currentNetwork.band}/ssid`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ssid: newSSID })
            });
            
            const ssidResult = await ssidResponse.json();
            if (!ssidResult.success) {
                throw new Error(ssidResult.message);
            }
        }
        
        // Update password if changed
        if (newPassword !== currentNetwork.password) {
            const passwordResponse = await fetch(`/api/device/${currentDevice}/wifi/${currentNetwork.band}/password`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: newPassword })
            });
            
            const passwordResult = await passwordResponse.json();
            if (!passwordResult.success) {
                throw new Error(passwordResult.message);
            }
        }
        
        showNotification('success', 'Cambios guardados exitosamente');
        closeModals();
        
        // Reload devices to show changes
        setTimeout(() => {
            loadDevices();
        }, 1000);
        
    } catch (error) {
        console.error('Error saving changes:', error);
        showNotification('error', error.message || 'Error guardando los cambios');
    } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
    }
}

async function saveContractChanges() {
    const contractInput = document.getElementById('contractNumber');
    const saveBtn = document.getElementById('contractSaveBtn');
    
    const newContract = contractInput.value.trim();
    
    try {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
        
        const response = await fetch(`/api/device/${currentDevice}/contract`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contract: newContract })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('success', 'Contrato actualizado correctamente');
            closeModals();
            loadDevices(); // Reload to show changes
        } else {
            throw new Error(result.message);
        }
        
    } catch (error) {
        console.error('Error saving contract:', error);
        showNotification('error', error.message || 'Error guardando el contrato');
    } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Guardar';
    }
}

async function showDeviceInfo(serialNumber) {
    try {
        const response = await fetch(`/api/devices/${serialNumber}/full-info`);
        const data = await response.json();
        
        if (data.success) {
            const device = devices.all.find(d => d.serial_number === serialNumber);
            if (device) {
                const modal = document.getElementById('deviceModal');
                const title = document.getElementById('modalTitle');
                const body = document.getElementById('modalBody');
                
                title.textContent = `Información: ${device.title_ssid || device.serial_number}`;
                
                body.innerHTML = `
                    <div class="device-info-grid">
                        <div class="info-section">
                            <h4><i class="fas fa-microchip"></i> Información Técnica</h4>
                            <div class="info-item">
                                <label>Serial:</label>
                                <span class="mono">${device.serial_number}</span>
                            </div>
                            <div class="info-item">
                                <label>Modelo:</label>
                                <span>${device.product_class}</span>
                            </div>
                            <div class="info-item">
                                <label>IP:</label>
                                <span class="mono">${device.ip}</span>
                            </div>
                            <div class="info-item">
                                <label>MAC:</label>
                                <span class="mono">${device.mac}</span>
                            </div>
                            <div class="info-item">
                                <label>Último contacto:</label>
                                <span>${device.last_inform || 'No disponible'}</span>
                            </div>
                        </div>
                        
                        <div class="info-section">
                            <h4><i class="fas fa-file-contract"></i> Información del Cliente</h4>
                            <div class="info-item">
                                <label>Contrato:</label>
                                <span>${device.contract_number || 'Sin contrato'}</span>
                            </div>
                            <div class="info-item">
                                <label>Cliente:</label>
                                <span>${device.customer_name || 'Sin cliente'}</span>
                            </div>
                        </div>
                        
                        <div class="info-section">
                            <h4><i class="fas fa-wifi"></i> Redes WiFi</h4>
                            ${device.wifi_networks.map(network => `
                                <div class="network-info">
                                    <div class="network-band ${network.band === '5GHz' ? 'band-5g' : 'band-2g'}">${network.band}</div>
                                    <div class="info-item">
                                        <label>SSID:</label>
                                        <span>${network.ssid}</span>
                                    </div>
                                    <div class="info-item">
                                        <label>Contraseña:</label>
                                        <span class="mono">${network.password || 'Sin contraseña'}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
                
                modal.classList.remove('hidden');
            }
        }
    } catch (error) {
        console.error('Error loading device info:', error);
        showNotification('error', 'Error cargando información del dispositivo');
    }
}

async function showHistoryModal() {
    const modal = document.getElementById('historyModal');
    const historyList = document.getElementById('historyList');
    
    try {
        historyList.innerHTML = '<div class="loading-text">Cargando historial...</div>';
        modal.classList.remove('hidden');
        
        const response = await fetch('/api/history?limit=100');
        const data = await response.json();
        
        if (data.success && data.history.length > 0) {
            historyList.innerHTML = data.history.map(item => `
                <div class="history-item">
                    <div class="history-header">
                        <div class="history-type ${item.change_type.toLowerCase()}">
                            ${item.change_type}
                        </div>
                        <div class="history-date">${formatDate(item.timestamp)}</div>
                    </div>
                    <div class="history-details">
                        <div class="history-device">
                            <strong>Dispositivo:</strong> ${item.serial_number}
                            ${item.contract_number ? `(${item.contract_number})` : ''}
                        </div>
                        ${item.band ? `<div><strong>Banda:</strong> ${item.band}</div>` : ''}
                        ${item.ssid ? `<div><strong>SSID:</strong> ${item.ssid}</div>` : ''}
                        <div class="history-change">
                            <strong>Cambio:</strong> "${item.old_value}" → "${item.new_value}"
                        </div>
                        <div class="history-user">
                            <strong>Usuario:</strong> ${item.username || 'Sistema'}
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            historyList.innerHTML = '<div class="empty-message">No hay registros en el historial</div>';
        }
    } catch (error) {
        console.error('Error loading history:', error);
        historyList.innerHTML = '<div class="error-message">Error cargando el historial</div>';
    }
}

async function showImportHistoryModal() {
    const modal = document.getElementById('importHistoryModal');
    const importHistoryList = document.getElementById('importHistoryList');
    
    try {
        importHistoryList.innerHTML = '<div class="loading-text">Cargando historial de importaciones...</div>';
        modal.classList.remove('hidden');
        
        const response = await fetch('/api/csv/import-history');
        const data = await response.json();
        
        if (data.success && data.history.length > 0) {
            importHistoryList.innerHTML = data.history.map(item => `
                <div class="import-history-item ${item.status}">
                    <div class="import-header">
                        <div class="import-file">
                            <i class="fas fa-file-csv"></i>
                            ${item.file_name}
                        </div>
                        <div class="import-status ${item.status}">
                            ${item.status === 'completed' ? 'Completado' : 
                              item.status === 'failed' ? 'Fallido' : 'Procesando'}
                        </div>
                    </div>
                    <div class="import-stats">
                        <span>Procesados: ${item.records_processed || 0}</span>
                        <span>Importados: ${item.records_imported || 0}</span>
                        <span>Actualizados: ${item.records_updated || 0}</span>
                        <span>Omitidos: ${item.records_skipped || 0}</span>
                    </div>
                    <div class="import-date">${formatDate(item.created_at)}</div>
                    ${item.error_message ? `<div class="import-error">${item.error_message}</div>` : ''}
                </div>
            `).join('');
        } else {
            importHistoryList.innerHTML = '<div class="empty-message">No hay importaciones registradas</div>';
        }
    } catch (error) {
        console.error('Error loading import history:', error);
        importHistoryList.innerHTML = '<div class="error-message">Error cargando el historial de importaciones</div>';
    }
}

function closeModals() {
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.classList.add('hidden');
    });
    currentDevice = null;
    currentNetwork = null;
}

function showLoading() {
    hideAllStates();
    document.getElementById('loadingState').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loadingState').classList.add('hidden');
}

function showEmptyState() {
    hideAllStates();
    document.getElementById('emptyState').classList.remove('hidden');
}

function showError() {
    hideAllStates();
    document.getElementById('errorState').classList.remove('hidden');
}

function hideAllStates() {
    document.getElementById('loadingState').classList.add('hidden');
    document.getElementById('emptyState').classList.add('hidden');
    document.getElementById('errorState').classList.add('hidden');
    document.getElementById('devicesGrid').style.display = 'grid';
}

function showNotification(type, message) {
    const notification = document.getElementById('notification');
    const content = notification.querySelector('.notification-content');
    const icon = content.querySelector('.notification-icon');
    const text = content.querySelector('.notification-text');
    const closeBtn = content.querySelector('.notification-close');
    
    // Set icon based on type
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    icon.className = `notification-icon fas ${icons[type] || icons.info}`;
    text.textContent = message;
    
    // Set notification type class
    notification.className = `notification ${type}`;
    
    // Show notification
    notification.classList.add('show');
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        notification.classList.remove('show');
    }, 5000);
    
    // Close button handler
    closeBtn.onclick = () => {
        notification.classList.remove('show');
    };
}

async function loadUserTheme() {
    try {
        const response = await fetch('/api/user/theme');
        const data = await response.json();
        
        if (data.success) {
            currentTheme = data.theme;
            applyTheme(currentTheme);
            updateThemeSelector(currentTheme);
        }
    } catch (error) {
        console.error('Error loading user theme:', error);
    }
}

async function setTheme(theme) {
    try {
        const response = await fetch('/api/user/theme', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ theme })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentTheme = theme;
            applyTheme(theme);
            updateThemeSelector(theme);
            showNotification('success', 'Tema actualizado');
        }
    } catch (error) {
        console.error('Error setting theme:', error);
        showNotification('error', 'Error actualizando el tema');
    }
}

function applyTheme(theme) {
    const html = document.documentElement;
    
    if (theme === 'light') {
        html.setAttribute('data-color-scheme', 'light');
    } else if (theme === 'dark') {
        html.setAttribute('data-color-scheme', 'dark');
    } else {
        html.removeAttribute('data-color-scheme');
    }
}

function updateThemeSelector(activeTheme) {
    document.querySelectorAll('.theme-option').forEach(option => {
        option.classList.remove('active');
        if (option.dataset.theme === activeTheme) {
            option.classList.add('active');
        }
    });
}

function formatDate(dateString) {
    if (!dateString) return 'No disponible';
    
    try {
        const date = new Date(dateString);
        return date.toLocaleString('es-ES', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (error) {
        return 'Fecha inválida';
    }
}