// Variables globales
let devices = { configured: [], unconfigured: [] };
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;
let sidebarOpen = false;
let currentUser = null;

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
        
        // Configurar event listeners
        setupEventListeners();
        
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
        userInfoElement.textContent = `${user.username} (${user.role})`;
    }
}

function setupEventListeners() {
    // Búsqueda inteligente unificada
    const smartSearchInput = document.getElementById('smartSearchInput');
    const clearSmartBtn = document.getElementById('clearSmartBtn');
    const reloadBtn = document.getElementById('reloadBtn');

    // Event listeners para búsqueda
    if (smartSearchInput) {
        smartSearchInput.addEventListener('input', handleSmartSearch);
        smartSearchInput.addEventListener('keyup', function(e) {
            if (clearSmartBtn) clearSmartBtn.classList.toggle('visible', e.target.value.length > 0);
            if (e.key === 'Enter') {
                performSmartSearch();
            }
        });
    }

    if (clearSmartBtn) clearSmartBtn.addEventListener('click', clearSmartSearch);
    if (reloadBtn) reloadBtn.addEventListener('click', reloadData);

    // Sidebar
    const sidebarBtn = document.getElementById('sidebarBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const closeSidebarBtn = document.getElementById('closeSidebarBtn');

    if (sidebarBtn) sidebarBtn.addEventListener('click', toggleSidebar);
    if (closeSidebarBtn) closeSidebarBtn.addEventListener('click', closeSidebar);
    if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeSidebar);

    // Botones del sidebar
    const historyBtn = document.getElementById('historyBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    if (historyBtn) historyBtn.addEventListener('click', openHistoryModal);
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    // Búsqueda de historial
    const historySearchBtn = document.getElementById('historySearchBtn');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');

    if (historySearchBtn) historySearchBtn.addEventListener('click', searchHistory);
    if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', clearHistorySearch);

    // Filtros de historial con Enter
    ['historySSIDFilter', 'historyProductClassFilter', 'historyUserFilter'].forEach(filterId => {
        const element = document.getElementById(filterId);
        if (element) {
            element.addEventListener('keyup', function(e) {
                if (e.key === 'Enter') {
                    searchHistory();
                }
            });
        }
    });

    // Formularios
    const editSSIDForm = document.getElementById('editSSIDForm');
    const editPasswordForm = document.getElementById('editPasswordForm');

    if (editSSIDForm) editSSIDForm.addEventListener('submit', handleSSIDSubmit);
    if (editPasswordForm) editPasswordForm.addEventListener('submit', handlePasswordSubmit);

    // Confirmación
    const confirmAction = document.getElementById('confirmAction');
    if (confirmAction) confirmAction.addEventListener('click', executeConfirmedAction);

    // Cerrar modales con ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeAllModals();
            closeSidebar();
        }
    });

    // Cerrar modales al hacer click fuera
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target.id);
        }
    });
}

// Funciones de autenticación
function logout() {
    if (confirm('¿Estás seguro de que quieres cerrar sesión?')) {
        window.location.href = '/logout';
    }
}

// Funciones de búsqueda inteligente
async function handleSmartSearch(e) {
    const query = e.target.value.trim();
    
    if (!query) {
        renderDevices(devices);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        if (data.success) {
            renderDevices(data.devices);
            
            // Mostrar información del tipo de búsqueda
            const totalResults = data.devices.configured.length + data.devices.unconfigured.length;
            if (totalResults > 0) {
                showNotification(`Se encontraron ${totalResults} dispositivo${totalResults !== 1 ? 's' : ''}`, 'success');
            }
        }
    } catch (error) {
        console.error('Error en búsqueda:', error);
        renderDevices({ configured: [], unconfigured: [] });
    }
}

async function performSmartSearch() {
    const query = document.getElementById('smartSearchInput')?.value?.trim() || '';
    
    try {
        const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        if (data.success) {
            renderDevices(data.devices);
            
            const totalResults = data.devices.configured.length + data.devices.unconfigured.length;
            if (totalResults === 0) {
                showNotification('No se encontraron dispositivos con ese criterio', 'info');
            } else {
                showNotification(`Se encontraron ${totalResults} dispositivo${totalResults !== 1 ? 's' : ''}`, 'success');
            }
        }
    } catch (error) {
        console.error('Error en búsqueda inteligente:', error);
        showNotification('Error realizando búsqueda', 'error');
    }
}

function clearSmartSearch() {
    const smartSearchInput = document.getElementById('smartSearchInput');
    const clearSmartBtn = document.getElementById('clearSmartBtn');
    
    if (smartSearchInput) smartSearchInput.value = '';
    if (clearSmartBtn) clearSmartBtn.classList.remove('visible');
    
    renderDevices(devices);
}

// Funciones de carga de datos
async function loadDevices() {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/devices`);
        const data = await response.json();
        
        if (data.success) {
            devices = data.devices;
            renderDevices(devices);
            showSuccess();
        } else {
            if (data.message && data.message.includes('Autenticación requerida')) {
                window.location.href = '/login';
                return;
            }
            showError();
        }
    } catch (error) {
        console.error('Error cargando dispositivos:', error);
        showError();
    }
}

async function reloadData() {
    const reloadBtn = document.getElementById('reloadBtn');
    if (!reloadBtn) return;

    const originalText = reloadBtn.innerHTML;
    reloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Recargando...';
    reloadBtn.disabled = true;

    try {
        await loadDevices();
        showNotification('Datos recargados correctamente', 'success');
    } catch (error) {
        showNotification('Error recargando datos', 'error');
    } finally {
        reloadBtn.innerHTML = originalText;
        reloadBtn.disabled = false;
    }
}

// Estados de la aplicación
function showLoading() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const configuredSection = document.getElementById('configuredSection');
    const unconfiguredSection = document.getElementById('unconfiguredSection');
    
    if (loadingState) loadingState.style.display = 'block';
    if (errorState) errorState.style.display = 'none';
    if (emptyState) emptyState.style.display = 'none';
    if (configuredSection) configuredSection.style.display = 'none';
    if (unconfiguredSection) unconfiguredSection.style.display = 'none';
}

function showError() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const configuredSection = document.getElementById('configuredSection');
    const unconfiguredSection = document.getElementById('unconfiguredSection');
    
    if (loadingState) loadingState.style.display = 'none';
    if (errorState) errorState.style.display = 'block';
    if (emptyState) emptyState.style.display = 'none';
    if (configuredSection) configuredSection.style.display = 'none';
    if (unconfiguredSection) unconfiguredSection.style.display = 'none';
}

function showSuccess() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    
    if (loadingState) loadingState.style.display = 'none';
    if (errorState) errorState.style.display = 'none';
}

function showEmpty() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const configuredSection = document.getElementById('configuredSection');
    const unconfiguredSection = document.getElementById('unconfiguredSection');
    
    if (loadingState) loadingState.style.display = 'none';
    if (errorState) errorState.style.display = 'none';
    if (emptyState) emptyState.style.display = 'block';
    if (configuredSection) configuredSection.style.display = 'none';
    if (unconfiguredSection) unconfiguredSection.style.display = 'none';
}

// Renderizar dispositivos con clasificación
function renderDevices(deviceData) {
    const configuredSection = document.getElementById('configuredSection');
    const unconfiguredSection = document.getElementById('unconfiguredSection');
    const configuredGrid = document.getElementById('configuredGrid');
    const unconfiguredGrid = document.getElementById('unconfiguredGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (!configuredGrid || !unconfiguredGrid) return;
    
    const configured = deviceData.configured || [];
    const unconfigured = deviceData.unconfigured || [];
    
    // Verificar si hay dispositivos
    if (configured.length === 0 && unconfigured.length === 0) {
        showEmpty();
        return;
    }
    
    // Mostrar secciones
    if (configuredSection) configuredSection.style.display = configured.length > 0 ? 'block' : 'none';
    if (unconfiguredSection) unconfiguredSection.style.display = unconfigured.length > 0 ? 'block' : 'none';
    if (emptyState) emptyState.style.display = 'none';
    
    // Renderizar dispositivos configurados
    configuredGrid.innerHTML = '';
    configured.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        configuredGrid.appendChild(deviceCard);
        
        // Animación escalonada
        setTimeout(() => {
            deviceCard.classList.add('slide-up');
        }, index * 50);
    });
    
    // Renderizar dispositivos no configurados
    unconfiguredGrid.innerHTML = '';
    unconfigured.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        unconfiguredGrid.appendChild(deviceCard);
        
        // Animación escalonada
        setTimeout(() => {
            deviceCard.classList.add('slide-up');
        }, (configured.length + index) * 50);
    });
    
    // Actualizar contadores
    updateSectionCounts(configured.length, unconfigured.length);
}

function updateSectionCounts(configuredCount, unconfiguredCount) {
    const configuredCount_elem = document.getElementById('configuredCount');
    const unconfiguredCount_elem = document.getElementById('unconfiguredCount');
    
    if (configuredCount_elem) {
        configuredCount_elem.textContent = `${configuredCount} dispositivo${configuredCount !== 1 ? 's' : ''}`;
    }
    
    if (unconfiguredCount_elem) {
        unconfiguredCount_elem.textContent = `${unconfiguredCount} dispositivo${unconfiguredCount !== 1 ? 's' : ''}`;
    }
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    
    const networks = device.wifi_networks || [];
    const networksHtml = networks.map(network => createNetworkHtml(device, network)).join('');
    
    const statusClass = device.configured ? 'configured' : 'unconfigured';
    const statusText = device.configured ? 'Configurado' : 'Sin configurar';
    const statusIcon = device.configured ? 'fa-check-circle' : 'fa-exclamation-triangle';
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-icon">
                <i class="fas fa-router"></i>
            </div>
            <div class="device-info">
                <h4>${device.product_class}</h4>
                <div class="device-serial">${device.serial_number}</div>
                <div class="device-network-info">
                    <div class="network-detail">
                        <i class="fas fa-globe"></i>
                        <span>IP: ${device.ip || 'N/A'}</span>
                    </div>
                    <div class="network-detail">
                        <i class="fas fa-network-wired"></i>
                        <span>MAC: ${device.mac || 'N/A'}</span>
                    </div>
                </div>
            </div>
            <div class="device-status ${statusClass}">
                <i class="fas ${statusIcon}"></i>
                <span>${statusText}</span>
            </div>
        </div>
        <div class="wifi-networks">
            ${networksHtml}
        </div>
    `;
    
    return card;
}

function createNetworkHtml(device, network) {
    const bandClass = network.band === '5GHz' ? 'band-5' : 'band-2-4';
    const hasPassword = network.password && network.password.trim().length > 0;
    const passwordDisplay = hasPassword ? '••••••••' : 'Sin contraseña';
    
    return `
        <div class="wifi-network" onclick="openNetworkDetails('${device.serial_number}', '${network.band}')">
            <div class="network-header">
                <div class="network-ssid">
                    <i class="fas fa-wifi"></i>
                    <span>${network.ssid}</span>
                    <span class="band-badge ${bandClass}">${network.band}</span>
                </div>
            </div>
            <div class="network-password">
                <div class="password-display">
                    <span class="password-label">Contraseña:</span>
                    <span class="password-value" id="pwd-${device.serial_number}-${network.band.replace('.', '-')}">${passwordDisplay}</span>
                    <button type="button" class="password-toggle" onclick="event.stopPropagation(); toggleNetworkPassword('${device.serial_number}', '${network.band}', '${network.password}')">
                        <i class="fas fa-eye" id="toggle-icon-${device.serial_number}-${network.band.replace('.', '-')}"></i>
                    </button>
                </div>
                <div class="network-actions">
                    <button type="button" class="btn btn-sm btn-primary" onclick="event.stopPropagation(); openEditSSIDModal('${device.serial_number}', '${network.band}')">
                        <i class="fas fa-edit"></i> SSID
                    </button>
                    <button type="button" class="btn btn-sm btn-warning" onclick="event.stopPropagation(); openEditPasswordModal('${device.serial_number}', '${network.band}')">
                        <i class="fas fa-key"></i> Password
                    </button>
                </div>
            </div>
        </div>
    `;
}

function toggleNetworkPassword(serial, band, actualPassword) {
    const passwordElement = document.getElementById(`pwd-${serial}-${band.replace('.', '-')}`);
    const toggleIcon = document.getElementById(`toggle-icon-${serial}-${band.replace('.', '-')}`);
    
    if (!passwordElement || !toggleIcon) return;
    
    const isHidden = passwordElement.textContent === '••••••••';
    
    if (isHidden) {
        passwordElement.textContent = actualPassword || 'Sin contraseña';
        toggleIcon.className = 'fas fa-eye-slash';
    } else {
        passwordElement.textContent = actualPassword ? '••••••••' : 'Sin contraseña';
        toggleIcon.className = 'fas fa-eye';
    }
}

// Funciones del Sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebarOpen) {
        closeSidebar();
    } else {
        if (sidebar) sidebar.classList.add('open');
        if (overlay) overlay.classList.add('active');
        sidebarOpen = true;
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    sidebarOpen = false;
}

// Funciones de Modales
function openNetworkDetails(serialNumber, band) {
    const configuredDevices = devices.configured || [];
    const unconfiguredDevices = devices.unconfigured || [];
    const allDevices = [...configuredDevices, ...unconfiguredDevices];
    
    const device = allDevices.find(d => d.serial_number === serialNumber);
    if (!device) return;
    
    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;
    
    currentDevice = device;
    currentNetwork = network;
    
    // Actualizar contenido del modal
    document.getElementById('modalDeviceSerial').textContent = device.serial_number;
    document.getElementById('modalProductClass').textContent = device.product_class;
    document.getElementById('modalBand').textContent = network.band;
    document.getElementById('modalSSID').textContent = network.ssid;
    document.getElementById('modalWLANConfig').textContent = network.wlan_configuration;
    
    const passwordElement = document.getElementById('modalPassword');
    const toggleButton = document.getElementById('modalPasswordToggle');
    
    if (network.password) {
        passwordElement.textContent = '••••••••';
        passwordElement.dataset.actualPassword = network.password;
        if (toggleButton) {
            toggleButton.style.display = 'inline-block';
            toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
        }
    } else {
        passwordElement.textContent = 'Sin contraseña';
        passwordElement.dataset.actualPassword = '';
        if (toggleButton) {
            toggleButton.style.display = 'none';
        }
    }
    
    openModal('networkDetailsModal');
}

function openEditSSIDModal(serialNumber, band) {
    const configuredDevices = devices.configured || [];
    const unconfiguredDevices = devices.unconfigured || [];
    const allDevices = [...configuredDevices, ...unconfiguredDevices];
    
    const device = allDevices.find(d => d.serial_number === serialNumber);
    if (!device) return;
    
    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;
    
    currentDevice = device;
    currentNetwork = network;
    
    document.getElementById('editSSIDCurrentValue').textContent = network.ssid;
    document.getElementById('newSSID').value = network.ssid;
    
    openModal('editSSIDModal');
    document.getElementById('newSSID').focus();
}

function openEditPasswordModal(serialNumber, band) {
    const configuredDevices = devices.configured || [];
    const unconfiguredDevices = devices.unconfigured || [];
    const allDevices = [...configuredDevices, ...unconfiguredDevices];
    
    const device = allDevices.find(d => d.serial_number === serialNumber);
    if (!device) return;
    
    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;
    
    currentDevice = device;
    currentNetwork = network;
    
    document.getElementById('editPasswordCurrentValue').textContent = network.password ? '••••••••' : 'Sin contraseña';
    document.getElementById('newPassword').value = '';
    
    openModal('editPasswordModal');
    document.getElementById('newPassword').focus();
}

function togglePasswordVisibility(inputId, toggleBtn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    if (inputId === 'modalPassword') {
        const actualPassword = input.dataset.actualPassword || '';
        const isHidden = input.textContent === '••••••••';
        
        if (isHidden) {
            input.textContent = actualPassword;
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            input.textContent = '••••••••';
            toggleBtn.innerHTML = '<i class="fas fa-eye"></i>';
        }
    } else {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        
        const icon = toggleBtn.querySelector('i');
        if (icon) {
            icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
        }
    }
}

// Funciones de envío de formularios
async function handleSSIDSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice || !currentNetwork) return;
    
    const newSSID = document.getElementById('newSSID').value.trim();
    if (!newSSID) {
        showNotification('El SSID no puede estar vacío', 'error');
        return;
    }
    
    const submitBtn = document.getElementById('submitSSID');
    const originalText = submitBtn.innerHTML;
    
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualizando...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/ssid`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid: newSSID })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('SSID actualizado correctamente', 'success');
            closeModal('editSSIDModal');
            await loadDevices(); // Recargar datos
        } else {
            showNotification(data.message || 'Error actualizando SSID', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice || !currentNetwork) return;
    
    const newPassword = document.getElementById('newPassword').value.trim();
    
    const submitBtn = document.getElementById('submitPassword');
    const originalText = submitBtn.innerHTML;
    
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualizando...';
    submitBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Contraseña actualizada correctamente', 'success');
            closeModal('editPasswordModal');
            await loadDevices(); // Recargar datos
        } else {
            showNotification(data.message || 'Error actualizando contraseña', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    } finally {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

// Funciones del historial - CORREGIDAS
async function openHistoryModal() {
    openModal('historyModal');
    
    // Mostrar estado de carga
    const historyContent = document.getElementById('historyContent');
    const loadingHistory = document.getElementById('loadingHistory');
    
    if (historyContent) historyContent.style.display = 'none';
    if (loadingHistory) loadingHistory.style.display = 'block';
    
    // Limpiar filtros
    clearHistorySearch();
    
    // Cargar historial
    await loadHistory();
}

async function loadHistory() {
    try {
        const response = await fetch(`${API_BASE}/history`);
        const data = await response.json();
        
        // Ocultar estado de carga SIEMPRE
        const loadingHistory = document.getElementById('loadingHistory');
        const historyContent = document.getElementById('historyContent');
        
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyContent) historyContent.style.display = 'block';
        
        if (data.success) {
            renderHistory(data.history);
        } else {
            showNotification('Error cargando historial', 'error');
            renderHistory([]);
        }
    } catch (error) {
        console.error('Error cargando historial:', error);
        
        // Asegurar que se oculte el loading
        const loadingHistory = document.getElementById('loadingHistory');
        const historyContent = document.getElementById('historyContent');
        
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyContent) historyContent.style.display = 'block';
        
        showNotification('Error de conexión cargando historial', 'error');
        renderHistory([]);
    }
}

async function searchHistory() {
    const ssidFilter = document.getElementById('historySSIDFilter').value.trim();
    const productClassFilter = document.getElementById('historyProductClassFilter').value.trim();
    const userFilter = document.getElementById('historyUserFilter').value.trim();
    
    const params = new URLSearchParams();
    if (ssidFilter) params.append('ssid', ssidFilter);
    if (productClassFilter) params.append('product_class', productClassFilter);
    if (userFilter) params.append('username', userFilter);
    
    // Mostrar estado de carga
    const historyContent = document.getElementById('historyContent');
    const loadingHistory = document.getElementById('loadingHistory');
    
    if (historyContent) historyContent.style.display = 'none';
    if (loadingHistory) loadingHistory.style.display = 'block';
    
    try {
        const response = await fetch(`${API_BASE}/history?${params}`);
        const data = await response.json();
        
        // Ocultar estado de carga SIEMPRE
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyContent) historyContent.style.display = 'block';
        
        if (data.success) {
            renderHistory(data.history);
            
            if (data.history.length === 0) {
                showNotification('No se encontraron registros con esos filtros', 'info');
            } else {
                showNotification(`Se encontraron ${data.history.length} registro${data.history.length !== 1 ? 's' : ''}`, 'success');
            }
        } else {
            renderHistory([]);
            showNotification('Error en la búsqueda', 'error');
        }
    } catch (error) {
        console.error('Error en búsqueda de historial:', error);
        
        // Asegurar que se oculte el loading
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyContent) historyContent.style.display = 'block';
        
        renderHistory([]);
        showNotification('Error de conexión', 'error');
    }
}

function clearHistorySearch() {
    const filters = ['historySSIDFilter', 'historyProductClassFilter', 'historyUserFilter'];
    filters.forEach(filterId => {
        const element = document.getElementById(filterId);
        if (element) element.value = '';
    });
}

function renderHistory(history) {
    const historyList = document.getElementById('historyList');
    const noHistoryMessage = document.getElementById('noHistoryMessage');
    
    if (!historyList) return;
    
    if (history.length === 0) {
        historyList.innerHTML = '';
        if (noHistoryMessage) noHistoryMessage.style.display = 'block';
        return;
    }
    
    if (noHistoryMessage) noHistoryMessage.style.display = 'none';
    
    historyList.innerHTML = history.map(item => `
        <div class="history-item">
            <div class="history-header">
                <div class="history-type">
                    <i class="fas ${item.change_type === 'SSID' ? 'fa-wifi' : 'fa-key'}"></i>
                    <span class="change-type">${item.change_type}</span>
                </div>
                <div class="history-date">${formatDateTime(item.timestamp)}</div>
            </div>
            <div class="history-details">
                <div class="history-device">
                    <span class="history-serial">${item.serial_number}</span>
                    <span class="history-model">${item.product_class}</span>
                    <span class="band-badge ${item.band === '5GHz' ? 'band-5' : 'band-2-4'}">${item.band}</span>
                </div>
                <div class="history-change">
                    <span class="history-ssid">${item.ssid}</span>
                    ${item.change_type === 'SSID' ? 
                        `<div class="change-values">
                            <span class="old-value">${item.old_value}</span>
                            <i class="fas fa-arrow-right"></i>
                            <span class="new-value">${item.new_value}</span>
                        </div>` : 
                        '<div class="change-values"><span class="password-change">Contraseña modificada</span></div>'
                    }
                </div>
                <div class="history-user">
                    <i class="fas fa-user"></i>
                    <span>${item.username}</span>
                </div>
            </div>
        </div>
    `).join('');
}

// Funciones utilitarias
function formatDateTime(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleDateString('es-ES', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return timestamp;
    }
}

function executeConfirmedAction() {
    if (pendingAction) {
        pendingAction();
        pendingAction = null;
    }
    closeModal('confirmationModal');
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        setTimeout(() => modal.classList.add('show'), 10);
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => modal.style.display = 'none', 300);
    }
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.classList.remove('show');
        setTimeout(() => modal.style.display = 'none', 300);
    });
}

function showNotification(message, type = 'info') {
    // Crear elemento de notificación
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Agregar al DOM
    document.body.appendChild(notification);
    
    // Mostrar con animación
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Auto-remover después de 5 segundos
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

function getNotificationIcon(type) {
    switch (type) {
        case 'success': return 'fa-check-circle';
        case 'error': return 'fa-exclamation-circle';
        case 'warning': return 'fa-exclamation-triangle';
        default: return 'fa-info-circle';
    }
}