// Variables globales
let devices = [];
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;
let sidebarOpen = false;

// Configuración de la API
const API_BASE = '/api';

// Inicializar aplicación
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

async function initializeApp() {
    try {
        // Configurar event listeners
        setupEventListeners();
        
        // Cargar datos iniciales
        await Promise.all([
            loadStatistics(),
            loadDevices()
        ]);
        
        showSuccess();
    } catch (error) {
        console.error('Error inicializando app:', error);
        showError();
    }
}

function setupEventListeners() {
    // Búsqueda
    const searchInput = document.getElementById('searchInput');
    const clearBtn = document.getElementById('clearBtn');
    
    searchInput.addEventListener('input', handleSearch);
    searchInput.addEventListener('keyup', function(e) {
        clearBtn.classList.toggle('visible', e.target.value.length > 0);
    });
    clearBtn.addEventListener('click', clearSearch);
    
    // Botones de header
    document.getElementById('reloadBtn').addEventListener('click', reloadData);
    document.getElementById('commitBtn').addEventListener('click', commitTasks);
    
    // Sidebar
    const sidebarBtn = document.getElementById('sidebarBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const closeSidebarBtn = document.getElementById('closeSidebarBtn');
    
    if (sidebarBtn) {
        sidebarBtn.addEventListener('click', toggleSidebar);
    }
    if (closeSidebarBtn) {
        closeSidebarBtn.addEventListener('click', closeSidebar);
    }
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }
    
    // Botones del sidebar
    const historyBtn = document.getElementById('historyBtn');
    if (historyBtn) {
        historyBtn.addEventListener('click', openHistoryModal);
    }
    
    // Búsqueda de historial
    const historySearchBtn = document.getElementById('historySearchBtn');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');
    
    if (historySearchBtn) {
        historySearchBtn.addEventListener('click', searchHistory);
    }
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', clearHistorySearch);
    }
    
    // Formularios
    document.getElementById('editSSIDForm').addEventListener('submit', handleSSIDSubmit);
    document.getElementById('editPasswordForm').addEventListener('submit', handlePasswordSubmit);
    
    // Confirmación
    document.getElementById('confirmAction').addEventListener('click', executeConfirmedAction);
    
    // Toggle contraseña en modal de detalles
    document.getElementById('modalPasswordToggle').addEventListener('click', function() {
        togglePasswordVisibility('modalPassword', this);
    });
    
    // Botones del modal de detalles
    document.getElementById('editSSIDBtn').addEventListener('click', function() {
        if (currentNetwork) {
            openEditSSIDModal();
        }
    });
    
    document.getElementById('editPasswordBtn').addEventListener('click', function() {
        if (currentNetwork) {
            openEditPasswordModal();
        }
    });
    
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

// Funciones del sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebarOpen) {
        closeSidebar();
    } else {
        openSidebar();
    }
}

function openSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    sidebar.classList.add('open');
    overlay.classList.add('active');
    sidebarOpen = true;
    
    // Prevent body scroll
    document.body.style.overflow = 'hidden';
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    sidebar.classList.remove('open');
    overlay.classList.remove('active');
    sidebarOpen = false;
    
    // Restore body scroll
    document.body.style.overflow = '';
}

// Funciones de historial
async function openHistoryModal() {
    closeSidebar();
    await loadHistory();
    openModal('historyModal');
}

async function loadHistory(filters = {}) {
    try {
        const params = new URLSearchParams();
        
        if (filters.ssid) {
            params.append('ssid', filters.ssid);
        }
        if (filters.product_class) {
            params.append('product_class', filters.product_class);
        }
        
        const response = await fetch(`${API_BASE}/history?${params}`);
        const data = await response.json();
        
        if (data.success) {
            renderHistory(data.history);
        } else {
            showNotification('Error cargando historial', 'error');
        }
    } catch (error) {
        console.error('Error cargando historial:', error);
        showNotification('Error cargando historial', 'error');
    }
}

function renderHistory(history) {
    const historyList = document.getElementById('historyList');
    
    if (!history || history.length === 0) {
        historyList.innerHTML = '<div class="no-history">No se encontraron cambios en el historial</div>';
        return;
    }
    
    historyList.innerHTML = '';
    
    history.forEach(change => {
        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        
        const changeIcon = change.change_type === 'SSID' ? '📶' : '🔐';
        const changeColor = change.change_type === 'SSID' ? '#32a852' : '#ff6b35';
        
        historyItem.innerHTML = `
            <div class="history-header">
                <div class="history-device">
                    <span class="device-serial">${change.serial_number}</span>
                    <span class="device-class">${change.product_class || 'N/A'}</span>
                </div>
                <div class="history-time">${formatTimestamp(change.timestamp)}</div>
            </div>
            <div class="history-body">
                <div class="history-change">
                    <span class="change-icon" style="color: ${changeColor}">${changeIcon}</span>
                    <span class="change-type">${change.change_type}</span>
                    <span class="change-band">${change.band}</span>
                </div>
                <div class="history-network">
                    <strong>Red:</strong> ${change.ssid}
                </div>
                ${change.change_type === 'SSID' ? 
                    `<div class="history-values">
                        <span class="old-value">Anterior: ${change.old_value}</span>
                        <span class="arrow">→</span>
                        <span class="new-value">Nuevo: ${change.new_value}</span>
                    </div>` : 
                    `<div class="history-values">
                        <span class="password-change">Contraseña modificada</span>
                    </div>`
                }
            </div>
        `;
        
        historyList.appendChild(historyItem);
    });
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

async function searchHistory() {
    const ssidFilter = document.getElementById('historySsidFilter').value.trim();
    const productClassFilter = document.getElementById('historyProductClassFilter').value.trim();
    
    await loadHistory({
        ssid: ssidFilter,
        product_class: productClassFilter
    });
}

function clearHistorySearch() {
    document.getElementById('historySsidFilter').value = '';
    document.getElementById('historyProductClassFilter').value = '';
    loadHistory();
}

// Funciones de carga de datos
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE}/statistics`);
        const data = await response.json();
        
        if (data.success) {
            updateStatistics(data.statistics);
        }
    } catch (error) {
        console.error('Error cargando estadísticas:', error);
    }
}

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
            showError();
        }
    } catch (error) {
        console.error('Error cargando dispositivos:', error);
        showError();
    }
}

async function handleSearch(e) {
    const query = e.target.value.trim();
    
    try {
        const response = await fetch(`${API_BASE}/search?serial=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        if (data.success) {
            renderDevices(data.devices);
        }
    } catch (error) {
        console.error('Error en búsqueda:', error);
        renderDevices([]);
    }
}

function clearSearch() {
    const searchInput = document.getElementById('searchInput');
    const clearBtn = document.getElementById('clearBtn');
    
    searchInput.value = '';
    clearBtn.classList.remove('visible');
    renderDevices(devices);
}

async function reloadData() {
    const reloadBtn = document.getElementById('reloadBtn');
    const originalText = reloadBtn.innerHTML;
    
    reloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Recargando...';
    reloadBtn.disabled = true;
    
    try {
        await Promise.all([
            loadStatistics(),
            loadDevices()
        ]);
        showNotification('Datos recargados correctamente desde GenieACS', 'success');
    } catch (error) {
        showNotification('Error recargando datos', 'error');
    } finally {
        reloadBtn.innerHTML = originalText;
        reloadBtn.disabled = false;
    }
}

async function commitTasks() {
    const commitBtn = document.getElementById('commitBtn');
    const originalText = commitBtn.innerHTML;
    
    commitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';
    commitBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/commit-tasks`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('✅ Tareas aplicadas a GenieACS exitosamente', 'success');
        } else {
            showNotification(`❌ Error en commit: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification('❌ Error de conexión al hacer commit', 'error');
        console.error('Error en commit:', error);
    } finally {
        commitBtn.innerHTML = originalText;
        commitBtn.disabled = false;
    }
}

// Funciones de renderizado
function updateStatistics(stats) {
    document.getElementById('totalDevices').textContent = stats.total_devices || '0';
    document.getElementById('devicesWithWifi').textContent = stats.devices_with_wifi || '0';
    document.getElementById('devicesWithPasswords').textContent = stats.devices_with_passwords || '0';
    document.getElementById('totalNetworks').textContent = stats.total_wifi_networks || '0';
}

function renderDevices(devicesList) {
    const resultsCount = document.getElementById('resultsCount');
    const devicesGrid = document.getElementById('devicesGrid');
    
    resultsCount.textContent = devicesList.length;
    
    if (devicesList.length === 0) {
        showEmpty();
        return;
    }
    
    devicesGrid.innerHTML = '';
    devicesGrid.style.display = 'grid';
    hideStates();
    
    devicesList.forEach((device, index) => {
        const deviceCard = createDeviceCard(device, index);
        devicesGrid.appendChild(deviceCard);
    });
}

function createDeviceCard(device, index) {
    const card = document.createElement('div');
    card.className = 'device-card slide-up';
    card.style.animationDelay = `${index * 0.1}s`;
    
    const serialNumber = truncateText(device.serial_number || 'N/A', 25);
    const productClass = device.product_class || 'Dispositivo';
    const wifiNetworks = device.wifi_networks || [];
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-icon">
                <i class="fas fa-router"></i>
            </div>
            <div class="device-info">
                <h4>${productClass}</h4>
                <div class="device-serial">${serialNumber}</div>
            </div>
        </div>
        
        <div class="wifi-networks">
            ${wifiNetworks.map(network => `
                <div class="wifi-network" onclick="openNetworkDetails('${device.serial_number}', '${network.band}')">
                    <div class="network-header">
                        <div class="network-ssid">
                            <i class="fas fa-wifi"></i>
                            <span>${network.ssid}</span>
                            <span class="band-badge ${network.band === '5GHz' ? 'band-5' : 'band-2-4'}">${network.band}</span>
                        </div>
                    </div>
                    <div class="network-password">
                        <div class="password-display">
                            <i class="fas fa-key"></i>
                            <span class="password-value">${network.password ? '••••••••' : 'Sin contraseña'}</span>
                            ${network.password ? `
                                <button class="password-toggle" onclick="event.stopPropagation(); toggleNetworkPassword(this, '${network.password}')" type="button">
                                    <i class="fas fa-eye"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    
    return card;
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function toggleNetworkPassword(button, password) {
    const passwordValue = button.parentElement.querySelector('.password-value');
    const icon = button.querySelector('i');
    
    if (passwordValue.textContent === '••••••••') {
        passwordValue.textContent = password;
        icon.className = 'fas fa-eye-slash';
    } else {
        passwordValue.textContent = '••••••••';
        icon.className = 'fas fa-eye';
    }
}

// Funciones de modal
function openNetworkDetails(serialNumber, band) {
    const device = devices.find(d => d.serial_number === serialNumber);
    const network = device.wifi_networks.find(n => n.band === band);
    
    if (!device || !network) {
        showNotification('Red no encontrada', 'error');
        return;
    }
    
    currentDevice = device;
    currentNetwork = network;
    
    // Llenar datos del modal
    document.getElementById('modalSerialNumber').textContent = device.serial_number;
    document.getElementById('modalProductClass').textContent = device.product_class;
    document.getElementById('modalIP').textContent = device.ip;
    document.getElementById('modalMAC').textContent = device.mac;
    document.getElementById('modalBand').textContent = network.band;
    document.getElementById('modalSSID').textContent = network.ssid;
    document.getElementById('modalPassword').textContent = network.password || 'Sin contraseña';
    
    openModal('networkDetailsModal');
}

function openEditSSIDModal() {
    closeModal('networkDetailsModal');
    document.getElementById('currentSSID').value = currentNetwork.ssid;
    document.getElementById('newSSID').value = currentNetwork.ssid;
    openModal('editSSIDModal');
}

function openEditPasswordModal() {
    closeModal('networkDetailsModal');
    document.getElementById('currentPassword').value = currentNetwork.password || '';
    document.getElementById('newPassword').value = '';
    openModal('editPasswordModal');
}

function openModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    document.body.style.overflow = '';
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
    document.body.style.overflow = '';
}

// Funciones de formulario
async function handleSSIDSubmit(e) {
    e.preventDefault();
    
    const newSSID = document.getElementById('newSSID').value.trim();
    
    if (!newSSID) {
        showNotification('SSID no puede estar vacío', 'error');
        return;
    }
    
    if (newSSID === currentNetwork.ssid) {
        showNotification('El SSID es el mismo', 'warning');
        return;
    }
    
    showConfirmation(
        `¿Confirmar cambio de SSID?\n\nRed: ${currentNetwork.ssid}\nBanda: ${currentNetwork.band}\n\nNuevo SSID: ${newSSID}`,
        () => updateSSID(newSSID)
    );
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value.trim();
    
    if (newPassword && (newPassword.length < 8 || newPassword.length > 63)) {
        showNotification('Contraseña debe tener entre 8 y 63 caracteres', 'error');
        return;
    }
    
    if (newPassword === currentNetwork.password) {
        showNotification('La contraseña es la misma', 'warning');
        return;
    }
    
    showConfirmation(
        `¿Confirmar cambio de contraseña?\n\nRed: ${currentNetwork.ssid}\nBanda: ${currentNetwork.band}`,
        () => updatePassword(newPassword)
    );
}

async function updateSSID(newSSID) {
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/ssid`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ssid: newSSID })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('SSID actualizado exitosamente', 'success');
            currentNetwork.ssid = newSSID;
            closeAllModals();
            await reloadData();
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification('Error de conexión', 'error');
        console.error('Error actualizando SSID:', error);
    }
}

async function updatePassword(newPassword) {
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: newPassword })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('Contraseña actualizada exitosamente', 'success');
            currentNetwork.password = newPassword;
            closeAllModals();
            await reloadData();
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification('Error de conexión', 'error');
        console.error('Error actualizando contraseña:', error);
    }
}

// Funciones de utilidad
function showConfirmation(message, action) {
    document.getElementById('confirmMessage').textContent = message;
    pendingAction = action;
    openModal('confirmModal');
}

function executeConfirmedAction() {
    if (pendingAction) {
        pendingAction();
        pendingAction = null;
    }
    closeModal('confirmModal');
}

function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');
    
    if (input.textContent.includes('•')) {
        input.textContent = currentNetwork.password || 'Sin contraseña';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.textContent = currentNetwork.password ? '••••••••' : 'Sin contraseña';
        icon.className = 'fas fa-eye';
    }
}

function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer') || createNotificationContainer();
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-times-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    notification.innerHTML = `
        <i class="${icons[type]}"></i>
        <div class="notification-content">
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notificationContainer';
    container.className = 'notification-container';
    document.body.appendChild(container);
    return container;
}

// Funciones de estado
function showLoading() {
    hideStates();
    document.getElementById('loadingState').style.display = 'block';
}

function showError() {
    hideStates();
    document.getElementById('errorState').style.display = 'block';
}

function showEmpty() {
    hideStates();
    document.getElementById('emptyState').style.display = 'block';
}

function showSuccess() {
    hideStates();
    document.getElementById('devicesGrid').style.display = 'grid';
}

function hideStates() {
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('errorState').style.display = 'none';
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('devicesGrid').style.display = 'none';
}