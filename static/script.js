// Variables globales
let devices = [];
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
    // Búsqueda principal
    const searchInput = document.getElementById('searchInput');
    const clearBtn = document.getElementById('clearBtn');
    const searchBtn = document.getElementById('searchBtn');
    const clearAllFilters = document.getElementById('clearAllFilters');

    // Event listeners para búsqueda
    if (searchInput) {
        searchInput.addEventListener('input', handleMainSearch);
        searchInput.addEventListener('keyup', function(e) {
            if (clearBtn) clearBtn.classList.toggle('visible', e.target.value.length > 0);
            if (e.key === 'Enter') {
                performAdvancedSearch();
            }
        });
    }

    if (clearBtn) clearBtn.addEventListener('click', clearMainSearch);
    if (searchBtn) searchBtn.addEventListener('click', performAdvancedSearch);
    if (clearAllFilters) clearAllFilters.addEventListener('click', clearAllFiltersFunc);

    // Filtros adicionales con Enter
    ['productClassFilter', 'ipFilter', 'ssidFilter'].forEach(filterId => {
        const element = document.getElementById(filterId);
        if (element) {
            element.addEventListener('keyup', function(e) {
                if (e.key === 'Enter') {
                    performAdvancedSearch();
                }
            });
        }
    });

    // Botones de header
    const reloadBtn = document.getElementById('reloadBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    if (reloadBtn) reloadBtn.addEventListener('click', reloadData);
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

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
    if (historyBtn) historyBtn.addEventListener('click', openHistoryModal);

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

    // Toggle contraseña en modal de detalles
    const modalPasswordToggle = document.getElementById('modalPasswordToggle');
    if (modalPasswordToggle) {
        modalPasswordToggle.addEventListener('click', function() {
            togglePasswordVisibility('modalPassword', this);
        });
    }

    // Botones del modal de detalles
    const editSSIDBtn = document.getElementById('editSSIDBtn');
    const editPasswordBtn = document.getElementById('editPasswordBtn');
    if (editSSIDBtn) {
        editSSIDBtn.addEventListener('click', function() {
            if (currentNetwork) {
                openEditSSIDModal();
            }
        });
    }
    if (editPasswordBtn) {
        editPasswordBtn.addEventListener('click', function() {
            if (currentNetwork) {
                openEditPasswordModal();
            }
        });
    }

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

// Funciones de búsqueda
async function handleMainSearch(e) {
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

async function performAdvancedSearch() {
    const filters = {
        serial: document.getElementById('searchInput')?.value?.trim() || '',
        product_class: document.getElementById('productClassFilter')?.value?.trim() || '',
        ip: document.getElementById('ipFilter')?.value?.trim() || '',
        ssid: document.getElementById('ssidFilter')?.value?.trim() || ''
    };

    try {
        const params = new URLSearchParams();
        Object.keys(filters).forEach(key => {
            if (filters[key]) {
                params.append(key, filters[key]);
            }
        });

        const response = await fetch(`${API_BASE}/search?${params}`);
        const data = await response.json();
        if (data.success) {
            renderDevices(data.devices);
            // Mostrar notificación con resultados
            const count = data.devices.length;
            if (count === 0) {
                showNotification('No se encontraron dispositivos con esos filtros', 'info');
            } else {
                showNotification(`Se encontraron ${count} dispositivo${count !== 1 ? 's' : ''}`, 'success');
            }
        }
    } catch (error) {
        console.error('Error en búsqueda avanzada:', error);
        showNotification('Error realizando búsqueda', 'error');
    }
}

function clearMainSearch() {
    const searchInput = document.getElementById('searchInput');
    const clearBtn = document.getElementById('clearBtn');
    if (searchInput) searchInput.value = '';
    if (clearBtn) clearBtn.classList.remove('visible');
    renderDevices(devices);
}

function clearAllFiltersFunc() {
    const inputs = ['searchInput', 'productClassFilter', 'ipFilter', 'ssidFilter'];
    inputs.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) clearBtn.classList.remove('visible');
    renderDevices(devices);
    showNotification('Filtros limpiados', 'info');
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
    const devicesGrid = document.getElementById('devicesGrid');

    if (loadingState) loadingState.style.display = 'block';
    if (errorState) errorState.style.display = 'none';
    if (emptyState) emptyState.style.display = 'none';
    if (devicesGrid) devicesGrid.style.display = 'none';
}

function showError() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const devicesGrid = document.getElementById('devicesGrid');

    if (loadingState) loadingState.style.display = 'none';
    if (errorState) errorState.style.display = 'block';
    if (emptyState) emptyState.style.display = 'none';
    if (devicesGrid) devicesGrid.style.display = 'none';
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
    const devicesGrid = document.getElementById('devicesGrid');

    if (loadingState) loadingState.style.display = 'none';
    if (errorState) errorState.style.display = 'none';
    if (emptyState) emptyState.style.display = 'block';
    if (devicesGrid) devicesGrid.style.display = 'none';
}

// Renderizar dispositivos
function renderDevices(deviceList) {
    const devicesGrid = document.getElementById('devicesGrid');
    const emptyState = document.getElementById('emptyState');

    if (!devicesGrid) return;

    if (!deviceList || deviceList.length === 0) {
        showEmpty();
        return;
    }

    devicesGrid.innerHTML = '';
    devicesGrid.style.display = 'grid';
    if (emptyState) emptyState.style.display = 'none';

    deviceList.forEach((device, index) => {
        const deviceCard = createDeviceCard(device);
        devicesGrid.appendChild(deviceCard);
        
        // Animación escalonada
        setTimeout(() => {
            deviceCard.classList.add('slide-up');
        }, index * 100);
    });
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';

    const networks = device.wifi_networks || [];
    const networksHtml = networks.map(network => 
        createNetworkHtml(device, network)
    ).join('');

    card.innerHTML = `
        <div class="device-header">
            <div class="device-icon">
                <i class="fas fa-router"></i>
            </div>
            <div class="device-info">
                <h4>Dispositivo ${device.product_class || 'Desconocido'}</h4>
                <div class="device-serial">${device.serial_number || 'N/A'}</div>
            </div>
        </div>
        <div class="wifi-networks">
            ${networksHtml}
        </div>
        <div class="device-details" style="padding: 16px; border-top: 1px solid var(--color-card-border-inner); font-size: 12px; color: var(--color-text-secondary);">
            <div><strong>IP:</strong> ${device.ip || 'N/A'}</div>
            <div><strong>MAC:</strong> ${device.mac || 'N/A'}</div>
            <div><strong>Último Contacto:</strong> ${device.last_inform || 'N/A'}</div>
        </div>
    `;

    return card;
}

function createNetworkHtml(device, network) {
    const bandClass = network.band === '5GHz' ? 'band-5' : 'band-2-4';
    const hasPassword = network.password && network.password.trim();
    const passwordDisplay = hasPassword ? '••••••••' : 'Sin contraseña';

    return `
        <div class="wifi-network" onclick="openNetworkDetails('${device.serial_number}', '${network.band}')">
            <div class="network-header">
                <div class="network-ssid">
                    <span>${network.ssid || 'Sin SSID'}</span>
                    <span class="band-badge ${bandClass}">${network.band}</span>
                </div>
            </div>
            <div class="network-password">
                <i class="fas fa-key"></i>
                <div class="password-display">
                    <span class="password-value">${passwordDisplay}</span>
                </div>
            </div>
        </div>
    `;
}

// Modal de detalles de red
function openNetworkDetails(serialNumber, band) {
    const device = devices.find(d => d.serial_number === serialNumber);
    if (!device) return;

    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;

    currentDevice = device;
    currentNetwork = network;

    const modal = document.getElementById('networkDetailsModal');
    const modalSSID = document.getElementById('modalSSID');
    const modalBand = document.getElementById('modalBand');
    const modalPassword = document.getElementById('modalPassword');
    const modalWlanConfig = document.getElementById('modalWlanConfig');

    if (modalSSID) modalSSID.textContent = network.ssid || 'Sin SSID';
    if (modalBand) modalBand.textContent = network.band;
    if (modalPassword) modalPassword.textContent = network.password || 'Sin contraseña';
    if (modalWlanConfig) modalWlanConfig.textContent = network.wlan_configuration || 'N/A';

    openModal('networkDetailsModal');
}

// Funciones del sidebar
function toggleSidebar() {
    if (sidebarOpen) {
        closeSidebar();
    } else {
        openSidebar();
    }
}

function openSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (sidebar) sidebar.classList.add('open');
    if (overlay) overlay.classList.add('active');
    sidebarOpen = true;
    document.body.style.overflow = 'hidden';
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    sidebarOpen = false;
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
        if (filters.ssid) params.append('ssid', filters.ssid);
        if (filters.product_class) params.append('product_class', filters.product_class);
        if (filters.username) params.append('username', filters.username);

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
    if (!historyList) return;

    if (!history || history.length === 0) {
        historyList.innerHTML = `
            <div class="no-history">
                <i class="fas fa-info-circle"></i>
                <p>No se encontraron cambios en el historial</p>
            </div>
        `;
        return;
    }

    historyList.innerHTML = '';
    history.forEach(item => {
        const historyItem = createHistoryItem(item);
        historyList.appendChild(historyItem);
    });
}

function createHistoryItem(item) {
    const div = document.createElement('div');
    div.className = 'history-item';

    const changeIcon = item.change_type === 'SSID' ? 'fa-wifi' : 'fa-key';
    const changeTypeText = item.change_type === 'SSID' ? 'Cambio de SSID' : 'Cambio de Contraseña';

    div.innerHTML = `
        <div class="history-header">
            <div class="history-device">
                <div class="device-serial">${item.serial_number}</div>
                <div class="device-class">${item.product_class || 'N/A'}</div>
            </div>
            <div class="history-time">${formatHistoryTime(item.timestamp)}</div>
        </div>
        <div class="history-body">
            <div class="history-change">
                <i class="fas ${changeIcon} change-icon"></i>
                <div class="change-type">${changeTypeText}</div>
                <div class="change-band ${item.band === '5GHz' ? 'band-5' : 'band-2-4'}">${item.band}</div>
                <div class="history-network">${item.ssid}</div>
            </div>
            ${item.change_type === 'SSID' ? `
                <div class="history-values">
                    <span class="old-value">${item.old_value}</span>
                    <span class="arrow">→</span>
                    <span class="new-value">${item.new_value}</span>
                </div>
            ` : `
                <div class="history-values">
                    <span class="password-change">Contraseña modificada</span>
                </div>
            `}
            <div style="margin-top: 8px; font-size: 11px; color: var(--color-text-secondary);">
                <i class="fas fa-user"></i> ${item.username || 'Sistema'}
            </div>
        </div>
    `;

    return div;
}

function formatHistoryTime(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleString('es-ES');
    } catch (error) {
        return timestamp;
    }
}

async function searchHistory() {
    const filters = {
        ssid: document.getElementById('historySSIDFilter')?.value?.trim() || '',
        product_class: document.getElementById('historyProductClassFilter')?.value?.trim() || '',
        username: document.getElementById('historyUserFilter')?.value?.trim() || ''
    };

    await loadHistory(filters);
}

function clearHistorySearch() {
    const inputs = ['historySSIDFilter', 'historyProductClassFilter', 'historyUserFilter'];
    inputs.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });
    loadHistory();
}

// Funciones de modales
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
    document.body.style.overflow = '';
}

// Funciones de edición
function openEditSSIDModal() {
    if (!currentNetwork) return;
    
    const newSSIDInput = document.getElementById('newSSID');
    if (newSSIDInput) newSSIDInput.value = currentNetwork.ssid || '';
    
    closeModal('networkDetailsModal');
    openModal('editSSIDModal');
}

function openEditPasswordModal() {
    if (!currentNetwork) return;
    
    const newPasswordInput = document.getElementById('newPassword');
    if (newPasswordInput) newPasswordInput.value = currentNetwork.password || '';
    
    closeModal('networkDetailsModal');
    openModal('editPasswordModal');
}

async function handleSSIDSubmit(e) {
    e.preventDefault();
    if (!currentDevice || !currentNetwork) return;

    const newSSID = document.getElementById('newSSID')?.value?.trim();
    if (!newSSID) {
        showNotification('El SSID no puede estar vacío', 'error');
        return;
    }

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
        console.error('Error actualizando SSID:', error);
        showNotification('Error de conexión', 'error');
    }
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    if (!currentDevice || !currentNetwork) return;

    const newPassword = document.getElementById('newPassword')?.value?.trim();
    if (!newPassword) {
        showNotification('La contraseña no puede estar vacía', 'error');
        return;
    }

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
        console.error('Error actualizando contraseña:', error);
        showNotification('Error de conexión', 'error');
    }
}

// Funciones auxiliares
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');
    
    if (!input || !icon) return;
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

function executeConfirmedAction() {
    if (pendingAction) {
        pendingAction();
        pendingAction = null;
    }
    closeModal('confirmModal');
}

// Sistema de notificaciones
function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    if (!container) return;

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    const iconMap = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };

    notification.innerHTML = `
        <i class="fas ${iconMap[type] || iconMap.info}"></i>
        <div class="notification-content">
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close" onclick="closeNotification(this)">
            <i class="fas fa-times"></i>
        </button>
    `;

    container.appendChild(notification);

    // Auto-cerrar después de 5 segundos
    setTimeout(() => {
        closeNotification(notification.querySelector('.notification-close'));
    }, 5000);
}

function closeNotification(button) {
    const notification = button.closest('.notification');
    if (notification) {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }
}