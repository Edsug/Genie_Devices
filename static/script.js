// Variables globales
let devices = [];
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;

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

    // Botón recargar
    document.getElementById('reloadBtn').addEventListener('click', reloadData);

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
        }
    });

    // Cerrar modales al hacer click fuera
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            closeModal(e.target.id);
        }
    });
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
        showNotification('Datos recargados correctamente', 'success');
    } catch (error) {
        showNotification('Error recargando datos', 'error');
    } finally {
        reloadBtn.innerHTML = originalText;
        reloadBtn.disabled = false;
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
                <i class="fas fa-wifi"></i>
            </div>
            <div class="device-info">
                <h4>${productClass}</h4>
                <div class="device-serial">${serialNumber}</div>
            </div>
        </div>

        <div class="wifi-networks">
            ${wifiNetworks.map(network => createNetworkHTML(device, network)).join('')}
        </div>
    `;

    return card;
}

function createNetworkHTML(device, network) {
    const bandClass = network.band === '5GHz' ? 'band-5' : 'band-2-4';
    const primaryIcon = network.is_primary ? '<i class="fas fa-star" title="Red principal"></i>' : '';

    return `
        <div class="wifi-network" onclick="showNetworkDetails('${device.serial_number}', '${network.band}')">
            <div class="network-header">
                <div class="network-ssid">
                    <span>${network.ssid || 'Sin SSID'}</span>
                    <span class="band-badge ${bandClass}">${network.band}</span>
                    ${primaryIcon}
                </div>
            </div>
            <div class="network-password">
                <i class="fas fa-key"></i>
                <div class="password-display">
                    <span class="password-value">${maskPassword(network.password)}</span>
                    <button class="password-toggle" onclick="event.stopPropagation(); toggleNetworkPassword(this, '${network.password || ''}')" title="Mostrar/Ocultar contraseña">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
        </div>
    `;
}

// Funciones de utilidad
function truncateText(text, maxLength) {
    if (!text) return 'N/A';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

function maskPassword(password) {
    if (!password) return 'Sin contraseña';
    return '●'.repeat(Math.min(password.length, 12));
}

function toggleNetworkPassword(button, password) {
    const passwordElement = button.parentElement.querySelector('.password-value');
    const icon = button.querySelector('i');

    if (passwordElement.textContent.includes('●')) {
        passwordElement.textContent = password || 'Sin contraseña';
        icon.className = 'fas fa-eye-slash';
    } else {
        passwordElement.textContent = maskPassword(password);
        icon.className = 'fas fa-eye';
    }
}

// Funciones de modales
function showNetworkDetails(deviceSerial, networkBand) {
    // Buscar dispositivo
    const device = devices.find(d => d.serial_number === deviceSerial);
    if (!device) return;

    // Buscar red específica
    const network = device.wifi_networks.find(n => n.band === networkBand);
    if (!network) return;

    // Guardar referencias globales
    currentDevice = device;
    currentNetwork = network;

    // Llenar modal con información
    document.getElementById('modalTitle').textContent = `Red ${network.band} - ${network.ssid}`;
    document.getElementById('modalBand').textContent = network.band;
    document.getElementById('modalSSID').textContent = network.ssid || 'N/A';
    document.getElementById('modalPassword').textContent = network.password || 'Sin contraseña';
    document.getElementById('modalDevice').textContent = device.serial_number;
    document.getElementById('modalProductClass').textContent = device.product_class || 'N/A';
    document.getElementById('modalIP').textContent = device.ip || 'N/A';
    document.getElementById('modalMAC').textContent = device.mac || 'N/A';
    document.getElementById('modalLastInform').textContent = device.last_inform || 'N/A';

    // Resetear toggle de contraseña
    const toggle = document.getElementById('modalPasswordToggle');
    const passwordSpan = document.getElementById('modalPassword');
    const icon = toggle.querySelector('i');

    if (network.password) {
        passwordSpan.textContent = maskPassword(network.password);
        icon.className = 'fas fa-eye';
        toggle.style.display = 'flex';
    } else {
        toggle.style.display = 'none';
    }

    openModal('networkDetailsModal');
}

function openEditSSIDModal() {
    if (!currentNetwork) return;

    document.getElementById('currentSSID').value = currentNetwork.ssid || '';
    document.getElementById('newSSID').value = currentNetwork.ssid || '';

    closeModal('networkDetailsModal');
    openModal('editSSIDModal');

    // Enfocar y seleccionar el input
    setTimeout(() => {
        const input = document.getElementById('newSSID');
        input.focus();
        input.select();
    }, 100);
}

function openEditPasswordModal() {
    if (!currentNetwork) return;

    document.getElementById('networkSSID').value = `${currentNetwork.band} - ${currentNetwork.ssid}`;
    document.getElementById('currentPassword').value = currentNetwork.password || '';
    document.getElementById('newPassword').value = currentNetwork.password || '';

    closeModal('networkDetailsModal');
    openModal('editPasswordModal');

    // Enfocar el input
    setTimeout(() => {
        document.getElementById('newPassword').focus();
    }, 100);
}

async function handleSSIDSubmit(e) {
    e.preventDefault();

    const newSSID = document.getElementById('newSSID').value.trim();

    if (!newSSID) {
        showNotification('El SSID no puede estar vacío', 'error');
        return;
    }

    if (newSSID.length > 32) {
        showNotification('El SSID no puede tener más de 32 caracteres', 'error');
        return;
    }

    if (newSSID === currentNetwork.ssid) {
        closeModal('editSSIDModal');
        return;
    }

    // Confirmar cambio
    const message = `¿Confirmar cambio de SSID a "${newSSID}"?\nEsto puede desconectar dispositivos conectados.`;
    showConfirmModal(message, async () => {
        await updateSSID(newSSID);
    });
}

async function handlePasswordSubmit(e) {
    e.preventDefault();

    const newPassword = document.getElementById('newPassword').value.trim();

    if (newPassword && (newPassword.length < 8 || newPassword.length > 63)) {
        showNotification('La contraseña debe tener entre 8 y 63 caracteres', 'error');
        return;
    }

    if (newPassword === currentNetwork.password) {
        closeModal('editPasswordModal');
        return;
    }

    // Confirmar cambio
    const message = newPassword 
        ? `¿Confirmar cambio de contraseña WiFi?\nEsto desconectará todos los dispositivos conectados.`
        : `¿Confirmar eliminación de contraseña?\nLa red quedará abierta y sin seguridad.`;

    showConfirmModal(message, async () => {
        await updatePassword(newPassword);
    });
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
            showNotification(`SSID actualizado correctamente a "${newSSID}"`, 'success');
            closeModal('editSSIDModal');

            // Actualizar datos locales
            currentNetwork.ssid = newSSID;
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification('Error de conexión al actualizar SSID', 'error');
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
            const message = newPassword 
                ? 'Contraseña WiFi actualizada correctamente'
                : 'Contraseña WiFi eliminada - Red abierta';
            showNotification(message, 'success');
            closeModal('editPasswordModal');

            // Actualizar datos locales
            currentNetwork.password = newPassword;
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(`Error: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification('Error de conexión al actualizar contraseña', 'error');
        console.error('Error actualizando contraseña:', error);
    }
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

// Funciones de modales
function openModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    document.body.style.overflow = 'auto';
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
    document.body.style.overflow = 'auto';
}

function showConfirmModal(message, action) {
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

// Funciones de utilidad para contraseñas
function togglePasswordVisibility(elementId, button) {
    const element = document.getElementById(elementId);
    const icon = button.querySelector('i');

    if (!currentNetwork || !currentNetwork.password) return;

    if (element.textContent.includes('●')) {
        element.textContent = currentNetwork.password;
        icon.className = 'fas fa-eye-slash';
    } else {
        element.textContent = maskPassword(currentNetwork.password);
        icon.className = 'fas fa-eye';
    }
}

function togglePasswordInput(inputId) {
    const input = document.getElementById(inputId);
    const button = input.parentElement.querySelector('.password-toggle');
    const icon = button.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// Sistema de notificaciones
function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');

    let icon = 'fa-info-circle';
    let title = 'Información';

    switch (type) {
        case 'success':
            icon = 'fa-check-circle';
            title = 'Éxito';
            break;
        case 'error':
            icon = 'fa-exclamation-circle';
            title = 'Error';
            break;
        case 'warning':
            icon = 'fa-exclamation-triangle';
            title = 'Advertencia';
            break;
    }

    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas ${icon}"></i>
        <div class="notification-content">
            <div class="notification-title">${title}</div>
            <div class="notification-message">${message}</div>
        </div>
    `;

    container.appendChild(notification);

    // Auto eliminar después de 5 segundos
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);

    // Permitir cerrar al hacer click
    notification.addEventListener('click', () => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    });
}