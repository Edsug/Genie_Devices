// Variables globales
let devices = { configured: [], unconfigured: [] };
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;
let sidebarOpen = false;
let currentUser = null;
let currentFilter = 'all'; // all, configured, unconfigured

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
    // Búsqueda inteligente
    const smartSearchInput = document.getElementById('smartSearchInput');
    const clearSmartBtn = document.getElementById('clearSmartBtn');
    const reloadBtn = document.getElementById('reloadBtn');

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

    // Botones de navegación
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            setActiveFilter(filter);
            filterDevices(filter);
        });
    });

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
    ['historySSIDFilter', 'historyContractFilter', 'historyProductClassFilter', 'historyUserFilter'].forEach(filterId => {
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
    const editContractForm = document.getElementById('editContractForm');
    const editSSIDForm = document.getElementById('editSSIDForm');
    const editPasswordForm = document.getElementById('editPasswordForm');

    if (editContractForm) editContractForm.addEventListener('submit', handleContractSubmit);
    if (editSSIDForm) editSSIDForm.addEventListener('submit', handleSSIDSubmit);
    if (editPasswordForm) editPasswordForm.addEventListener('submit', handlePasswordSubmit);

    // Toggle contraseña en modal de edición
    const passwordToggleEdit = document.getElementById('passwordToggleEdit');
    if (passwordToggleEdit) {
        passwordToggleEdit.addEventListener('click', function() {
            togglePasswordVisibility('passwordInput', this);
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

// Funciones de navegación
function setActiveFilter(filter) {
    currentFilter = filter;
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-filter') === filter) {
            btn.classList.add('active');
        }
    });
}

function filterDevices(filter) {
    const query = document.getElementById('smartSearchInput')?.value?.trim() || '';
    
    if (query) {
        // Si hay búsqueda, usar search con filtro
        performSmartSearch(filter);
    } else {
        // Sin búsqueda, filtrar localmente
        if (filter === 'all') {
            renderDevices(devices);
        } else if (filter === 'configured') {
            renderDevices({ configured: devices.configured, unconfigured: [] });
        } else if (filter === 'unconfigured') {
            renderDevices({ configured: [], unconfigured: devices.unconfigured });
        }
    }
}

// Funciones de búsqueda inteligente
async function handleSmartSearch(e) {
    const query = e.target.value.trim();
    if (!query) {
        filterDevices(currentFilter);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}&filter=${currentFilter}`);
        const data = await response.json();
        if (data.success) {
            renderDevices(data.devices);
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

async function performSmartSearch(filter = null) {
    const query = document.getElementById('smartSearchInput')?.value?.trim() || '';
    const searchFilter = filter || currentFilter;
    
    try {
        const response = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}&filter=${searchFilter}`);
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
    
    filterDevices(currentFilter);
}

// Funciones de carga de datos
async function loadDevices() {
    showLoading();
    try {
        const response = await fetch(`${API_BASE}/devices`);
        const data = await response.json();
        
        if (data.success) {
            devices = data.devices;
            filterDevices(currentFilter);
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

    // Mostrar secciones según filtro activo
    const showConfigured = currentFilter === 'all' || currentFilter === 'configured';
    const showUnconfigured = currentFilter === 'all' || currentFilter === 'unconfigured';

    if (configuredSection) {
        configuredSection.style.display = (showConfigured && configured.length > 0) ? 'block' : 'none';
    }
    if (unconfiguredSection) {
        unconfiguredSection.style.display = (showUnconfigured && unconfigured.length > 0) ? 'block' : 'none';
    }
    if (emptyState) emptyState.style.display = 'none';

    // Renderizar dispositivos configurados
    if (showConfigured) {
        configuredGrid.innerHTML = '';
        configured.forEach((device, index) => {
            const deviceCard = createDeviceCard(device);
            configuredGrid.appendChild(deviceCard);
            // Animación escalonada
            setTimeout(() => {
                deviceCard.classList.add('slide-up');
            }, index * 50);
        });
    }

    // Renderizar dispositivos no configurados
    if (showUnconfigured) {
        unconfiguredGrid.innerHTML = '';
        unconfigured.forEach((device, index) => {
            const deviceCard = createDeviceCard(device);
            unconfiguredGrid.appendChild(deviceCard);
            // Animación escalonada
            setTimeout(() => {
                deviceCard.classList.add('slide-up');
            }, (configured.length + index) * 50);
        });
    }

    // Actualizar contadores
    updateSectionCounts(configured.length, unconfigured.length);
}

function updateSectionCounts(configuredCount, unconfiguredCount) {
    const configuredCountElem = document.getElementById('configuredCount');
    const unconfiguredCountElem = document.getElementById('unconfiguredCount');

    if (configuredCountElem) {
        configuredCountElem.textContent = `${configuredCount} dispositivo${configuredCount !== 1 ? 's' : ''}`;
    }
    if (unconfiguredCountElem) {
        unconfiguredCountElem.textContent = `${unconfiguredCount} dispositivo${unconfiguredCount !== 1 ? 's' : ''}`;
    }
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';

    const networks = device.wifi_networks || [];
    const statusClass = device.configured ? 'configured' : 'unconfigured';
    const statusText = device.configured ? 'Configurado' : 'Sin configurar';
    const statusIcon = device.configured ? 'fa-check-circle' : 'fa-exclamation-triangle';

    // Crear botones de redes limpios
    const networksHtml = networks.map(network => createNetworkButtonHtml(device, network)).join('');

    card.innerHTML = `
        <div class="device-header-clean">
            <div class="device-title-section">
                <h4 class="device-title" onclick="editDeviceTitle('${device.serial_number}')">
                    <i class="fas fa-edit edit-icon"></i>
                    ${device.title_ssid || 'Sin nombre'}
                </h4>
                <div class="device-contract" onclick="editDeviceContract('${device.serial_number}')">
                    <i class="fas fa-file-contract"></i>
                    <span>${device.contract_number || 'Sin contrato'}</span>
                    <i class="fas fa-edit edit-icon"></i>
                </div>
            </div>
            <div class="device-status ${statusClass}">
                <i class="fas ${statusIcon}"></i>
                <span>${statusText}</span>
            </div>
        </div>
        <div class="device-networks-clean">
            ${networksHtml}
        </div>
    `;

    return card;
}

function createNetworkButtonHtml(device, network) {
    const bandClass = network.band === '5GHz' ? 'band-5' : 'band-2-4';
    const hasPassword = network.password && network.password.trim();
    const passwordDisplay = hasPassword ? '••••••••' : 'Sin contraseña';
    
    return `
        <div class="network-button" onclick="openNetworkDetails('${device.serial_number}', '${network.band}')">
            <div class="network-button-header">
                <div class="network-button-info">
                    <span class="band-badge ${bandClass}">${network.band}</span>
                    <span class="network-ssid">${network.ssid}</span>
                </div>
                <button class="password-quick-toggle" onclick="event.stopPropagation(); quickTogglePassword(this, '${network.password || ''}')" ${!hasPassword ? 'disabled' : ''}>
                    <i class="fas fa-eye"></i>
                </button>
            </div>
            <div class="network-password-preview">
                <i class="fas fa-key"></i>
                <span class="password-preview-text">${passwordDisplay}</span>
            </div>
        </div>
    `;
}

// Funciones de edición rápida
function editDeviceTitle(serialNumber) {
    const device = findDeviceBySerial(serialNumber);
    if (!device) return;

    const newTitle = prompt('Ingresa el nuevo título (SSID 5G):', device.title_ssid || '');
    if (newTitle !== null && newTitle.trim()) {
        // Buscar red 5GHz y actualizar SSID
        const network5g = device.wifi_networks.find(n => n.band === '5GHz');
        if (network5g) {
            updateSSID(serialNumber, '5GHz', newTitle.trim());
        }
    }
}

function editDeviceContract(serialNumber) {
    currentDevice = findDeviceBySerial(serialNumber);
    if (!currentDevice) return;

    const contractInput = document.getElementById('contractInput');
    if (contractInput) {
        contractInput.value = currentDevice.contract_number || '';
    }

    openModal('editContractModal');
}

function quickTogglePassword(button, password) {
    const passwordText = button.parentElement.parentElement.querySelector('.password-preview-text');
    const icon = button.querySelector('i');
    
    if (icon.classList.contains('fa-eye')) {
        // Mostrar contraseña
        passwordText.textContent = password || 'Sin contraseña';
        icon.className = 'fas fa-eye-slash';
        button.classList.add('active');
    } else {
        // Ocultar contraseña
        passwordText.textContent = password ? '••••••••' : 'Sin contraseña';
        icon.className = 'fas fa-eye';
        button.classList.remove('active');
    }
}

// Funciones de detalles de red
function openNetworkDetails(serialNumber, band) {
    const device = findDeviceBySerial(serialNumber);
    if (!device) return;

    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;

    currentDevice = device;
    currentNetwork = network;

    // Establecer título del modal
    const modalTitle = document.getElementById('networkModalTitle');
    if (modalTitle) {
        modalTitle.innerHTML = `<i class="fas fa-wifi"></i> Red ${network.band} - ${network.ssid}`;
    }

    // Cargar detalles técnicos
    const detailsContent = document.getElementById('networkDetailsContent');
    if (detailsContent) {
        detailsContent.innerHTML = `
            <div class="technical-details">
                <h4><i class="fas fa-info-circle"></i> Información Técnica</h4>
                <div class="detail-row">
                    <label>Dispositivo:</label>
                    <span>${device.serial_number}</span>
                </div>
                <div class="detail-row">
                    <label>Modelo:</label>
                    <span>${device.product_class}</span>
                </div>
                <div class="detail-row">
                    <label>IP:</label>
                    <span>${device.ip}</span>
                </div>
                <div class="detail-row">
                    <label>MAC:</label>
                    <span>${device.mac}</span>
                </div>
                <div class="detail-row">
                    <label>Última conexión:</label>
                    <span>${device.last_inform || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <label>Versión Software:</label>
                    <span>${device.software_version || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <label>Versión Hardware:</label>
                    <span>${device.hardware_version || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <label>Contrato:</label>
                    <span>${device.contract_number || 'Sin asignar'}</span>
                </div>
            </div>
            <div class="network-current-config">
                <h4><i class="fas fa-wifi"></i> Configuración Actual</h4>
                <div class="detail-row">
                    <label>SSID:</label>
                    <span>${network.ssid}</span>
                </div>
                <div class="detail-row">
                    <label>Banda:</label>
                    <span>${network.band}</span>
                </div>
                <div class="detail-row">
                    <label>Contraseña:</label>
                    <div class="password-display">
                        <span id="modalPassword" class="password-value">${network.password ? '••••••••' : 'Sin contraseña'}</span>
                        <button id="modalPasswordToggle" class="password-toggle" ${!network.password ? 'disabled' : ''}>
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                <div class="detail-row">
                    <label>Configuración WLAN:</label>
                    <span>${network.wlan_configuration}</span>
                </div>
            </div>
        `;

        // Configurar toggle de contraseña en modal
        const modalPasswordToggle = document.getElementById('modalPasswordToggle');
        if (modalPasswordToggle) {
            modalPasswordToggle.addEventListener('click', function() {
                togglePasswordVisibility('modalPassword', this, network.password);
            });
        }
    }

    openModal('networkDetailsModal');
}

// Funciones de formularios
async function handleContractSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice) return;

    const contractInput = document.getElementById('contractInput');
    const newContract = contractInput.value.trim();

    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/contract`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contract: newContract })
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Contrato actualizado correctamente', 'success');
            closeModal('editContractModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message || 'Error actualizando contrato', 'error');
        }
    } catch (error) {
        console.error('Error actualizando contrato:', error);
        showNotification('Error de conexión', 'error');
    }
}

async function handleSSIDSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice || !currentNetwork) return;

    const ssidInput = document.getElementById('ssidInput');
    const newSSID = ssidInput.value.trim();

    if (!newSSID) {
        showNotification('El SSID no puede estar vacío', 'error');
        return;
    }

    await updateSSID(currentDevice.serial_number, currentNetwork.band, newSSID);
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice || !currentNetwork) return;

    const passwordInput = document.getElementById('passwordInput');
    const newPassword = passwordInput.value.trim();

    await updatePassword(currentDevice.serial_number, currentNetwork.band, newPassword);
}

// Funciones de actualización
async function updateSSID(serialNumber, band, newSSID) {
    try {
        const response = await fetch(`${API_BASE}/device/${serialNumber}/wifi/${band}/ssid`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid: newSSID })
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('SSID actualizado correctamente', 'success');
            closeModal('editSSIDModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message || 'Error actualizando SSID', 'error');
        }
    } catch (error) {
        console.error('Error actualizando SSID:', error);
        showNotification('Error de conexión', 'error');
    }
}

async function updatePassword(serialNumber, band, newPassword) {
    try {
        const response = await fetch(`${API_BASE}/device/${serialNumber}/wifi/${band}/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword })
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Contraseña actualizada correctamente', 'success');
            closeModal('editPasswordModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message || 'Error actualizando contraseña', 'error');
        }
    } catch (error) {
        console.error('Error actualizando contraseña:', error);
        showNotification('Error de conexión', 'error');
    }
}

// Funciones auxiliares
function findDeviceBySerial(serialNumber) {
    let device = devices.configured.find(d => d.serial_number === serialNumber);
    if (!device) {
        device = devices.unconfigured.find(d => d.serial_number === serialNumber);
    }
    return device;
}

function togglePasswordVisibility(inputId, button, actualPassword = null) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');
    
    if (input.type === 'password' || input.classList.contains('password-hidden')) {
        // Mostrar contraseña
        if (actualPassword !== null) {
            input.textContent = actualPassword || 'Sin contraseña';
            input.classList.remove('password-hidden');
        } else {
            input.type = 'text';
        }
        icon.className = 'fas fa-eye-slash';
    } else {
        // Ocultar contraseña
        if (actualPassword !== null) {
            input.textContent = actualPassword ? '••••••••' : 'Sin contraseña';
            input.classList.add('password-hidden');
        } else {
            input.type = 'password';
        }
        icon.className = 'fas fa-eye';
    }
}

// Funciones de modal
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        // Enfocar primer input si existe
        const firstInput = modal.querySelector('input, textarea, select');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        // Limpiar formularios
        const forms = modal.querySelectorAll('form');
        forms.forEach(form => form.reset());
    }
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
        const forms = modal.querySelectorAll('form');
        forms.forEach(form => form.reset());
    });
}

function openEditSSIDModal() {
    if (!currentNetwork) return;
    
    const ssidInput = document.getElementById('ssidInput');
    if (ssidInput) {
        ssidInput.value = currentNetwork.ssid;
    }
    
    closeModal('networkDetailsModal');
    openModal('editSSIDModal');
}

function openEditPasswordModal() {
    if (!currentNetwork) return;
    
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.value = currentNetwork.password || '';
    }
    
    closeModal('networkDetailsModal');
    openModal('editPasswordModal');
}

// Funciones de sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebarOpen = !sidebarOpen;
        
        if (sidebarOpen) {
            sidebar.classList.add('open');
            overlay.classList.add('active');
        } else {
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
        }
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebarOpen = false;
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    }
}

// Funciones de historial
async function openHistoryModal() {
    openModal('historyModal');
    await loadHistory();
}

async function loadHistory() {
    const loadingHistory = document.getElementById('loadingHistory');
    const historyList = document.getElementById('historyList');
    
    if (loadingHistory) loadingHistory.style.display = 'block';
    if (historyList) historyList.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/history`);
        const data = await response.json();
        
        if (loadingHistory) loadingHistory.style.display = 'none';
        
        if (data.success && data.history.length > 0) {
            renderHistory(data.history);
        } else {
            if (historyList) {
                historyList.innerHTML = '<p class="empty-history">No se encontraron cambios en el historial</p>';
            }
        }
    } catch (error) {
        console.error('Error cargando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<p class="empty-history">Error cargando el historial</p>';
        }
    }
}

async function searchHistory() {
    const filters = {
        ssid: document.getElementById('historySSIDFilter')?.value || '',
        contract: document.getElementById('historyContractFilter')?.value || '',
        product_class: document.getElementById('historyProductClassFilter')?.value || '',
        username: document.getElementById('historyUserFilter')?.value || ''
    };

    const params = new URLSearchParams();
    Object.keys(filters).forEach(key => {
        if (filters[key]) {
            params.append(key, filters[key]);
        }
    });

    const loadingHistory = document.getElementById('loadingHistory');
    const historyList = document.getElementById('historyList');
    
    if (loadingHistory) loadingHistory.style.display = 'block';
    if (historyList) historyList.innerHTML = '';

    try {
        const response = await fetch(`${API_BASE}/history?${params}`);
        const data = await response.json();
        
        if (loadingHistory) loadingHistory.style.display = 'none';
        
        if (data.success && data.history.length > 0) {
            renderHistory(data.history);
        } else {
            if (historyList) {
                historyList.innerHTML = '<p class="empty-history">No se encontraron cambios con esos filtros</p>';
            }
        }
    } catch (error) {
        console.error('Error buscando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<p class="empty-history">Error realizando búsqueda</p>';
        }
    }
}

function clearHistorySearch() {
    const filterInputs = ['historySSIDFilter', 'historyContractFilter', 'historyProductClassFilter', 'historyUserFilter'];
    filterInputs.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });
    loadHistory();
}

function renderHistory(history) {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    historyList.innerHTML = history.map(item => createHistoryItemHtml(item)).join('');
}

function createHistoryItemHtml(item) {
    const changeTypeIcons = {
        'SSID': 'fa-wifi',
        'PASSWORD': 'fa-key',
        'CONTRACT': 'fa-file-contract'
    };

    const icon = changeTypeIcons[item.change_type] || 'fa-edit';
    const date = new Date(item.timestamp).toLocaleString('es-ES');

    return `
        <div class="history-item">
            <div class="history-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="history-content">
                <div class="history-header">
                    <strong>${item.change_type}</strong>
                    <span class="history-date">${date}</span>
                </div>
                <div class="history-details">
                    <span class="history-device">${item.serial_number} (${item.product_class})</span>
                    ${item.contract_number ? `<span class="history-contract">Contrato: ${item.contract_number}</span>` : ''}
                    ${item.band ? `<span class="history-band">${item.band}</span>` : ''}
                    ${item.ssid ? `<span class="history-ssid">SSID: ${item.ssid}</span>` : ''}
                </div>
                <div class="history-change">
                    ${item.old_value !== item.new_value ? 
                        `<span class="old-value">${item.old_value}</span> → <span class="new-value">${item.new_value}</span>` :
                        `<span class="password-change">${item.change_type === 'PASSWORD' ? 'Contraseña actualizada' : 'Cambio realizado'}</span>`
                    }
                </div>
                <div class="history-user">
                    <i class="fas fa-user"></i>
                    <span>${item.username}</span>
                </div>
            </div>
        </div>
    `;
}

// Funciones de confirmación
function executeConfirmedAction() {
    if (pendingAction) {
        pendingAction();
        pendingAction = null;
    }
    closeModal('confirmModal');
}

// Funciones de notificación
function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer') || document.body;
    
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
    
    container.appendChild(notification);
    
    // Mostrar notificación
    setTimeout(() => notification.classList.add('show'), 100);
    
    // Auto-ocultar después de 5 segundos
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-triangle',
        'warning': 'fa-exclamation-circle',
        'info': 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}