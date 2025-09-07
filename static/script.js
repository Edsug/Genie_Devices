// Variables globales
let devices = { configured: [], unconfigured: [] };
let currentDevice = null;
let currentNetwork = null;
let pendingAction = null;
let sidebarOpen = false;
let currentUser = null;
let currentFilter = 'all'; // all, configured, unconfigured
let currentTheme = 'system'; // light, dark, system

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
            <div class="user-details">
                <span class="username">${user.username}</span>
                <span class="role">${user.role_name}</span>
            </div>
        `;
    }
}

// Gestión de tema
async function loadUserTheme() {
    try {
        const response = await fetch('/api/user/theme');
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                currentTheme = data.theme;
                applyTheme(currentTheme);
            }
        }
    } catch (error) {
        console.error('Error cargando tema:', error);
    }
}

function applyTheme(theme) {
    const root = document.documentElement;
    if (theme === 'system') {
        // Usar preferencia del sistema
        root.removeAttribute('data-color-scheme');
    } else {
        // Aplicar tema específico
        root.setAttribute('data-color-scheme', theme);
    }
    
    currentTheme = theme;
    // Actualizar botones de tema
    updateThemeButtons();
}

function updateThemeButtons() {
    const themeButtons = document.querySelectorAll('.theme-btn');
    themeButtons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-theme') === currentTheme) {
            btn.classList.add('active');
        }
    });
}

async function changeTheme(theme) {
    try {
        const response = await fetch('/api/user/theme', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ theme })
        });
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                applyTheme(theme);
                showNotification('Tema actualizado correctamente', 'success');
            }
        }
    } catch (error) {
        console.error('Error cambiando tema:', error);
        showNotification('Error cambiando tema', 'error');
    }
}

// Función para detectar contraseñas válidas
function isValidPassword(password) {
    if (!password || password.trim() === '') {
        return false;
    }
    
    const cleanPassword = password.trim();
    
    // Filtrar contraseñas inválidas comunes
    const invalidPatterns = [
        /^[*.\-_\s]+$/,           // Solo asteriscos, puntos, guiones, espacios
        /^[0-9A-Fa-f]{32}$/,      // Hash MD5
        /^[0-9A-Fa-f]{64}$/,      // Hash SHA256
        /^\$[0-9]\$.*$/,          // Hash con formato $n$...
        /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i // UUID
    ];
    
    for (const pattern of invalidPatterns) {
        if (pattern.test(cleanPassword)) {
            return false;
        }
    }
    
    // Debe tener entre 8 y 63 caracteres para WiFi
    if (cleanPassword.length < 8 || cleanPassword.length > 63) {
        return false;
    }
    
    return true;
}

// Función para mostrar contraseña o "Sin contraseña"
function displayPassword(password, hidden = true) {
    if (!password || !isValidPassword(password)) {
        return '<em class="no-password">Sin contraseña</em>';
    }
    
    if (hidden) {
        return '••••••••';
    }
    
    return password;
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
    
    // Sidebar - CORREGIDO
    const sidebarBtn = document.getElementById('sidebarBtn');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const closeSidebarBtn = document.getElementById('closeSidebarBtn');
    
    if (sidebarBtn) sidebarBtn.addEventListener('click', toggleSidebar);
    if (closeSidebarBtn) closeSidebarBtn.addEventListener('click', closeSidebar);
    if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeSidebar);
    
    // Botones del sidebar
    const historyBtn = document.getElementById('historyBtn');
    const usersBtn = document.getElementById('usersBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (historyBtn) historyBtn.addEventListener('click', openHistoryModal);
    if (usersBtn) usersBtn.addEventListener('click', openUsersModal);
    if (logoutBtn) logoutBtn.addEventListener('click', logout);
    
    // Botones de tema
    const themeButtons = document.querySelectorAll('.theme-btn');
    themeButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');
            changeTheme(theme);
        });
    });
    
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
    const createUserForm = document.getElementById('createUserForm');
    
    if (editContractForm) editContractForm.addEventListener('submit', handleContractSubmit);
    if (editSSIDForm) editSSIDForm.addEventListener('submit', handleSSIDSubmit);
    if (editPasswordForm) editPasswordForm.addEventListener('submit', handlePasswordSubmit);
    if (createUserForm) createUserForm.addEventListener('submit', handleCreateUserSubmit);
    
    // Toggle contraseña en modales
    const passwordToggles = document.querySelectorAll('.password-toggle');
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            togglePasswordVisibility(targetId, this);
        });
    });
    
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

// Renderizar dispositivos con separación visual mejorada
function renderDevices(deviceData) {
    const configuredSection = document.getElementById('configuredSection');
    const unconfiguredSection = document.getElementById('unconfiguredSection');
    const configuredGrid = document.getElementById('configuredGrid');
    const unconfiguredGrid = document.getElementById('unconfiguredGrid');
    const emptyState = document.getElementById('emptyState');
    const sectionSeparator = document.getElementById('sectionSeparator');
    
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
    
    // Mostrar separador solo cuando ambas secciones son visibles
    if (sectionSeparator) {
        const shouldShowSeparator = currentFilter === 'all' && configured.length > 0 && unconfigured.length > 0;
        sectionSeparator.style.display = shouldShowSeparator ? 'block' : 'none';
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
    
    // Crear botones de redes limpios con contraseñas validadas
    const networksHtml = networks.map(network => createNetworkButtonHtml(device, network)).join('');
    
    card.innerHTML = `
        <div class="device-header-clean">
            <div class="device-title-section">
                <h4 class="device-title" tabindex="0" 
                    onclick="openDeviceModal('${device.serial_number}')" 
                    onkeydown="if(event.key==='Enter') openDeviceModal('${device.serial_number}')">
                    ${device.title_ssid || device.serial_number}
                    <i class="fas fa-edit edit-icon"></i>
                </h4>
                <div class="device-contract" tabindex="0" 
                     onclick="editContract('${device.serial_number}', '${device.contract_number || ''}')"
                     onkeydown="if(event.key==='Enter') editContract('${device.serial_number}', '${device.contract_number || ''}')">
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
    const isValidPass = isValidPassword(network.password);
    const passwordPreview = isValidPass ? '••••••••' : 'Sin contraseña';
    const toggleIcon = isValidPass ? 'fa-eye' : 'fa-eye-slash';
    const toggleClass = isValidPass ? '' : 'disabled';
    
    return `
        <div class="network-button" 
             onclick="openNetworkModal('${device.serial_number}', '${network.band}')" 
             tabindex="0" 
             onkeydown="if(event.key==='Enter') openNetworkModal('${device.serial_number}', '${network.band}')">
            <div class="network-button-header">
                <div class="network-button-info">
                    <span class="network-ssid">${network.ssid}</span>
                    <span class="band-badge ${bandClass}">${network.band}</span>
                </div>
                <button class="password-quick-toggle ${isValidPass ? '' : 'disabled'}" 
                        onclick="event.stopPropagation(); toggleNetworkPassword(this, '${device.serial_number}', '${network.band}')" 
                        ${!isValidPass ? 'disabled' : ''}
                        aria-label="Mostrar/ocultar contraseña">
                    <i class="fas ${toggleIcon}"></i>
                </button>
            </div>
            <div class="network-password-preview">
                <i class="fas fa-key"></i>
                <span class="password-preview-text">${passwordPreview}</span>
            </div>
        </div>
    `;
}

// Funciones mejoradas para toggle de contraseñas
function toggleNetworkPassword(button, deviceSerial, band) {
    if (button.disabled) return;
    
    const device = [...devices.configured, ...devices.unconfigured]
        .find(d => d.serial_number === deviceSerial);
    
    if (!device) return;
    
    const network = device.wifi_networks.find(n => n.band === band);
    if (!network || !isValidPassword(network.password)) return;
    
    const icon = button.querySelector('i');
    const previewText = button.closest('.network-button').querySelector('.password-preview-text');
    
    const isHidden = icon.classList.contains('fa-eye');
    
    if (isHidden) {
        // Mostrar contraseña
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
        previewText.textContent = network.password;
        button.classList.add('active');
    } else {
        // Ocultar contraseña
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
        previewText.textContent = '••••••••';
        button.classList.remove('active');
    }
}

// Modales
function openDeviceModal(serialNumber) {
    const device = [...devices.configured, ...devices.unconfigured]
        .find(d => d.serial_number === serialNumber);
    
    if (!device) return;
    
    currentDevice = device;
    
    // Actualizar contenido del modal
    document.getElementById('deviceSerial').textContent = device.serial_number;
    document.getElementById('deviceProduct').textContent = device.product_class;
    document.getElementById('deviceSoftware').textContent = device.software_version || 'N/A';
    document.getElementById('deviceHardware').textContent = device.hardware_version || 'N/A';
    document.getElementById('deviceIP').textContent = device.ip || 'N/A';
    document.getElementById('deviceMAC').textContent = device.mac || 'N/A';
    document.getElementById('deviceLastInform').textContent = device.last_inform || 'N/A';
    document.getElementById('deviceContract').textContent = device.contract_number || 'Sin contrato';
    
    openModal('deviceModal');
}

function openNetworkModal(serialNumber, band) {
    const device = [...devices.configured, ...devices.unconfigured]
        .find(d => d.serial_number === serialNumber);
    
    if (!device) return;
    
    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;
    
    currentDevice = device;
    currentNetwork = network;
    
    // Actualizar contenido del modal
    document.getElementById('networkDevice').textContent = device.serial_number;
    document.getElementById('networkBand').textContent = network.band;
    document.getElementById('networkSSID').textContent = network.ssid;
    
    const passwordElement = document.getElementById('networkPassword');
    const isValidPass = isValidPassword(network.password);
    
    if (isValidPass) {
        passwordElement.innerHTML = '<span class="password-hidden">••••••••</span>';
    } else {
        passwordElement.innerHTML = '<em class="no-password">Sin contraseña</em>';
    }
    
    // Habilitar/deshabilitar botones según permisos
    const editSSIDBtn = document.getElementById('editSSIDBtn');
    const editPasswordBtn = document.getElementById('editPasswordBtn');
    
    if (editSSIDBtn && currentUser) {
        editSSIDBtn.style.display = currentUser.role_level >= 2 ? 'inline-flex' : 'none';
    }
    
    if (editPasswordBtn && currentUser) {
        editPasswordBtn.style.display = currentUser.role_level >= 1 ? 'inline-flex' : 'none';
    }
    
    openModal('networkModal');
}

function editContract(serialNumber, currentContract) {
    if (!currentUser || currentUser.role_level < 1) {
        showNotification('No tienes permisos para editar contratos', 'error');
        return;
    }
    
    const device = [...devices.configured, ...devices.unconfigured]
        .find(d => d.serial_number === serialNumber);
    
    if (!device) return;
    
    currentDevice = device;
    
    document.getElementById('contractDevice').textContent = device.serial_number;
    document.getElementById('contractCurrent').textContent = currentContract || 'Sin contrato';
    document.getElementById('contractInput').value = currentContract || '';
    
    openModal('contractModal');
}

function openEditSSIDModal() {
    if (!currentNetwork) return;
    
    document.getElementById('ssidDevice').textContent = currentDevice.serial_number;
    document.getElementById('ssidBand').textContent = currentNetwork.band;
    document.getElementById('ssidCurrent').textContent = currentNetwork.ssid;
    document.getElementById('ssidInput').value = currentNetwork.ssid;
    
    closeModal('networkModal');
    openModal('ssidModal');
}

function openEditPasswordModal() {
    if (!currentNetwork) return;
    
    document.getElementById('passwordDevice').textContent = currentDevice.serial_number;
    document.getElementById('passwordBand').textContent = currentNetwork.band;
    
    const currentPasswordDiv = document.getElementById('passwordCurrent');
    const isValidPass = isValidPassword(currentNetwork.password);
    
    if (isValidPass) {
        currentPasswordDiv.innerHTML = '<span class="password-hidden">••••••••</span>';
    } else {
        currentPasswordDiv.innerHTML = '<em class="no-password">Sin contraseña actual</em>';
    }
    
    document.getElementById('passwordInput').value = '';
    
    closeModal('networkModal');
    openModal('passwordModal');
}

// Handlers de formularios
async function handleContractSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const newContract = formData.get('contract').trim();
    
    if (!currentDevice) return;
    
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/contract`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ contract: newContract })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Contrato actualizado correctamente', 'success');
            closeModal('contractModal');
            await loadDevices(); // Recargar para actualizar la vista
        } else {
            showNotification(data.message || 'Error actualizando contrato', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    }
}

async function handleSSIDSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const newSSID = formData.get('ssid').trim();
    
    if (!currentDevice || !currentNetwork) return;
    
    if (!newSSID) {
        showNotification('El SSID no puede estar vacío', 'error');
        return;
    }
    
    if (newSSID.length > 32) {
        showNotification('El SSID no puede tener más de 32 caracteres', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/ssid`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ssid: newSSID })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('SSID actualizado correctamente', 'success');
            closeModal('ssidModal');
            await loadDevices(); // Recargar para actualizar la vista
        } else {
            showNotification(data.message || 'Error actualizando SSID', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    }
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const newPassword = formData.get('password').trim();
    
    if (!currentDevice || !currentNetwork) return;
    
    if (newPassword && (newPassword.length < 8 || newPassword.length > 63)) {
        showNotification('La contraseña debe tener entre 8 y 63 caracteres', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/device/${currentDevice.serial_number}/wifi/${currentNetwork.band}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: newPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Contraseña actualizada correctamente', 'success');
            closeModal('passwordModal');
            await loadDevices(); // Recargar para actualizar la vista
        } else {
            showNotification(data.message || 'Error actualizando contraseña', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    }
}

// Funciones de toggle de contraseña en modales
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Funciones de modal
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        // Enfocar en el primer input si existe
        const firstInput = modal.querySelector('input:not([type="hidden"])');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
}

// Sidebar CORREGIDO
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebarOpen = !sidebarOpen;
        
        if (sidebarOpen) {
            sidebar.classList.add('open');
            overlay.classList.add('active');
            document.body.style.overflow = 'hidden'; // Prevenir scroll
        } else {
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
            document.body.style.overflow = '';
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
        document.body.style.overflow = '';
    }
}

// Historial
async function openHistoryModal() {
    closeSidebar();
    await loadHistory();
    openModal('historyModal');
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
                historyList.innerHTML = '<div class="no-history">No se encontraron cambios en el historial</div>';
            }
        }
    } catch (error) {
        console.error('Error cargando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<div class="error-history">Error cargando el historial</div>';
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
                historyList.innerHTML = '<div class="no-history">No se encontraron cambios con esos filtros</div>';
            }
        }
    } catch (error) {
        console.error('Error buscando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<div class="error-history">Error realizando búsqueda</div>';
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
    
    // MOSTRAR CONTRASEÑAS REALES EN HISTORIAL - CORREGIDO
    let changeText = '';
    if (item.change_type === 'PASSWORD') {
        // Las contraseñas ya vienen normalizadas del backend
        // Si dice "Sin contraseña" mostrar como tal
        // Si es una contraseña real, mostrarla
        const oldValueDisplay = item.old_value || 'Sin contraseña anterior';
        const newValueDisplay = item.new_value || 'Sin contraseña';
        
        changeText = `
            <div class="history-change">
                <span class="old-value">${oldValueDisplay}</span> 
                <i class="fas fa-arrow-right"></i> 
                <span class="new-value">${newValueDisplay}</span>
            </div>
        `;
    } else {
        changeText = `
            <div class="history-change">
                <span class="old-value">${item.old_value}</span> 
                <i class="fas fa-arrow-right"></i> 
                <span class="new-value">${item.new_value}</span>
            </div>
        `;
    }
    
    return `
        <div class="history-item">
            <div class="history-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="history-content">
                <div class="history-header">
                    <strong>Cambio de ${item.change_type}</strong>
                    <div class="history-date">${date}</div>
                </div>
                <div class="history-details">
                    <span class="history-device">
                        <i class="fas fa-router"></i>
                        ${item.serial_number}
                    </span>
                    <span class="history-contract">
                        <i class="fas fa-file-contract"></i>
                        ${item.contract_number || 'Sin contrato'}
                    </span>
                    ${item.band ? `<span class="history-band"><i class="fas fa-wifi"></i> ${item.band}</span>` : ''}
                    ${item.ssid ? `<span class="history-ssid"><i class="fas fa-network-wired"></i> ${item.ssid}</span>` : ''}
                </div>
                ${changeText}
                <div class="history-user">
                    <i class="fas fa-user"></i>
                    ${item.username}
                </div>
            </div>
        </div>
    `;
}

// Gestión de usuarios
async function openUsersModal() {
    if (!currentUser || currentUser.role_level < 2) {
        showNotification('No tienes permisos para gestionar usuarios', 'error');
        return;
    }
    
    closeSidebar();
    await loadUsers();
    openModal('usersModal');
}

async function loadUsers() {
    const loadingUsers = document.getElementById('loadingUsers');
    const usersList = document.getElementById('usersList');
    
    if (loadingUsers) loadingUsers.style.display = 'block';
    if (usersList) usersList.innerHTML = '';
    
    try {
        const response = await fetch(`${API_BASE}/users`);
        const data = await response.json();
        
        if (loadingUsers) loadingUsers.style.display = 'none';
        
        if (data.success) {
            renderUsers(data.users, data.roles);
        } else {
            if (usersList) {
                usersList.innerHTML = '<div class="error-users">Error cargando usuarios</div>';
            }
        }
    } catch (error) {
        console.error('Error cargando usuarios:', error);
        if (loadingUsers) loadingUsers.style.display = 'none';
        if (usersList) {
            usersList.innerHTML = '<div class="error-users">Error cargando usuarios</div>';
        }
    }
}

function renderUsers(users, roles) {
    const usersList = document.getElementById('usersList');
    if (!usersList) return;
    
    const canCreateUsers = currentUser && currentUser.role_level >= 2;
    const canDeleteUsers = currentUser && currentUser.role_level >= 2;
    
    usersList.innerHTML = `
        ${canCreateUsers ? `
            <div class="create-user-form">
                <h4><i class="fas fa-user-plus"></i> Crear Nuevo Usuario</h4>
                <form id="createUserForm">
                    <div class="form-group">
                        <label for="createUsername">Nombre de usuario</label>
                        <input type="text" id="createUsername" name="username" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="createPassword">Contraseña</label>
                        <div class="password-input">
                            <input type="password" id="createPassword" name="password" class="form-control" required>
                            <button type="button" class="password-toggle" data-target="createPassword">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="createRole">Rol</label>
                        <select id="createRole" name="role" class="form-control">
                            ${currentUser.role === 'noc' ? '<option value="informatica">Informática</option>' : ''}
                            <option value="callcenter" selected>Call Center</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Crear Usuario
                    </button>
                </form>
            </div>
        ` : ''}
        
        <div class="users-list">
            ${users.map(user => `
                <div class="user-item">
                    <div class="user-info">
                        <div class="user-header">
                            <strong>${user.username}</strong>
                            <span class="user-role ${user.role}">${user.role_name}</span>
                        </div>
                        <div class="user-details">
                            <small>Creado: ${user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</small>
                            <small>Último acceso: ${user.last_login ? new Date(user.last_login).toLocaleString() : 'Nunca'}</small>
                        </div>
                        <div class="user-description">
                            <small>${roles[user.role]?.description || ''}</small>
                        </div>
                    </div>
                    <div class="user-actions">
                        ${canDeleteUsers && user.username !== 'admin' && user.id !== currentUser.id ? `
                            <button class="btn btn-warning btn-sm" 
                                    onclick="confirmDeleteUser(${user.id}, '${user.username}')">
                                <i class="fas fa-trash"></i> Eliminar
                            </button>
                        ` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    
    // Agregar event listeners para el formulario de crear usuario
    const createUserForm = document.getElementById('createUserForm');
    if (createUserForm) {
        createUserForm.addEventListener('submit', handleCreateUserSubmit);
        
        // Toggle de contraseña
        const passwordToggle = createUserForm.querySelector('.password-toggle');
        if (passwordToggle) {
            passwordToggle.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                togglePasswordVisibility(targetId, this);
            });
        }
    }
}

async function handleCreateUserSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const userData = {
        username: formData.get('username').trim(),
        password: formData.get('password').trim(),
        role: formData.get('role')
    };
    
    if (!userData.username || !userData.password) {
        showNotification('Todos los campos son requeridos', 'error');
        return;
    }
    
    if (userData.password.length < 6) {
        showNotification('La contraseña debe tener al menos 6 caracteres', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Usuario creado correctamente', 'success');
            e.target.reset();
            await loadUsers(); // Recargar lista
        } else {
            showNotification(data.message || 'Error creando usuario', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    }
}

function confirmDeleteUser(userId, username) {
    if (confirm(`¿Estás seguro de que quieres eliminar el usuario "${username}"?`)) {
        deleteUser(userId);
    }
}

async function deleteUser(userId) {
    try {
        const response = await fetch(`${API_BASE}/users/${userId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Usuario eliminado correctamente', 'success');
            await loadUsers(); // Recargar lista
        } else {
            showNotification(data.message || 'Error eliminando usuario', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error de conexión', 'error');
    }
}

// Notificaciones mejoradas
function showNotification(message, type = 'info', duration = 4000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${icons[type] || icons.info}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Mostrar animación
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    // Auto-ocultar
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, duration);
}