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
            <i class="fas fa-user"></i>
            <span>
                <strong>${user.username}</strong>
                <small>${user.role_name}</small>
            </span>
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
                <h4 class="device-title" onclick="openContractModal('${device.serial_number}', '${device.contract_number || ''}', '${device.product_class}')" tabindex="0">
                    ${device.title_ssid || device.serial_number}
                    <i class="fas fa-edit edit-icon"></i>
                </h4>
                <div class="device-contract" onclick="openContractModal('${device.serial_number}', '${device.contract_number || ''}', '${device.product_class}')" tabindex="0">
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
    const hasPassword = network.password && network.password.trim() !== '';
    const passwordPreview = hasPassword ? '••••••••' : 'Sin contraseña';
    
    return `
        <div class="network-button" onclick="openNetworkModal('${device.serial_number}', '${network.band}')">
            <div class="network-button-header">
                <div class="network-button-info">
                    <span class="network-ssid">${network.ssid}</span>
                    <span class="band-badge ${bandClass}">${network.band}</span>
                </div>
                <button class="password-quick-toggle ${hasPassword ? 'active' : ''}" 
                        onclick="event.stopPropagation(); toggleQuickPassword(this, '${device.serial_number}', '${network.band}')"
                        ${hasPassword ? '' : 'disabled'}>
                    <i class="fas ${hasPassword ? 'fa-eye' : 'fa-eye-slash'}"></i>
                </button>
            </div>
            <div class="network-password-preview">
                <i class="fas fa-key"></i>
                <span class="password-preview-text">${passwordPreview}</span>
            </div>
        </div>
    `;
}

// Quick password toggle
let passwordVisible = {};

function toggleQuickPassword(button, serialNumber, band) {
    const key = `${serialNumber}-${band}`;
    const isVisible = passwordVisible[key];
    
    if (isVisible) {
        // Ocultar contraseña
        passwordVisible[key] = false;
        button.innerHTML = '<i class="fas fa-eye"></i>';
        
        // Encontrar y actualizar la preview
        const preview = button.closest('.network-button').querySelector('.password-preview-text');
        if (preview) {
            preview.textContent = '••••••••';
        }
    } else {
        // Mostrar contraseña - buscar el dispositivo
        const device = [...devices.configured, ...devices.unconfigured]
            .find(d => d.serial_number === serialNumber);
        
        if (device) {
            const network = device.wifi_networks.find(n => n.band === band);
            if (network && network.password) {
                passwordVisible[key] = true;
                button.innerHTML = '<i class="fas fa-eye-slash"></i>';
                
                const preview = button.closest('.network-button').querySelector('.password-preview-text');
                if (preview) {
                    preview.textContent = network.password;
                }
                
                // Auto-ocultar después de 3 segundos
                setTimeout(() => {
                    if (passwordVisible[key]) {
                        toggleQuickPassword(button, serialNumber, band);
                    }
                }, 3000);
            }
        }
    }
}

// Modales de edición de contrato
function openContractModal(serialNumber, currentContract, productClass) {
    currentDevice = { serial_number: serialNumber, contract_number: currentContract, product_class: productClass };
    
    const modal = document.getElementById('editContractModal');
    const serialElement = document.getElementById('editContractSerial');
    const productElement = document.getElementById('editContractProduct');
    const contractInput = document.getElementById('contractInput');

    if (serialElement) serialElement.textContent = serialNumber;
    if (productElement) productElement.textContent = productClass;
    if (contractInput) contractInput.value = currentContract || '';

    openModal('editContractModal');
}

async function handleContractSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice) return;

    const contractInput = document.getElementById('contractInput');
    const newContract = contractInput.value.trim();

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
            showNotification(data.message, 'success');
            closeModal('editContractModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Error actualizando contrato:', error);
        showNotification('Error actualizando contrato', 'error');
    }
}

// Modales de redes WiFi
function openNetworkModal(serialNumber, band) {
    // Buscar dispositivo y red
    const device = [...devices.configured, ...devices.unconfigured]
        .find(d => d.serial_number === serialNumber);
    
    if (!device) return;

    const network = device.wifi_networks.find(n => n.band === band);
    if (!network) return;

    currentDevice = device;
    currentNetwork = network;

    // Llenar modal con datos
    const modal = document.getElementById('networkDetailsModal');
    const deviceSerial = document.getElementById('detailDeviceSerial');
    const deviceProduct = document.getElementById('detailDeviceProduct');
    const networkBand = document.getElementById('detailNetworkBand');
    const networkSSID = document.getElementById('detailNetworkSSID');
    const networkPassword = document.getElementById('detailNetworkPassword');

    if (deviceSerial) deviceSerial.textContent = device.serial_number;
    if (deviceProduct) deviceProduct.textContent = device.product_class;
    if (networkBand) networkBand.textContent = network.band;
    if (networkSSID) networkSSID.textContent = network.ssid;
    if (networkPassword) {
        networkPassword.textContent = network.password || 'Sin contraseña configurada';
    }

    openModal('networkDetailsModal');
}

function openEditSSIDModal() {
    if (!currentDevice || !currentNetwork) return;

    const ssidInput = document.getElementById('ssidInput');
    if (ssidInput) ssidInput.value = currentNetwork.ssid;

    closeModal('networkDetailsModal');
    openModal('editSSIDModal');
}

function openEditPasswordModal() {
    if (!currentDevice || !currentNetwork) return;

    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) passwordInput.value = currentNetwork.password || '';

    closeModal('networkDetailsModal');
    openModal('editPasswordModal');
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
            showNotification(data.message, 'success');
            closeModal('editSSIDModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Error actualizando SSID:', error);
        showNotification('Error actualizando SSID', 'error');
    }
}

async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    if (!currentDevice || !currentNetwork) return;

    const passwordInput = document.getElementById('passwordInput');
    const newPassword = passwordInput.value.trim();

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
            showNotification(data.message, 'success');
            closeModal('editPasswordModal');
            await loadDevices(); // Recargar para mostrar cambios
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Error actualizando contraseña:', error);
        showNotification('Error actualizando contraseña', 'error');
    }
}

function togglePasswordVisibility(inputId, toggleButton) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    
    const icon = toggleButton.querySelector('i');
    if (icon) {
        icon.className = `fas ${isPassword ? 'fa-eye-slash' : 'fa-eye'}`;
    }
}

// Sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        if (sidebarOpen) {
            closeSidebar();
        } else {
            openSidebar();
        }
    }
}

function openSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.add('open');
        overlay.classList.add('active');
        sidebarOpen = true;
        document.body.style.overflow = 'hidden';
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
        sidebarOpen = false;
        document.body.style.overflow = '';
    }
}

// Historial
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
                historyList.innerHTML = '<p class="text-center text-gray-500">No se encontraron cambios en el historial</p>';
            }
        }
    } catch (error) {
        console.error('Error cargando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<p class="text-center text-red-500">Error cargando el historial</p>';
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
                historyList.innerHTML = '<p class="text-center text-gray-500">No se encontraron cambios con esos filtros</p>';
            }
        }
    } catch (error) {
        console.error('Error buscando historial:', error);
        if (loadingHistory) loadingHistory.style.display = 'none';
        if (historyList) {
            historyList.innerHTML = '<p class="text-center text-red-500">Error realizando búsqueda</p>';
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
    
    // Crear texto del cambio según el tipo
    let changeText = '';
    if (item.change_type === 'PASSWORD') {
        // Mostrar contraseñas reales en el historial
        changeText = `<div class="history-change">
            <span class="old-value">${item.old_value}</span> → <span class="new-value">${item.new_value}</span>
        </div>`;
    } else if (item.change_type === 'SSID') {
        changeText = `<div class="history-change">
            <span class="old-value">${item.old_value}</span> → <span class="new-value">${item.new_value}</span>
        </div>`;
    } else if (item.change_type === 'CONTRACT') {
        changeText = `<div class="history-change">
            <span class="old-value">${item.old_value}</span> → <span class="new-value">${item.new_value}</span>
        </div>`;
    }

    return `
        <div class="history-item">
            <div class="history-icon">
                <i class="fas ${icon}"></i>
            </div>
            <div class="history-content">
                <div class="history-header">
                    <strong>Cambio de ${item.change_type}</strong>
                    <span class="history-date">${date}</span>
                </div>
                <div class="history-details">
                    <span class="history-device">📱 ${item.serial_number}</span>
                    <span class="history-contract">📄 ${item.contract_number || 'Sin contrato'}</span>
                    ${item.band ? `<span class="history-band">📶 ${item.band}</span>` : ''}
                    ${item.ssid ? `<span class="history-ssid">🏷️ ${item.ssid}</span>` : ''}
                </div>
                ${changeText}
                <div class="history-user">
                    <i class="fas fa-user"></i>
                    <span>${item.username}</span>
                </div>
            </div>
        </div>
    `;
}

// Gestión de usuarios
async function openUsersModal() {
    // Verificar permisos
    if (!currentUser || currentUser.role_level < 2) {
        showNotification('No tienes permisos para gestionar usuarios', 'error');
        return;
    }

    openModal('usersModal');
    await loadUsers();
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
                usersList.innerHTML = '<p class="text-center text-red-500">Error cargando usuarios</p>';
            }
        }
    } catch (error) {
        console.error('Error cargando usuarios:', error);
        if (loadingUsers) loadingUsers.style.display = 'none';
        if (usersList) {
            usersList.innerHTML = '<p class="text-center text-red-500">Error cargando usuarios</p>';
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
            <div class="create-user-section">
                <button class="btn btn-primary" onclick="showCreateUserForm()">
                    <i class="fas fa-user-plus"></i> Crear Usuario
                </button>
            </div>
        ` : ''}
        
        <div class="users-list">
            ${users.map(user => createUserItemHtml(user, roles, canDeleteUsers)).join('')}
        </div>
    `;
}

function createUserItemHtml(user, roles, canDelete) {
    const roleInfo = roles[user.role] || { name: user.role, description: '' };
    const lastLogin = user.last_login ? new Date(user.last_login).toLocaleString('es-ES') : 'Nunca';
    const createdAt = new Date(user.created_at).toLocaleString('es-ES');
    
    const canDeleteThisUser = canDelete && user.username !== 'admin' && user.id !== currentUser.id;

    return `
        <div class="user-item">
            <div class="user-info">
                <div class="user-header">
                    <strong>${user.username}</strong>
                    <span class="user-role ${user.role}">${roleInfo.name}</span>
                </div>
                <div class="user-details">
                    <small>Creado: ${createdAt}</small>
                    <small>Último acceso: ${lastLogin}</small>
                </div>
                <div class="user-description">
                    <small>${roleInfo.description}</small>
                </div>
            </div>
            <div class="user-actions">
                ${canDeleteThisUser ? `
                    <button class="btn btn-outline btn-sm" onclick="deleteUser(${user.id}, '${user.username}')">
                        <i class="fas fa-trash"></i> Eliminar
                    </button>
                ` : ''}
            </div>
        </div>
    `;
}

function showCreateUserForm() {
    const createUserDiv = document.getElementById('createUserDiv');
    const usersList = document.getElementById('usersList');
    
    if (createUserDiv) createUserDiv.style.display = 'block';
    if (usersList) {
        // Scrollear al formulario
        createUserDiv.scrollIntoView({ behavior: 'smooth' });
    }

    // Llenar select de roles según permisos
    const roleSelect = document.getElementById('newUserRole');
    if (roleSelect && currentUser) {
        roleSelect.innerHTML = '';
        
        if (currentUser.role === 'noc') {
            // NOC puede crear todos los roles
            roleSelect.innerHTML = `
                <option value="callcenter">Call Center</option>
                <option value="informatica">Informática</option>
                <option value="noc">NOC</option>
            `;
        } else if (currentUser.role === 'informatica') {
            // Informática solo puede crear Call Center
            roleSelect.innerHTML = `
                <option value="callcenter">Call Center</option>
            `;
        }
    }
}

function hideCreateUserForm() {
    const createUserDiv = document.getElementById('createUserDiv');
    const form = document.getElementById('createUserForm');
    
    if (createUserDiv) createUserDiv.style.display = 'none';
    if (form) form.reset();
}

async function handleCreateUserSubmit(e) {
    e.preventDefault();

    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newUserPassword').value.trim();
    const role = document.getElementById('newUserRole').value;

    if (!username || !password) {
        showNotification('Usuario y contraseña son requeridos', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(data.message, 'success');
            hideCreateUserForm();
            await loadUsers(); // Recargar lista
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Error creando usuario:', error);
        showNotification('Error creando usuario', 'error');
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`¿Estás seguro de que quieres eliminar el usuario "${username}"?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/users/${userId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showNotification(data.message, 'success');
            await loadUsers(); // Recargar lista
        } else {
            showNotification(data.message, 'error');
        }
    } catch (error) {
        console.error('Error eliminando usuario:', error);
        showNotification('Error eliminando usuario', 'error');
    }
}

// Funciones de modal
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        
        // Focus en el primer elemento focusable
        const focusable = modal.querySelector('input, button, select, textarea, [tabindex]');
        if (focusable) {
            setTimeout(() => focusable.focus(), 100);
        }
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

// Confirmaciones
function confirmAction(action, message) {
    pendingAction = action;
    const confirmMessage = document.getElementById('confirmMessage');
    if (confirmMessage) confirmMessage.textContent = message;
    openModal('confirmModal');
}

function executeConfirmedAction() {
    if (pendingAction) {
        pendingAction();
        pendingAction = null;
    }
    closeModal('confirmModal');
}

// Notificaciones
function showNotification(message, type = 'info', duration = 4000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" aria-label="Cerrar">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;

    document.body.appendChild(notification);

    // Mostrar notificación
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);

    // Auto-remover
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, duration);
}

function getNotificationIcon(type) {
    switch (type) {
        case 'success': return 'fa-check-circle';
        case 'error': return 'fa-exclamation-circle';
        case 'warning': return 'fa-exclamation-triangle';
        case 'info': 
        default: return 'fa-info-circle';
    }
}