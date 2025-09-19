// GenieACS WiFi Manager - JavaScript CON PAGINACIÓN COMPLETA

// Variables globales
let devices = { all: [], configured: [], unconfigured: [] };
let currentUser = null;
let currentPollingInterval = null;
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
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    console.log("🚀 Iniciando aplicación...");
    const mainLoader = document.getElementById('mainLoader');
    if (mainLoader) mainLoader.classList.remove('hidden');

    const isAuthenticated = await checkAuthentication();
    if (!isAuthenticated) {
        window.location.href = '/login';
        return;
    }
    
    // Inicia el sondeo para obtener los dispositivos
    startPollingForDevices();
    setupEventListeners();
}

/**
 * Inicia un intervalo que llama a loadDevicesPage hasta que tiene éxito.
 */
function startPollingForDevices() {
    console.log("[Polling] Iniciando sondeo de dispositivos...");
    
    // Detiene cualquier sondeo anterior
    if (currentPollingInterval) {
        clearInterval(currentPollingInterval);
        currentPollingInterval = null;
    }

    let retryCount = 0;
    const maxRetries = 10; // Máximo 10 intentos (30 segundos)
    
    const attemptLoad = async () => {
        const result = await loadDevicesPage(1);
        
        // Si la carga fue exitosa y tenemos dispositivos, detenemos el sondeo
        if (result && result.devices && result.devices.length > 0) {
            console.log(`[Polling] ✅ ¡Éxito! ${result.devices.length} dispositivos cargados. Deteniendo sondeo.`);
            clearInterval(currentPollingInterval);
            currentPollingInterval = null;
            
            // Ocultar el indicador de carga principal
            const loadingIndicator = document.getElementById('loadingIndicator');
            if (loadingIndicator) loadingIndicator.classList.add('hidden');
            
            return;
        }
        
        // Incrementar contador de reintentos
        retryCount++;
        
        // Si superamos el máximo de reintentos, detener el sondeo y mostrar error
        if (retryCount >= maxRetries) {
            console.error("[Polling] Máximo de reintentos alcanzado. Deteniendo sondeo.");
            clearInterval(currentPollingInterval);
            currentPollingInterval = null;
            
            // Ocultar el indicador de carga principal
            const loadingIndicator = document.getElementById('loadingIndicator');
            if (loadingIndicator) loadingIndicator.classList.add('hidden');
            
            // Mostrar estado de error
            showErrorState("No se pudieron cargar los dispositivos después de varios intentos.");
            
            return;
        }
        
        console.log(`[Polling] ... Servidor aún sincronizando. Reintento ${retryCount}/${maxRetries}...`);
    };

    // Ejecutar el primer intento inmediatamente
    attemptLoad();
    // Configurar intentos subsecuentes cada 3 segundos
    currentPollingInterval = setInterval(attemptLoad, 3000);
}

async function loadDevicesPage(page, search = '', filter = 'all') {
    if (isLoading) return;
    
    console.log(`📄 Cargando página ${page} con filtro '${filter}' y búsqueda '${search}'`);
    
    isLoading = true;
    showLoadingState();
    
    try {
        const params = new URLSearchParams({
            page: page.toString(),
            per_page: devicesPerPage.toString(),
            filter: filter
        });
        
        if (search) {
            params.append('search', search);
        }
        
        const response = await fetch(`${API_BASE}/devices?${params}`);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        console.log("Respuesta del servidor:", data); // Añadir este log para depuración
        
        if (!data.success) {
            throw new Error(data.message || 'Error desconocido del servidor');
        }
        
        // Actualizar variables globales
        currentPage = data.pagination.page;
        totalPages = data.pagination.pages;
        
        // Ocultar estados de carga y error
        hideLoadingState();
        hideErrorState();
        
        // Renderizar dispositivos y paginación
        renderDevices(data.devices);
        renderPagination(data.pagination);
        updateFilterCounts(data.counts);
        
        console.log(`✅ Página ${page} cargada: ${data.devices.length} dispositivos`);
        
        // Devolver la estructura completa de datos para que el sondeo pueda evaluar correctamente
        return {
            devices: data.devices,
            pagination: data.pagination,
            counts: data.counts
        };
        
    } catch (error) {
        console.error('❌ Error cargando dispositivos:', error);
        showErrorState(error.message);
        isLoading = false;
    }
    
    isLoading = false;
}

// En script.js, reemplaza tu función createDeviceCard actual con esta versión final.

function createDeviceCard(device) {
    const card = document.createElement('div');
    const statusClass = device.configured ? 'configured' : 'unconfigured';
    const statusText = device.configured ? 'Configurado' : 'No Configurado';
    card.className = `device-card ${statusClass}`;

    // Encuentra la información de las redes 2.4GHz y 5GHz
    // El 'find' asegura que la app no se rompa si un dispositivo no tiene una de las bandas.
    const network2_4 = Array.isArray(device.wifi_networks) ? device.wifi_networks.find(net => net.band.includes('2.4')) : null;
    const network5 = Array.isArray(device.wifi_networks) ? device.wifi_networks.find(net => net.band.includes('5')) : null;

    // Determina el SSID principal para el título (usamos el de 2.4GHz como prioridad)
    const mainSSID = (network2_4 && network2_4.ssid_configured) ? network2_4.ssid_configured : (device.serial_number || 'Dispositivo');

    // Construye el HTML de la tarjeta con la nueva estructura profesional
    card.innerHTML = `
        <div class="card-header">
            <div class="device-title">
                <h3 class="main-ssid" title="${mainSSID}">${mainSSID}</h3>
                <button class="btn btn-icon btn-details" data-serial="${device.serial_number}" title="Ver detalles técnicos">
                    <i class="fas fa-info-circle"></i>
                </button>
            </div>
            <div class="device-status ${statusClass}">${statusText}</div>
        </div>
        
        <div class="card-customer-details">
            <div class="customer-item">
                <i class="fas fa-file-contract"></i>
                <span>${device.contract_number || 'Sin contrato'}</span>
            </div>
            <div class="customer-item">
                <i class="fas fa-user"></i>
                <span>${device.customer_name || 'Sin cliente'}</span>
            </div>
        </div>

        <div class="device-wifi-details">
            <div class="wifi-network-item">
                <span class="wifi-band-label band-2g">2.4 GHz</span>
                <div class="wifi-ssid">${(network2_4 && network2_4.ssid_configured) ? network2_4.ssid_configured : 'N/A'}</div>
                <div class="password-field">
                    <input type="password" value="${(network2_4 && network2_4.password) ? network2_4.password : ''}" readonly>
                    <button class="password-toggle" title="Mostrar/Ocultar contraseña">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            <div class="wifi-network-item">
                <span class="wifi-band-label band-5g">5 GHz</span>
                <div class="wifi-ssid">${(network5 && network5.ssid_configured) ? network5.ssid_configured : 'N/A'}</div>
                <div class="password-field">
                    <input type="password" value="${(network5 && network5.password) ? network5.password : ''}" readonly>
                    <button class="password-toggle" title="Mostrar/Ocultar contraseña">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
        </div>
    `;

    // --- Configuración de Eventos para los Botones ---

    // Botón para abrir el modal de detalles técnicos
    card.querySelector('.btn-details').addEventListener('click', (e) => {
        e.stopPropagation(); // Evita que otros eventos de la tarjeta se disparen
        if (typeof openTechnicalModal === 'function') {
            openTechnicalModal(device.serial_number);
        } else {
            console.error('La función openTechnicalModal no está definida.');
        }
    });

    // Botones para mostrar/ocultar contraseña
    card.querySelectorAll('.password-toggle').forEach(button => {
        button.addEventListener('click', (e) => {
            e.stopPropagation();
            const input = button.previousElementSibling;
            const icon = button.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });
    });

    return card;
}


async function debugApiResponse() {
    try {
        const response = await fetch(`${API_BASE}/devices?page=1&per_page=5`);
        const data = await response.json();
        console.log("=== DEPURACIÓN ===");
        console.log("Respuesta completa:", data);
        console.log("Dispositivos:", data.devices);
        console.log("Primer dispositivo:", data.devices[0]);
        console.log("===============");
    } catch (error) {
        console.error("Error en depuración:", error);
    }
}

// Llamar a esta función en la consola del navegador para depurar
// debugApiResponse();


function renderDevices(devices) {
    console.log("Renderizando dispositivos:", devices); // Añadir este log
    
    const grid = document.getElementById('devicesGrid');
    if (!grid) {
        console.error("No se encontró el elemento devicesGrid");
        return;
    }
    
    grid.innerHTML = '';

    if (!devices || devices.length === 0) {
        console.log("No hay dispositivos para mostrar");
        // No mostramos "No se encontraron" si el sondeo aún podría estar activo
        if (!currentPollingInterval) {
            showEmptyState();
        }
        return;
    }

    console.log(`Creando ${devices.length} tarjetas de dispositivos`);
    
    devices.forEach((device, index) => {
        console.log(`Creando tarjeta para dispositivo ${index}:`, device);
        const card = createDeviceCard(device);
        grid.appendChild(card);
        setTimeout(() => {
            card.classList.add('visible');
        }, 10 * index);
    });
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

// Reemplaza tu función handleTechnicalFormSubmit actual con esta versión COMPLETA Y FINAL
async function handleTechnicalFormSubmit(e) {
    e.preventDefault();
    const form = e.target;
    const serialNumber = form.dataset.serialNumber;
    const saveBtn = document.getElementById('saveTechnicalInfoBtn');

    // Parte 1: Recopilar los datos del formulario (esto ya lo tenías)
    const newValues = {
        ssid24: document.getElementById('ssid24Input').value,
        password24: document.getElementById('newPassword24').value,
        ssid5: document.getElementById('ssid5Input').value,
        password5: document.getElementById('newPassword5').value,
    };

    const originalValues = {
        ssid24: form.dataset.originalSsid24,
        ssid5: form.dataset.originalSsid5,
    };

    const tasks = [];
    if (newValues.ssid24 !== originalValues.ssid24) {
        tasks.push({ endpoint: '/api/device/update-ssid', payload: { serial_number: serialNumber, ssid: newValues.ssid24, band: '2.4GHz' }, name: 'SSID 2.4GHz' });
    }
    if (newValues.password24) {
        tasks.push({ endpoint: '/api/device/update-password', payload: { serial_number: serialNumber, password: newValues.password24, band: '2.4GHz' }, name: 'Contraseña 2.4GHz' });
    }
    if (newValues.ssid5 !== originalValues.ssid5) {
        tasks.push({ endpoint: '/api/device/update-ssid', payload: { serial_number: serialNumber, ssid: newValues.ssid5, band: '5GHz' }, name: 'SSID 5GHz' });
    }
    if (newValues.password5) {
        tasks.push({ endpoint: '/api/device/update-password', payload: { serial_number: serialNumber, password: newValues.password5, band: '5GHz' }, name: 'Contraseña 5GHz' });
    }

    if (tasks.length === 0) {
        showNotification('No hay cambios para guardar.', 'info');
        return;
    }

    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Actualizando...';

    // Parte 2: Aquí empieza el bloque try/catch/finally que ejecuta las tareas
    try {
        // Ejecuta todas las tareas de actualización en paralelo
        const promises = tasks.map(task =>
            fetch(task.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(task.payload)
            }).then(async response => {
                const data = await response.json();
                if (!response.ok || !data.success) {
                    // Si algo falla, arroja un error detallado que se capturará en el 'catch'
                    throw new Error(`Error en ${task.name}: ${data.message || 'Fallo desconocido del servidor'}`);
                }
                return { name: task.name, ...data };
            })
        );

        // Espera a que todas las promesas (actualizaciones) terminen
        const results = await Promise.all(promises);

        const updatedNames = results.map(r => r.name).join(', ');
        showNotification(`Tareas de actualización enviadas: ${updatedNames}`, 'success');
        
        // --- PASO CLAVE: Forzar refresco del caché del servidor ---
        // Llama a la nueva ruta que borra el caché en el backend
        await fetch('/api/devices/refresh', { method: 'POST' });
        console.log('Cache del servidor limpiado, recargando dispositivos...');

        // Si todo fue exitoso, cierra el modal y recarga la lista de dispositivos
        closeTechnicalModal();
        await loadDevicesPage(currentPage);

    } catch (error) {
        // Si CUALQUIERA de las actualizaciones falla, se ejecuta este bloque
        console.error('Error durante la actualización:', error);
        showNotification(error.message, 'error');
    } finally {
        // Este bloque se ejecuta SIEMPRE, ya sea que la actualización haya sido exitosa o fallida
        // Restaura el botón a su estado original
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="fas fa-save"></i> Actualizar Cambios';
    }
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
    if (!file) {
        logCSVImport('❌ No se seleccionó ningún archivo.', 'error');
        return;
    }
    
    if (!file.name.toLowerCase().endsWith('.csv')) {
        logCSVImport('❌ Archivo inválido. Debe ser un archivo .csv', 'error');
        // También muestra una notificación más visible
        if (typeof showNotification === 'function') {
            showNotification('Formato de archivo no válido. Solo se permiten archivos .csv', 'error');
        }
        return;
    }
    
    // Guardar el archivo en la variable global que ya tienes
    selectedFile = file; 
    
    // Actualizar la UI para mostrar el archivo seleccionado
    const fileInfoContainer = document.getElementById('selectedFileInfo');
    const fileDetailsSpan = document.getElementById('fileDetails'); // Asumiendo que este es el span dentro de fileInfoContainer
    const dropArea = document.getElementById('dropArea');

    if (fileInfoContainer && fileDetailsSpan && dropArea) {
        fileDetailsSpan.textContent = `Archivo: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        fileInfoContainer.classList.remove('hidden');
        dropArea.classList.add('hidden');
    }
    
    // Resetear la barra de progreso y el log antes de una nueva subida
    if (typeof resetProgressBar === 'function') {
        resetProgressBar();
    }
    logCSVImport('', 'clear'); // Limpiar el log del modal
    
    // ¡Llamada clave! Iniciar el proceso de subida.
    uploadSelectedCSV();
}

async function uploadSelectedCSV() {
    if (!selectedFile) {
        logCSVImport('❌ Error interno: No hay archivo seleccionado para subir.', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile); // La clave 'file' es la que espera tu backend

    const progress = document.getElementById('csvUploadProgress');
    
    // Prepara la UI para la subida
    if (progress) progress.classList.remove('hidden');
    if (progress) progress.value = 0;
    
    logCSVImport(`Subiendo y procesando ${selectedFile.name}...`, 'info');

    try {
        // Simular progreso de subida
        if (progress) progress.value = 50;
        
        // Llamada a la API correcta en tu app.py
        const response = await fetch('/api/csv/upload', {
            method: 'POST',
            body: formData,
        });

        if (progress) progress.value = 100;
        const result = await response.json();

        if (response.ok) {
            logCSVImport(`✅ ${result.message}`, 'success');
            if (result.stats) {
                logCSVImport(`Resultados: ${result.stats.updated || 0} actualizados, ${result.stats.failed || 0} fallidos.`, 'info');
            }
            showNotification('Archivo CSV procesado con éxito.', 'success');
            loadDevicesPage(1); // ¡Importante! Recargar los dispositivos para ver los cambios
        } else {
            logCSVImport(`❌ ${result.message}`, 'error');
            showNotification(result.message || 'Error al procesar el archivo.', 'error');
        }
    } catch (error) {
        logToModal(`❌ Error de red: No se pudo conectar con el servidor.`, 'error');
        showNotification('Error de conexión con el servidor.', 'error');
    } finally {
        // Cerrar el modal automáticamente después de 5 segundos para que el usuario vea el resultado
        setTimeout(() => {
            if (typeof closeCSVImportModal === 'function') {
                closeCSVImportModal();
            }
        }, 7000); // Un poco más de tiempo para leer el log
    }
}

/**
 * Función para escribir en el log del modal.
 * @param {string} message - El mensaje a mostrar.
 * @param {string} type - 'info', 'success', 'error', o 'clear' para limpiar.
 */
function logCSVImport(message, type = 'info') {
    const logContainer = document.getElementById('csvUploadLog');
    if (!logContainer) return;

    if (type === 'clear') {
        logContainer.innerHTML = '';
        logContainer.classList.add('hidden');
        return;
    }

    logContainer.classList.remove('hidden');
    const p = document.createElement('p');
    p.className = `log-${type}`;
    p.textContent = message;
    logContainer.appendChild(p);
    logContainer.scrollTop = logContainer.scrollHeight; // Auto-scroll al último mensaje
}

function resetProgressBar() {
    const progress = document.getElementById('csvUploadProgress');
    if (progress) {
        progress.classList.add('hidden');
        progress.value = 0;
    }
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

function renderPagination(pagination) {
    const paginationContainer = document.getElementById('paginationContainer');
    if (!paginationContainer) return;
    
    // Si solo hay una página, ocultar la paginación
    if (pagination.pages <= 1) {
        paginationContainer.classList.add('hidden');
        return;
    }
    
    paginationContainer.classList.remove('hidden');
    
    let paginationHTML = '';
    
    // Crear contenedor de paginación
    paginationHTML = '<div class="pagination">';
    
    // Botón anterior
    if (pagination.has_prev) {
        paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(${pagination.prev_page})">
            <i class="fas fa-chevron-left"></i>
        </button>`;
    } else {
        paginationHTML += `<button class="pagination-btn disabled">
            <i class="fas fa-chevron-left"></i>
        </button>`;
    }
    
    // Determinar el rango de páginas a mostrar
    let startPage = Math.max(1, pagination.page - 2);
    let endPage = Math.min(pagination.pages, pagination.page + 2);
    
    // Mostrar primera página y puntos suspensivos si es necesario
    if (startPage > 1) {
        paginationHTML += `<button class="pagination-btn" onclick="loadDevicesPage(1)">1</button>`;
        if (startPage > 2) {
            paginationHTML += `<span class="pagination-dots">...</span>`;
        }
    }
    
    // Mostrar números de página
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === pagination.page ? 'active' : '';
        paginationHTML += `<button class="pagination-btn ${activeClass}" onclick="loadDevicesPage(${i})">${i}</button>`;
    }
    
    // Mostrar última página y puntos suspensivos si es necesario
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
    } else {
        paginationHTML += `<button class="pagination-btn disabled">
            <i class="fas fa-chevron-right"></i>
        </button>`;
    }
    
    paginationHTML += '</div>';
    
    // Información de paginación
    const startItem = ((pagination.page - 1) * pagination.per_page) + 1;
    const endItem = Math.min(pagination.page * pagination.per_page, pagination.total);
    
    paginationHTML += `
        <div class="pagination-info">
            Mostrando ${startItem}-${endItem} de ${pagination.total} dispositivos
        </div>
    `;
    
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
    const loadingState = document.getElementById('loadingIndicator');
    const devicesGrid = document.getElementById('devicesGrid');
    const emptyState = document.getElementById('emptyState');
    const errorState = document.getElementById('errorState');
    
    if (loadingState) loadingState.classList.remove('hidden');
    if (devicesGrid) devicesGrid.innerHTML = '';
    if (emptyState) emptyState.classList.add('hidden');
    if (errorState) errorState.classList.add('hidden');
}

function hideLoadingState() {
    const loadingState = document.getElementById('loadingIndicator');
    if (loadingState) {
        loadingState.classList.add('hidden');
    }
}

function showErrorState(message = 'Error cargando dispositivos') {
    const errorState = document.getElementById('errorState');
    const loadingState = document.getElementById('loadingIndicator');
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

function hideErrorState() {
    const errorState = document.getElementById('errorState');
    if (errorState) {
        errorState.classList.add('hidden');
    }
}

function showEmptyState() {
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingIndicator');
    const errorState = document.getElementById('errorState');
    
    if (emptyState) emptyState.classList.remove('hidden');
    if (loadingState) loadingState.classList.add('hidden');
    if (errorState) errorState.classList.add('hidden');
}

function hideEmptyState() {
    const emptyState = document.getElementById('emptyState');
    if (emptyState) {
        emptyState.classList.add('hidden');
    }
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
