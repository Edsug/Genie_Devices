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
            <i class="fas fa-user"></i>
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
        if (resp.log) logCSVImport(`<pre style="overflow-x:auto">${resp.log}</pre>`);
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
  logDiv.innerHTML += message + '<br>';
  logDiv.scrollTop = logDiv.scrollHeight;
}

function clearCSVImportLog() {
  const logDiv = document.getElementById('csvUploadLog');
  if (logDiv) logDiv.innerHTML = '';
}

function updateProgressBar(value) {
  const progressBar = document.getElementById('csvUploadProgress');
  if (progressBar) {
    progressBar.value = value;
    progressBar.style.display = 'block';
  }
}

function resetProgressBar() {
  const progressBar = document.getElementById('csvUploadProgress');
  if (progressBar) {
    progressBar.value = 0;
    progressBar.style.display = 'block';
  }
}

function hideProgressBar() {
  const progressBar = document.getElementById('csvUploadProgress');
  if (progressBar) {
    progressBar.style.display = 'none';
  }
}

async function loadDevicesPage(page) {
    if (isLoading) {
        console.log('⏳ Ya hay una carga en progreso...');
        return;
    }
    
    isLoading = true;
    console.log(`📡 Cargando página ${page}...`);
    
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const devicesGrid = document.getElementById('devicesGrid');
    const paginationControls = document.getElementById('paginationControls');
    
    // Mostrar loading
    if (loadingState) loadingState.classList.remove('hidden');
    if (errorState) errorState.classList.add('hidden');
    if (emptyState) emptyState.classList.add('hidden');
    if (devicesGrid) devicesGrid.classList.add('hidden');
    if (paginationControls) paginationControls.classList.add('hidden');
    
    try {
        // Construir URL con parámetros
        const params = new URLSearchParams({
            page: page,
            per_page: devicesPerPage,
            filter: currentFilter
        });
        
        if (currentSearch) {
            params.append('search', currentSearch);
        }
        
        const response = await fetch(`/api/devices?${params}`);
        
        if (!response.ok) {
            throw new Error(`Error HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            console.log(`✅ Página ${page} cargada:`, data.pagination);
            
            // Actualizar variables globales
            currentPage = data.pagination.page;
            totalPages = data.pagination.pages;
            
            // Actualizar contadores
            updateDeviceCounts(data.counts);
            
            // Mostrar dispositivos
            displayDevices(data.devices);
            
            // Mostrar controles de paginación
            displayPagination(data.pagination);
            
            // Mostrar información de cache
            if (data.cache_age !== undefined) {
                const cacheInfo = data.cache_age === 0 ? 'Datos frescos' : `Cache: ${Math.floor(data.cache_age/60)}min ${data.cache_age%60}s`;
                console.log(`ℹ️ ${cacheInfo}`);
                updateCacheInfo(cacheInfo);
            }
            
        } else {
            throw new Error(data.message || 'Error desconocido');
        }
        
    } catch (error) {
        console.error('❌ Error cargando dispositivos:', error);
        showErrorState();
    } finally {
        isLoading = false;
        if (loadingState) loadingState.classList.add('hidden');
    }
}

function updateDeviceCounts(counts) {
    const countAll = document.getElementById('countAll');
    const countConfigured = document.getElementById('countConfigured');
    const countUnconfigured = document.getElementById('countUnconfigured');
    
    if (countAll) countAll.textContent = counts.total;
    if (countConfigured) countConfigured.textContent = counts.configured;
    if (countUnconfigured) countUnconfigured.textContent = counts.unconfigured;
    
    // Mostrar total filtrado si hay búsqueda
    if (currentSearch && counts.filtered !== counts.total) {
        const filterInfo = document.getElementById('filterInfo');
        if (filterInfo) {
            filterInfo.textContent = `Mostrando ${counts.filtered} de ${counts.total} dispositivos`;
            filterInfo.classList.remove('hidden');
        }
    } else {
        const filterInfo = document.getElementById('filterInfo');
        if (filterInfo) {
            filterInfo.classList.add('hidden');
        }
    }
}

function updateCacheInfo(cacheInfo) {
    const cacheInfoElement = document.getElementById('cacheInfo');
    if (cacheInfoElement) {
        cacheInfoElement.textContent = cacheInfo;
    }
}

function setActiveFilter(filter) {
    currentFilter = filter;
    currentPage = 1; // Reset a primera página al cambiar filtro
    
    // Actualizar UI de tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
        if (tab.dataset.filter === filter) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });
    
    // Cargar nueva página
    loadDevicesPage(1);
}

function displayDevices(deviceList) {
    const devicesGrid = document.getElementById('devicesGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (!devicesGrid) return;
    
    if (deviceList.length === 0) {
        devicesGrid.classList.add('hidden');
        if (emptyState) {
            emptyState.classList.remove('hidden');
            const emptyText = emptyState.querySelector('.empty-text p');
            if (emptyText) {
                if (currentSearch) {
                    emptyText.textContent = `No se encontraron dispositivos que coincidan con "${currentSearch}"`;
                } else {
                    emptyText.textContent = 'No hay dispositivos disponibles';
                }
            }
        }
        return;
    }
    
    if (emptyState) emptyState.classList.add('hidden');
    
    devicesGrid.innerHTML = deviceList.map(device => createDeviceCard(device)).join('');
    devicesGrid.classList.remove('hidden');
    
    // Agregar animación de entrada
    setTimeout(() => {
        devicesGrid.querySelectorAll('.device-card').forEach((card, index) => {
            setTimeout(() => {
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }, 50);
}

function createDeviceCard(device) {
    const statusClass = device.configured ? 'configured' : 'unconfigured';
    const statusText = device.configured ? 'Configurado' : 'No configurado';
    const statusIcon = device.configured ? 'check-circle' : 'exclamation-triangle';
    const primaryNetwork = device.wifi_networks.find(net => net.is_primary) || device.wifi_networks[0];
    const mainSSID = primaryNetwork ? (primaryNetwork.ssid || 'Sin SSID') : 'Sin SSID';

    // Construir HTML para las redes WiFi asociadas
    let networksHtml = '';
    if (device.wifi_networks && device.wifi_networks.length > 0) {
        networksHtml = device.wifi_networks.map(network => `
            <div class="network-item">
                <div class="network-header">
                    <span class="network-band band-${network.band === '5GHz' ? '5g' : '2g'}">${network.band}</span>
                    <span class="network-ssid">${network.ssid}</span>
                    <button class="password-toggle-btn ${!network.password ? 'no-password' : ''}" 
                            onclick="togglePassword('${device.serial_number}', '${network.band}')"
                            ${!network.password ? 'disabled' : ''}>
                        <i class="fas fa-${network.password ? 'eye' : 'eye-slash'}"></i>
                    </button>
                </div>
                <div class="network-password hidden" id="password-${device.serial_number}-${network.band}">
                    ${network.password || 'Sin contraseña'}
                </div>
            </div>
        `).join('');
    }

    return `
        <div class="device-card ${statusClass}" data-serial="${device.serial_number}" style="opacity: 0; transform: translateY(20px); transition: all 0.5s ease;">
            <div class="device-header">
                <div class="device-title-section">
                    <button class="device-title" onclick="showDeviceDetails('${device.serial_number}')">
                        ${device.serial_number}
                    </button>

                    ${device.contract_number ? `
                    <div class="device-contract has-contract" onclick="editContract('${device.serial_number}')">
                        <i class="fas fa-file-contract"></i>
                        <span>Contrato: ${device.contract_number}</span>
                        <i class="fas fa-edit edit-icon"></i>
                    </div>
                    ` : `
                    <div class="device-contract no-contract" onclick="editContract('${device.serial_number}')">
                        <i class="fas fa-plus-circle"></i>
                        <span>Agregar contrato</span>
                        <i class="fas fa-edit edit-icon"></i>
                    </div>
                    `}

                    ${device.customer_name ? `
                    <div class="device-customer">
                        <i class="fas fa-user"></i>
                        <span>${device.customer_name}</span>
                    </div>
                    ` : ''}
                </div>

                <div class="device-status ${statusClass}">
                    <i class="fas fa-${statusIcon}"></i>
                    <span>${statusText}</span>
                </div>
            </div>

            ${networksHtml ? `
            <div class="device-networks">
                ${networksHtml}
            </div>
            ` : ''}

            <div class="device-info">
                <div class="device-detail">
                    <i class="fas fa-network-wired"></i>
                    <span>${device.ip}</span>
                </div>
                <div class="device-detail">
                    <i class="fas fa-microchip"></i>
                    <span>${device.product_class}</span>
                </div>
                ${device.last_inform ? `
                <div class="device-detail">
                    <i class="fas fa-clock"></i>
                    <span>${device.last_inform}</span>
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

function displayPagination(pagination) {
    const paginationControls = document.getElementById('paginationControls');
    
    if (!paginationControls || pagination.pages <= 1) {
        if (paginationControls) paginationControls.classList.add('hidden');
        return;
    }
    
    let paginationHtml = `
        <div class="pagination-info">
            Página ${pagination.page} de ${pagination.pages} (${pagination.total} dispositivos)
        </div>
        <div class="pagination-buttons">
    `;
    
    // Botón anterior
    if (pagination.has_prev) {
        paginationHtml += `
            <button class="btn btn-secondary" onclick="goToPage(${pagination.prev_page})">
                <i class="fas fa-chevron-left"></i> Anterior
            </button>
        `;
    } else {
        paginationHtml += `
            <button class="btn btn-secondary" disabled>
                <i class="fas fa-chevron-left"></i> Anterior
            </button>
        `;
    }
    
    // Páginas numéricas
    const startPage = Math.max(1, pagination.page - 2);
    const endPage = Math.min(pagination.pages, pagination.page + 2);
    
    if (startPage > 1) {
        paginationHtml += `<button class="btn btn-secondary" onclick="goToPage(1)">1</button>`;
        if (startPage > 2) {
            paginationHtml += `<span class="pagination-dots">...</span>`;
        }
    }
    
    for (let i = startPage; i <= endPage; i++) {
        if (i === pagination.page) {
            paginationHtml += `<button class="btn btn-primary">${i}</button>`;
        } else {
            paginationHtml += `<button class="btn btn-secondary" onclick="goToPage(${i})">${i}</button>`;
        }
    }
    
    if (endPage < pagination.pages) {
        if (endPage < pagination.pages - 1) {
            paginationHtml += `<span class="pagination-dots">...</span>`;
        }
        paginationHtml += `<button class="btn btn-secondary" onclick="goToPage(${pagination.pages})">${pagination.pages}</button>`;
    }
    
    // Botón siguiente
    if (pagination.has_next) {
        paginationHtml += `
            <button class="btn btn-secondary" onclick="goToPage(${pagination.next_page})">
                Siguiente <i class="fas fa-chevron-right"></i>
            </button>
        `;
    } else {
        paginationHtml += `
            <button class="btn btn-secondary" disabled>
                Siguiente <i class="fas fa-chevron-right"></i>
            </button>
        `;
    }
    
    paginationHtml += `
        </div>
    `;
    
    paginationControls.innerHTML = paginationHtml;
    paginationControls.classList.remove('hidden');
}

function goToPage(page) {
    if (page !== currentPage && page >= 1 && page <= totalPages) {
        loadDevicesPage(page);
        
        // Scroll to top suavemente
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }
}

async function forceRefreshDevices() {
    console.log('🔄 Forzando actualización...');
    
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.disabled = true;
        const icon = refreshBtn.querySelector('i');
        if (icon) {
            icon.classList.add('fa-spin');
        }
    }
    
    try {
        const response = await fetch('/api/devices/refresh', {
            method: 'POST'
        });
        
        if (response.ok) {
            await loadDevicesPage(1);
            showNotification('Dispositivos actualizados correctamente', 'success');
        } else {
            throw new Error('Error al actualizar');
        }
    } catch (error) {
        console.error('❌ Error refrescando:', error);
        showNotification('Error al actualizar dispositivos', 'error');
    } finally {
        if (refreshBtn) {
            refreshBtn.disabled = false;
            const icon = refreshBtn.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-spin');
            }
        }
    }
}

function handleSearch() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;
    
    const query = searchInput.value.trim();
    
    // Actualizar búsqueda actual
    currentSearch = query;
    
    // Reset a primera página
    currentPage = 1;
    
    // Cargar nueva búsqueda
    loadDevicesPage(1);
    
    // Mostrar/ocultar botón clear
    const searchClear = document.getElementById('searchClear');
    if (searchClear) {
        if (query) {
            searchClear.classList.remove('hidden');
        } else {
            searchClear.classList.add('hidden');
        }
    }
}

function clearSearch() {
    const searchInput = document.getElementById('searchInput');
    const searchClear = document.getElementById('searchClear');
    
    if (searchInput) {
        searchInput.value = '';
    }
    if (searchClear) {
        searchClear.classList.add('hidden');
    }
    
    // Limpiar búsqueda
    currentSearch = '';
    currentPage = 1;
    
    // Recargar sin búsqueda
    loadDevicesPage(1);
}

// Funciones de dispositivos
function showDeviceDetails(serial) {
    showNotification(`Detalles de ${serial} - Próximamente`, 'info');
}

function editContract(serial) {
    showNotification(`Editar contrato de ${serial} - Próximamente`, 'info');
}

function togglePassword(serial, band) {
    const passwordElement = document.getElementById(`password-${serial}-${band}`);
    if (passwordElement) {
        passwordElement.classList.toggle('hidden');
        
        // Cambiar icono del botón
        const button = passwordElement.previousElementSibling.querySelector('.password-toggle-btn');
        if (button) {
            const icon = button.querySelector('i');
            if (icon) {
                if (passwordElement.classList.contains('hidden')) {
                    icon.className = 'fas fa-eye';
                } else {
                    icon.className = 'fas fa-eye-slash';
                }
            }
        }
    }
}

function showErrorState() {
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    const emptyState = document.getElementById('emptyState');
    const devicesGrid = document.getElementById('devicesGrid');
    const paginationControls = document.getElementById('paginationControls');
    
    if (loadingState) loadingState.classList.add('hidden');
    if (errorState) errorState.classList.remove('hidden');
    if (emptyState) emptyState.classList.add('hidden');
    if (devicesGrid) devicesGrid.classList.add('hidden');
    if (paginationControls) paginationControls.classList.add('hidden');
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
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.classList.add('hidden');
    });
}

function showNotification(message, type = 'info') {
    console.log(`📢 ${type.toUpperCase()}: ${message}`);
    
    const container = document.getElementById('notificationContainer') || createNotificationContainer();
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="notification-icon fas fa-${getNotificationIcon(type)}"></i>
            <span class="notification-text">${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    container.appendChild(notification);
    
    // Mostrar con animación
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    // Auto remove después de 5 segundos
    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 300);
        }
    }, 5000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notificationContainer';
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 3000;
        display: flex;
        flex-direction: column;
        gap: 10px;
    `;
    document.body.appendChild(container);
    return container;
}

function getNotificationIcon(type) {
    switch (type) {
        case 'success': return 'check-circle';
        case 'error': return 'exclamation-triangle';
        case 'warning': return 'exclamation-circle';
        default: return 'info-circle';
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl + R para refresh
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        forceRefreshDevices();
    }
    
    // Flecha izquierda para página anterior
    if (e.key === 'ArrowLeft' && e.altKey && currentPage > 1) {
        e.preventDefault();
        goToPage(currentPage - 1);
    }
    
    // Flecha derecha para página siguiente
    if (e.key === 'ArrowRight' && e.altKey && currentPage < totalPages) {
        e.preventDefault();
        goToPage(currentPage + 1);
    }
    
    // Esc para cerrar sidebar
    if (e.key === 'Escape') {
        closeSidebar();
        closeModals();
    }
});