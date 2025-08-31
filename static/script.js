
class WiFiManager {
    constructor() {
        this.devices = [];
        this.filteredDevices = [];
        this.baseUrl = 'http://localhost:5000/api';
        this.currentEditDevice = null;
        this.currentEditNetwork = null;

        this.initElements();
        this.bindEvents();
        this.loadInitialData();
    }

    initElements() {
        // Elementos del DOM
        this.searchInput = document.getElementById('searchInput');
        this.clearBtn = document.getElementById('clearBtn');
        this.reloadBtn = document.getElementById('reloadBtn');
        this.devicesGrid = document.getElementById('devicesGrid');
        this.loadingSpinner = document.getElementById('loadingSpinner');
        this.errorMessage = document.getElementById('errorMessage');
        this.emptyState = document.getElementById('emptyState');
        this.resultsCount = document.getElementById('resultsCount');

        // Elementos de estadísticas
        this.totalDevices = document.getElementById('totalDevices');
        this.devicesWithWifi = document.getElementById('devicesWithWifi');
        this.devicesWithPasswords = document.getElementById('devicesWithPasswords');
        this.totalNetworks = document.getElementById('totalNetworks');

        // Modales
        this.editSSIDModal = document.getElementById('editSSIDModal');
        this.editPasswordModal = document.getElementById('editPasswordModal');
        this.confirmModal = document.getElementById('confirmModal');

        // Formularios
        this.editSSIDForm = document.getElementById('editSSIDForm');
        this.editPasswordForm = document.getElementById('editPasswordForm');

        // Campos de formulario
        this.currentSSID = document.getElementById('currentSSID');
        this.newSSID = document.getElementById('newSSID');
        this.networkSSID = document.getElementById('networkSSID');
        this.currentPassword = document.getElementById('currentPassword');
        this.newPassword = document.getElementById('newPassword');

        // Confirmación
        this.confirmMessage = document.getElementById('confirmMessage');
        this.confirmAction = document.getElementById('confirmAction');

        // Contenedor de notificaciones
        this.notificationContainer = document.getElementById('notificationContainer');
    }

    bindEvents() {
        // Búsqueda en tiempo real
        this.searchInput.addEventListener('input', (e) => {
            this.handleSearch(e.target.value);
        });

        // Limpiar búsqueda
        this.clearBtn.addEventListener('click', () => {
            this.searchInput.value = '';
            this.handleSearch('');
        });

        // Recargar datos
        this.reloadBtn.addEventListener('click', () => {
            this.reloadData();
        });

        // Cerrar modales
        document.querySelectorAll('.close').forEach(closeBtn => {
            closeBtn.addEventListener('click', (e) => {
                const modalId = e.target.getAttribute('data-modal');
                if (modalId) {
                    this.closeModal(modalId);
                }
            });
        });

        // Cerrar modales con botones
        document.querySelectorAll('[data-close]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const modalId = e.target.getAttribute('data-close');
                this.closeModal(modalId);
            });
        });

        // Cerrar modal al hacer click fuera
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
        });

        // Cerrar modal con ESC
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal').forEach(modal => {
                    modal.style.display = 'none';
                });
            }
        });

        // Toggle de contraseñas
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('password-toggle') || e.target.parentElement.classList.contains('password-toggle')) {
                const button = e.target.classList.contains('password-toggle') ? e.target : e.target.parentElement;
                this.togglePasswordVisibility(button);
            }
        });

        // Formularios
        this.editSSIDForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitSSIDChange();
        });

        this.editPasswordForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitPasswordChange();
        });

        // Confirmación
        this.confirmAction.addEventListener('click', () => {
            this.executeConfirmedAction();
        });
    }

    async loadInitialData() {
        this.showLoading();
        try {
            await Promise.all([
                this.loadStatistics(),
                this.loadDevices()
            ]);
        } catch (error) {
            this.showError();
        }
    }

    async loadStatistics() {
        try {
            const response = await fetch(`${this.baseUrl}/statistics`);
            const data = await response.json();

            if (data.success) {
                this.updateStatistics(data.statistics);
            }
        } catch (error) {
            console.error('Error loading statistics:', error);
        }
    }

    async loadDevices() {
        try {
            const response = await fetch(`${this.baseUrl}/devices`);
            const data = await response.json();

            if (data.success) {
                this.devices = data.devices.filter(device => 
                    device.wifi_networks && device.wifi_networks.length > 0
                );
                this.filteredDevices = [...this.devices];
                this.renderDevices();
                this.hideLoading();
            } else {
                this.showError();
            }
        } catch (error) {
            console.error('Error loading devices:', error);
            this.showError();
        }
    }

    async handleSearch(query) {
        if (!query.trim()) {
            this.filteredDevices = [...this.devices];
            this.renderDevices();
            return;
        }

        try {
            const response = await fetch(`${this.baseUrl}/search?serial=${encodeURIComponent(query)}`);
            const data = await response.json();

            if (data.success) {
                this.filteredDevices = data.devices.filter(device => 
                    device.wifi_networks && device.wifi_networks.length > 0
                );
                this.renderDevices();
            }
        } catch (error) {
            console.error('Error searching devices:', error);
        }
    }

    async reloadData() {
        const originalText = this.reloadBtn.innerHTML;
        this.reloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Recargando...';
        this.reloadBtn.disabled = true;

        try {
            await fetch(`${this.baseUrl}/reload`);
            await this.loadInitialData();
            this.showNotification('Datos recargados correctamente', 'success');
        } catch (error) {
            console.error('Error reloading data:', error);
            this.showError();
        } finally {
            this.reloadBtn.innerHTML = originalText;
            this.reloadBtn.disabled = false;
        }
    }

    updateStatistics(stats) {
        this.totalDevices.textContent = stats.total_devices || '0';
        this.devicesWithWifi.textContent = stats.devices_with_wifi || '0';
        this.devicesWithPasswords.textContent = stats.devices_with_passwords || '0';
        this.totalNetworks.textContent = stats.total_wifi_networks || '0';
    }

    renderDevices() {
        this.resultsCount.textContent = this.filteredDevices.length;

        if (this.filteredDevices.length === 0) {
            this.showEmptyState();
            return;
        }

        this.devicesGrid.innerHTML = '';
        this.devicesGrid.style.display = 'grid';
        this.emptyState.style.display = 'none';

        this.filteredDevices.forEach((device, index) => {
            const deviceCard = this.createDeviceWiFiCard(device, index);
            this.devicesGrid.appendChild(deviceCard);
        });
    }

    createDeviceWiFiCard(device, index) {
        const card = document.createElement('div');
        card.className = 'device-wifi-card';
        card.style.animationDelay = `${index * 0.1}s`;

        const serialNumber = this.truncateText(device.serial_number || 'N/A', 30);
        const productClass = device.product_class || 'Dispositivo WiFi';
        const wifiNetworks = device.wifi_networks || [];

        card.innerHTML = `
            <div class="device-header">
                <div class="device-icon">
                    <i class="fas fa-wifi"></i>
                </div>
                <div class="device-title">
                    <h4>${productClass}</h4>
                    <div class="device-serial">${serialNumber}</div>
                </div>
            </div>

            <div class="wifi-networks">
                ${wifiNetworks.map((network, netIndex) => this.createNetworkHTML(device, network, netIndex)).join('')}
            </div>
        `;

        return card;
    }

    createNetworkHTML(device, network, index) {
        const isMainNetwork = network.is_main;
        const networkClass = isMainNetwork ? 'wifi-network main-network' : 'wifi-network';
        const badgeClass = isMainNetwork ? 'network-badge main' : 'network-badge';
        const badgeText = isMainNetwork ? 'Principal' : 'Secundaria';

        // Generar ID único para el toggle de contraseña
        const passwordToggleId = `pwd-${device.serial_number}-${network.wlan_id}`;

        return `
            <div class="${networkClass}">
                <div class="network-header">
                    <div class="network-info">
                        <div class="network-ssid">
                            <span>${network.ssid || 'Sin SSID'}</span>
                            <span class="${badgeClass}">${badgeText}</span>
                        </div>
                    </div>
                </div>

                <div class="network-details">
                    <div class="detail-item">
                        <span class="detail-label">Contraseña</span>
                        <div class="password-display">
                            <span class="password-value" id="${passwordToggleId}">${this.maskPassword(network.password)}</span>
                            <button class="password-toggle-btn" data-password="${network.password || ''}" data-target="${passwordToggleId}">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Estado</span>
                        <span class="detail-value">${network.enabled === 'true' || network.enabled === '1' ? '🟢 Activo' : '🔴 Inactivo'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Seguridad</span>
                        <span class="detail-value">${network.auth_mode || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Cifrado</span>
                        <span class="detail-value">${network.encryption_mode || 'N/A'}</span>
                    </div>
                </div>

                <div class="network-actions">
                    <button class="btn btn-primary btn-small" onclick="wifiManager.editSSID('${device.serial_number}', '${network.wlan_id}', '${network.ssid}')">
                        <i class="fas fa-edit"></i> Editar SSID
                    </button>
                    <button class="btn btn-warning btn-small" onclick="wifiManager.editPassword('${device.serial_number}', '${network.wlan_id}', '${network.ssid}', '${network.password || ''}')">
                        <i class="fas fa-key"></i> Cambiar Contraseña
                    </button>
                </div>
            </div>
        `;
    }

    maskPassword(password) {
        if (!password) return 'Sin contraseña';
        return '*'.repeat(Math.min(password.length, 12));
    }

    togglePasswordVisibility(button) {
        const targetId = button.getAttribute('data-target');
        const passwordElement = document.getElementById(targetId);
        const actualPassword = button.getAttribute('data-password');
        const icon = button.querySelector('i');

        if (passwordElement.textContent.includes('*')) {
            passwordElement.textContent = actualPassword || 'Sin contraseña';
            icon.className = 'fas fa-eye-slash';
        } else {
            passwordElement.textContent = this.maskPassword(actualPassword);
            icon.className = 'fas fa-eye';
        }
    }

    editSSID(deviceSerial, wlanId, currentSSID) {
        this.currentEditDevice = deviceSerial;
        this.currentEditNetwork = wlanId;

        this.currentSSID.value = currentSSID;
        this.newSSID.value = currentSSID;

        this.openModal('editSSIDModal');
        this.newSSID.focus();
        this.newSSID.select();
    }

    editPassword(deviceSerial, wlanId, ssid, currentPassword) {
        this.currentEditDevice = deviceSerial;
        this.currentEditNetwork = wlanId;

        this.networkSSID.value = ssid;
        this.currentPassword.value = currentPassword;
        this.newPassword.value = currentPassword;

        this.openModal('editPasswordModal');
        this.newPassword.focus();
        this.newPassword.select();
    }

    async submitSSIDChange() {
        const newSSIDValue = this.newSSID.value.trim();

        if (!newSSIDValue) {
            this.showNotification('El SSID no puede estar vacío', 'error');
            return;
        }

        if (newSSIDValue.length > 32) {
            this.showNotification('El SSID no puede tener más de 32 caracteres', 'error');
            return;
        }

        // Confirmar cambio
        this.confirmMessage.textContent = `¿Confirmar cambio de SSID a "${newSSIDValue}"? Esto puede desconectar dispositivos conectados.`;
        this.pendingAction = () => this.executeSSIDChange(newSSIDValue);
        this.openModal('confirmModal');
    }

    async executeSSIDChange(newSSID) {
        try {
            const response = await fetch(
                `${this.baseUrl}/device/${this.currentEditDevice}/wifi/${this.currentEditNetwork}/ssid`,
                {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ssid: newSSID })
                }
            );

            const result = await response.json();

            if (result.success) {
                this.showNotification(`SSID actualizado correctamente a "${newSSID}"`, 'success');
                this.closeModal('editSSIDModal');
                await this.loadDevices(); // Recargar para mostrar cambios
            } else {
                this.showNotification(`Error: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Error de conexión al actualizar SSID', 'error');
        }

        this.closeModal('confirmModal');
    }

    async submitPasswordChange() {
        const newPasswordValue = this.newPassword.value.trim();

        if (newPasswordValue.length > 0 && newPasswordValue.length < 8) {
            this.showNotification('La contraseña debe tener al menos 8 caracteres', 'error');
            return;
        }

        if (newPasswordValue.length > 63) {
            this.showNotification('La contraseña no puede tener más de 63 caracteres', 'error');
            return;
        }

        // Confirmar cambio
        const message = newPasswordValue ? 
            `¿Confirmar cambio de contraseña WiFi? Esto desconectará todos los dispositivos.` :
            `¿Confirmar eliminación de contraseña? La red quedará abierta.`;

        this.confirmMessage.textContent = message;
        this.pendingAction = () => this.executePasswordChange(newPasswordValue);
        this.openModal('confirmModal');
    }

    async executePasswordChange(newPassword) {
        try {
            const response = await fetch(
                `${this.baseUrl}/device/${this.currentEditDevice}/wifi/${this.currentEditNetwork}/password`,
                {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: newPassword })
                }
            );

            const result = await response.json();

            if (result.success) {
                const message = newPassword ? 
                    'Contraseña WiFi actualizada correctamente' :
                    'Contraseña WiFi eliminada - Red abierta';
                this.showNotification(message, 'success');
                this.closeModal('editPasswordModal');
                await this.loadDevices(); // Recargar para mostrar cambios
            } else {
                this.showNotification(`Error: ${result.message}`, 'error');
            }
        } catch (error) {
            this.showNotification('Error de conexión al actualizar contraseña', 'error');
        }

        this.closeModal('confirmModal');
    }

    executeConfirmedAction() {
        if (this.pendingAction) {
            this.pendingAction();
            this.pendingAction = null;
        }
    }

    openModal(modalId) {
        document.getElementById(modalId).style.display = 'block';
    }

    closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;

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

        notification.innerHTML = `
            <i class="fas ${icon}"></i>
            <div class="notification-content">
                <div class="notification-title">${title}</div>
                <div class="notification-message">${message}</div>
            </div>
        `;

        this.notificationContainer.appendChild(notification);

        // Auto remove después de 5 segundos
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);
    }

    truncateText(text, maxLength) {
        if (!text) return 'N/A';
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }

    showLoading() {
        this.loadingSpinner.style.display = 'block';
        this.devicesGrid.style.display = 'none';
        this.emptyState.style.display = 'none';
        this.errorMessage.style.display = 'none';
    }

    hideLoading() {
        this.loadingSpinner.style.display = 'none';
    }

    showError() {
        this.loadingSpinner.style.display = 'none';
        this.devicesGrid.style.display = 'none';
        this.emptyState.style.display = 'none';
        this.errorMessage.style.display = 'block';
    }

    showEmptyState() {
        this.loadingSpinner.style.display = 'none';
        this.devicesGrid.style.display = 'none';
        this.errorMessage.style.display = 'none';
        this.emptyState.style.display = 'block';
    }
}

// Inicializar la aplicación cuando el DOM esté listo
let wifiManager;
document.addEventListener('DOMContentLoaded', () => {
    wifiManager = new WiFiManager();
});
