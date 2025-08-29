
class GenieACSManager {
    constructor() {
        this.devices = [];
        this.filteredDevices = [];
        this.baseUrl = 'http://localhost:5000/api';

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
        this.devicesWithSoftware = document.getElementById('devicesWithSoftware');
        this.devicesWithSSID = document.getElementById('devicesWithSSID');
        this.lastUpdate = document.getElementById('lastUpdate');

        // Modal
        this.modal = document.getElementById('deviceModal');
        this.modalBody = document.getElementById('modalBody');
        this.closeModal = document.querySelector('.close');
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

        // Cerrar modal
        this.closeModal.addEventListener('click', () => {
            this.modal.style.display = 'none';
        });

        // Cerrar modal al hacer click fuera
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.modal.style.display = 'none';
            }
        });

        // Cerrar modal con ESC
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.modal.style.display === 'block') {
                this.modal.style.display = 'none';
            }
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
                this.devices = data.devices;
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
                this.filteredDevices = data.devices;
                this.renderDevices();
            }
        } catch (error) {
            console.error('Error searching devices:', error);
        }
    }

    async reloadData() {
        // Mostrar estado de carga en el botón
        const originalText = this.reloadBtn.innerHTML;
        this.reloadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Recargando...';
        this.reloadBtn.disabled = true;

        try {
            // Recargar datos del servidor
            await fetch(`${this.baseUrl}/reload`);

            // Recargar todo
            await this.loadInitialData();

            // Mostrar mensaje de éxito
            this.showSuccessMessage('Datos recargados correctamente');
        } catch (error) {
            console.error('Error reloading data:', error);
            this.showError();
        } finally {
            // Restaurar botón
            this.reloadBtn.innerHTML = originalText;
            this.reloadBtn.disabled = false;
        }
    }

    updateStatistics(stats) {
        this.totalDevices.textContent = stats.total_devices || '0';
        this.devicesWithSoftware.textContent = stats.devices_with_software_version || '0';
        this.devicesWithSSID.textContent = stats.devices_with_ssid || '0';

        // Formatear fecha
        if (stats.last_update && stats.last_update !== 'Desconocido') {
            const date = new Date(stats.last_update);
            this.lastUpdate.textContent = date.toLocaleString('es-ES', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } else {
            this.lastUpdate.textContent = 'Desconocido';
        }
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
            const deviceCard = this.createDeviceCard(device, index);
            this.devicesGrid.appendChild(deviceCard);
        });
    }

    createDeviceCard(device, index) {
        const card = document.createElement('div');
        card.className = 'device-card';
        card.style.animationDelay = `${index * 0.1}s`;

        // Limpiar datos
        const serialNumber = this.truncateText(device.serial_number || 'N/A', 25);
        const productClass = device.product_class || 'N/A';
        const softwareVersion = device.software_version || 'N/A';
        const ipAddress = device.ip || 'N/A';
        const ssids = device.ssid || [];
        const lastInform = device.last_inform || 'N/A';

        card.innerHTML = `
            <div class="device-header">
                <div class="device-icon">
                    <i class="fas fa-router"></i>
                </div>
                <div class="device-title">
                    <h4>${productClass}</h4>
                    <span>Serial: ${serialNumber}</span>
                </div>
            </div>

            <div class="device-info">
                <div class="info-row">
                    <span class="info-label">Software:</span>
                    <span class="info-value">${softwareVersion}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">IP:</span>
                    <span class="info-value">${ipAddress}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">SSIDs:</span>
                    <div class="ssid-tags">
                        ${ssids.length > 0 ? 
                            ssids.map(ssid => `<span class="ssid-tag">${ssid}</span>`).join('') :
                            '<span class="info-value">N/A</span>'
                        }
                    </div>
                </div>
                <div class="info-row">
                    <span class="info-label">Último contacto:</span>
                    <span class="info-value">${this.truncateText(lastInform, 20)}</span>
                </div>
            </div>
        `;

        // Agregar evento click para mostrar detalles
        card.addEventListener('click', () => {
            this.showDeviceDetails(device);
        });

        return card;
    }

    showDeviceDetails(device) {
        const details = `
            <div class="detail-section">
                <h3><i class="fas fa-info-circle"></i> Información General</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Número de Serie:</span>
                        <span class="detail-value">${device.serial_number || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Clase de Producto:</span>
                        <span class="detail-value">${device.product_class || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Fabricante:</span>
                        <span class="detail-value">${device.manufacturer || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Modelo:</span>
                        <span class="detail-value">${device.model_name || 'N/A'}</span>
                    </div>
                </div>
            </div>

            <div class="detail-section">
                <h3><i class="fas fa-microchip"></i> Versiones</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Software:</span>
                        <span class="detail-value">${device.software_version || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Hardware:</span>
                        <span class="detail-value">${device.hardware_version || 'N/A'}</span>
                    </div>
                </div>
            </div>

            <div class="detail-section">
                <h3><i class="fas fa-network-wired"></i> Conectividad</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Dirección IP:</span>
                        <span class="detail-value">${device.ip || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">MAC Address:</span>
                        <span class="detail-value">${device.mac_address || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">URL de Conexión:</span>
                        <span class="detail-value">${device.connection_url || 'N/A'}</span>
                    </div>
                </div>
            </div>

            <div class="detail-section">
                <h3><i class="fas fa-wifi"></i> Redes WiFi</h3>
                <div class="detail-grid">
                    ${device.ssid && device.ssid.length > 0 ? 
                        device.ssid.map((ssid, index) => `
                            <div class="detail-item">
                                <span class="detail-label">SSID ${index + 1}:</span>
                                <span class="detail-value">${ssid}</span>
                            </div>
                        `).join('') :
                        '<div class="detail-item"><span class="detail-label">SSIDs:</span><span class="detail-value">No configurados</span></div>'
                    }
                </div>
            </div>

            <div class="detail-section">
                <h3><i class="fas fa-clock"></i> Estado</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Último contacto:</span>
                        <span class="detail-value">${device.last_inform || 'N/A'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Tags:</span>
                        <span class="detail-value">
                            ${device.tags && device.tags.length > 0 ? 
                                device.tags.join(', ') : 'Ninguno'
                            }
                        </span>
                    </div>
                </div>
            </div>
        `;

        this.modalBody.innerHTML = details;
        this.modal.style.display = 'block';
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

    showSuccessMessage(message) {
        // Crear notificación temporal
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #27ae60;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
            z-index: 1001;
            animation: slideIn 0.3s ease;
        `;
        notification.innerHTML = `<i class="fas fa-check"></i> ${message}`;

        document.body.appendChild(notification);

        // Remover después de 3 segundos
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
}

// Agregar estilos para animaciones de notificación
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }

    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(notificationStyles);

// Inicializar la aplicación cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    new GenieACSManager();
});
