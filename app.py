
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime
import glob

app = Flask(__name__)
CORS(app)  # Permitir CORS para desarrollo

class GenieACSDataManager:
    def __init__(self):
        self.data = None
        self.last_loaded_file = None
        self.load_latest_data()

    def load_latest_data(self):
        """Cargar el archivo JSON más reciente"""
        try:
            # Buscar archivos JSON de GenieACS
            json_files = glob.glob("genieacs_devices_*.json")
            if not json_files:
                print("⚠️ No se encontraron archivos JSON de GenieACS")
                return False

            # Obtener el archivo más reciente
            latest_file = max(json_files, key=os.path.getctime)

            # Solo cargar si es un archivo diferente
            if latest_file != self.last_loaded_file:
                with open(latest_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                self.last_loaded_file = latest_file
                print(f"✅ Datos cargados desde: {latest_file}")
                return True
            return True
        except Exception as e:
            print(f"❌ Error cargando datos: {e}")
            return False

    def clean_ssids(self, ssid_list):
        """Limpiar y filtrar SSIDs para mostrar solo los principales"""
        if not ssid_list or not isinstance(ssid_list, list):
            return []

        # Filtrar SSIDs vacíos y duplicados
        cleaned_ssids = []
        seen_ssids = set()

        for ssid in ssid_list:
            ssid_clean = str(ssid).strip()
            if ssid_clean and ssid_clean not in seen_ssids:
                # Filtrar SSIDs que no son útiles (como AP-1, AP-2, etc.)
                if not ssid_clean.startswith('AP-') or len(cleaned_ssids) < 2:
                    cleaned_ssids.append(ssid_clean)
                    seen_ssids.add(ssid_clean)

        # Retornar máximo 2 SSIDs principales
        return cleaned_ssids[:2]

    def get_all_devices(self):
        """Obtener todos los dispositivos con SSIDs limpiados"""
        if not self.data:
            return []

        devices = self.data.get('devices', [])
        for device in devices:
            device['ssid'] = self.clean_ssids(device.get('ssid', []))

        return devices

    def search_by_serial(self, serial_query):
        """Buscar dispositivos por número de serie"""
        devices = self.get_all_devices()
        if not serial_query:
            return devices

        serial_query = serial_query.lower().strip()
        filtered_devices = []

        for device in devices:
            serial = device.get('serial_number', '').lower()
            if serial_query in serial:
                filtered_devices.append(device)

        return filtered_devices

    def get_statistics(self):
        """Obtener estadísticas de los dispositivos"""
        devices = self.get_all_devices()
        if not devices:
            return {}

        stats = {
            'total_devices': len(devices),
            'devices_with_product_class': sum(1 for d in devices if d.get('product_class')),
            'devices_with_software_version': sum(1 for d in devices if d.get('software_version')),
            'devices_with_ip': sum(1 for d in devices if d.get('ip')),
            'devices_with_ssid': sum(1 for d in devices if d.get('ssid')),
            'last_update': self.data.get('timestamp', 'Desconocido') if self.data else 'Desconocido'
        }

        return stats

# Instancia global del gestor de datos
data_manager = GenieACSDataManager()

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """API para obtener todos los dispositivos"""
    # Recargar datos si es necesario
    data_manager.load_latest_data()
    devices = data_manager.get_all_devices()
    return jsonify({
        'success': True,
        'devices': devices,
        'count': len(devices)
    })

@app.route('/api/search')
def search_devices():
    """API para buscar dispositivos por número de serie"""
    serial_query = request.args.get('serial', '')

    # Recargar datos si es necesario
    data_manager.load_latest_data()
    devices = data_manager.search_by_serial(serial_query)

    return jsonify({
        'success': True,
        'devices': devices,
        'count': len(devices),
        'query': serial_query
    })

@app.route('/api/statistics')
def get_statistics():
    """API para obtener estadísticas"""
    # Recargar datos si es necesario
    data_manager.load_latest_data()
    stats = data_manager.get_statistics()

    return jsonify({
        'success': True,
        'statistics': stats
    })

@app.route('/api/reload')
def reload_data():
    """API para recargar los datos manualmente"""
    success = data_manager.load_latest_data()
    return jsonify({
        'success': success,
        'message': 'Datos recargados correctamente' if success else 'Error recargando datos'
    })

if __name__ == '__main__':
    print("🚀 Iniciando servidor GenieACS Web Interface...")
    print("📊 Accede a http://localhost:5000 para ver la interfaz")
    app.run(debug=True, host='0.0.0.0', port=5000)
