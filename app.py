from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
import requests
from datetime import datetime
import glob
from urllib.parse import quote, unquote

app = Flask(__name__)
CORS(app)

# Configuración de GenieACS
GENIEACS_URL = "http://192.168.0.237:7557"
GENIEACS_USERNAME = "admin"
GENIEACS_PASSWORD = "admin"

class GenieACSWiFiManager:
    def __init__(self):
        self.data = None
        self.last_loaded_file = None
        self.load_latest_data()

    def load_latest_data(self):
        """Cargar el archivo JSON más reciente"""
        try:
            json_files = glob.glob("genieacs_devices_*.json")
            if not json_files:
                print("⚠️ No se encontraron archivos JSON de GenieACS")
                return False

            latest_file = max(json_files, key=os.path.getctime)

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

    def get_all_devices(self):
        """Obtener todos los dispositivos"""
        if not self.data:
            return []
        return self.data.get('devices', [])

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

    def get_device_by_serial(self, serial_number):
        """Obtener dispositivo específico por número de serie"""
        devices = self.get_all_devices()
        for device in devices:
            if device.get('serial_number') == serial_number:
                return device
        return None

    def send_genieacs_command(self, device_id, command_type, parameter_path, value=None):
        """Enviar comando a GenieACS para modificar parámetros"""
        try:
            # URL para tareas de GenieACS
            tasks_url = f"{GENIEACS_URL}/tasks"

            # Codificar el device_id para la URL
            encoded_device_id = quote(device_id, safe='')

            if command_type == "setParameterValues":
                # Comando para establecer valores de parámetros
                task_data = {
                    "name": "setParameterValues",
                    "parameterValues": [
                        [parameter_path, value, "xsd:string"]
                    ]
                }
            elif command_type == "refreshObject":
                # Comando para refrescar objeto
                task_data = {
                    "name": "refreshObject",
                    "objectName": parameter_path
                }
            else:
                return {"success": False, "message": "Tipo de comando no válido"}

            # Enviar tarea a GenieACS
            response = requests.post(
                f"{tasks_url}?connection_request",
                params={"device": encoded_device_id},
                json=task_data,
                auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
            )

            if response.status_code in [200, 202]:
                return {"success": True, "message": "Comando enviado correctamente"}
            else:
                return {"success": False, "message": f"Error en GenieACS: {response.status_code} - {response.text}"}

        except Exception as e:
            return {"success": False, "message": f"Error enviando comando: {str(e)}"}

    def update_wifi_ssid(self, device_serial, wlan_id, new_ssid):
        """Actualizar SSID de una red WiFi"""
        try:
            device = self.get_device_by_serial(device_serial)
            if not device:
                return {"success": False, "message": "Dispositivo no encontrado"}

            # Construir la ruta del parámetro SSID
            parameter_path = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{wlan_id}.SSID"

            # Enviar comando a GenieACS
            result = self.send_genieacs_command(
                device_serial, 
                "setParameterValues", 
                parameter_path, 
                new_ssid
            )

            if result["success"]:
                # Actualizar datos locales
                for wifi_net in device.get('wifi_networks', []):
                    if wifi_net.get('wlan_id') == wlan_id:
                        wifi_net['ssid'] = new_ssid
                        break

                return {"success": True, "message": f"SSID actualizado a: {new_ssid}"}
            else:
                return result

        except Exception as e:
            return {"success": False, "message": f"Error actualizando SSID: {str(e)}"}

    def update_wifi_password(self, device_serial, wlan_id, new_password):
        """Actualizar contraseña de una red WiFi"""
        try:
            device = self.get_device_by_serial(device_serial)
            if not device:
                return {"success": False, "message": "Dispositivo no encontrado"}

            # Construir la ruta del parámetro de contraseña
            parameter_path = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{wlan_id}.KeyPassphrase"

            # Enviar comando a GenieACS
            result = self.send_genieacs_command(
                device_serial, 
                "setParameterValues", 
                parameter_path, 
                new_password
            )

            if result["success"]:
                # Actualizar datos locales
                for wifi_net in device.get('wifi_networks', []):
                    if wifi_net.get('wlan_id') == wlan_id:
                        wifi_net['password'] = new_password
                        break

                return {"success": True, "message": "Contraseña WiFi actualizada correctamente"}
            else:
                return result

        except Exception as e:
            return {"success": False, "message": f"Error actualizando contraseña: {str(e)}"}

    def refresh_device_config(self, device_serial):
        """Refrescar configuración del dispositivo desde GenieACS"""
        try:
            # Refrescar configuración WLAN
            result = self.send_genieacs_command(
                device_serial,
                "refreshObject",
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
            )
            return result
        except Exception as e:
            return {"success": False, "message": f"Error refrescando dispositivo: {str(e)}"}

    def get_statistics(self):
        """Obtener estadísticas de los dispositivos"""
        devices = self.get_all_devices()
        if not devices:
            return {}

        stats = {
            'total_devices': len(devices),
            'devices_with_wifi': sum(1 for d in devices if d.get('wifi_networks')),
            'devices_with_passwords': sum(1 for d in devices if any(net.get('password') for net in d.get('wifi_networks', []))),
            'total_wifi_networks': sum(len(d.get('wifi_networks', [])) for d in devices),
            'last_update': self.data.get('timestamp', 'Desconocido') if self.data else 'Desconocido'
        }

        return stats

# Instancia global del gestor
wifi_manager = GenieACSWiFiManager()

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """API para obtener todos los dispositivos"""
    wifi_manager.load_latest_data()
    devices = wifi_manager.get_all_devices()
    return jsonify({
        'success': True,
        'devices': devices,
        'count': len(devices)
    })

@app.route('/api/search')
def search_devices():
    """API para buscar dispositivos por número de serie"""
    serial_query = request.args.get('serial', '')

    wifi_manager.load_latest_data()
    devices = wifi_manager.search_by_serial(serial_query)

    return jsonify({
        'success': True,
        'devices': devices,
        'count': len(devices),
        'query': serial_query
    })

@app.route('/api/device/<device_serial>/wifi')
def get_device_wifi(device_serial):
    """API para obtener configuración WiFi específica de un dispositivo"""
    device = wifi_manager.get_device_by_serial(device_serial)

    if not device:
        return jsonify({'success': False, 'message': 'Dispositivo no encontrado'}), 404

    return jsonify({
        'success': True,
        'device': device,
        'wifi_networks': device.get('wifi_networks', [])
    })

@app.route('/api/device/<device_serial>/wifi/<wlan_id>/ssid', methods=['PUT'])
def update_ssid(device_serial, wlan_id):
    """API para actualizar SSID de una red WiFi"""
    try:
        data = request.get_json()
        new_ssid = data.get('ssid', '').strip()

        if not new_ssid:
            return jsonify({'success': False, 'message': 'SSID no puede estar vacío'}), 400

        if len(new_ssid) < 1 or len(new_ssid) > 32:
            return jsonify({'success': False, 'message': 'SSID debe tener entre 1 y 32 caracteres'}), 400

        result = wifi_manager.update_wifi_ssid(device_serial, wlan_id, new_ssid)

        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error del servidor: {str(e)}'}), 500

@app.route('/api/device/<device_serial>/wifi/<wlan_id>/password', methods=['PUT'])
def update_password(device_serial, wlan_id):
    """API para actualizar contraseña de una red WiFi"""
    try:
        data = request.get_json()
        new_password = data.get('password', '').strip()

        if len(new_password) < 8 and new_password:  # Permitir contraseña vacía para redes abiertas
            return jsonify({'success': False, 'message': 'Contraseña debe tener al menos 8 caracteres'}), 400

        if len(new_password) > 63:
            return jsonify({'success': False, 'message': 'Contraseña no puede tener más de 63 caracteres'}), 400

        result = wifi_manager.update_wifi_password(device_serial, wlan_id, new_password)

        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error del servidor: {str(e)}'}), 500

@app.route('/api/device/<device_serial>/refresh', methods=['POST'])
def refresh_device(device_serial):
    """API para refrescar configuración del dispositivo"""
    result = wifi_manager.refresh_device_config(device_serial)

    if result['success']:
        # Recargar datos después del refresh
        wifi_manager.load_latest_data()
        return jsonify(result)
    else:
        return jsonify(result), 500

@app.route('/api/statistics')
def get_statistics():
    """API para obtener estadísticas"""
    wifi_manager.load_latest_data()
    stats = wifi_manager.get_statistics()

    return jsonify({
        'success': True,
        'statistics': stats
    })

@app.route('/api/reload')
def reload_data():
    """API para recargar los datos manualmente"""
    success = wifi_manager.load_latest_data()
    return jsonify({
        'success': success,
        'message': 'Datos recargados correctamente' if success else 'Error recargando datos'
    })

if __name__ == '__main__':
    print("🚀 Iniciando servidor GenieACS WiFi Manager...")
    print("📊 Funcionalidades disponibles:")
    print("   • Visualizar SSIDs y contraseñas")
    print("   • Editar SSIDs en tiempo real")
    print("   • Cambiar contraseñas WiFi")
    print("   • Buscar por número de serie")
    print("📡 Accede a http://localhost:5000 para la interfaz")
    app.run(debug=True, host='0.0.0.0', port=5000)
