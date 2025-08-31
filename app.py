
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import requests
import json
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# Configuración de GenieACS
GENIEACS_URL = "http://192.168.0.237:7557"
USERNAME = "admin"
PASSWORD = "admin"

# Cache de dispositivos
devices_cache = []
last_update = None

# Configuración de parámetros por Product Class
DEVICE_PARAMETERS = {
    "HG114XT30": {
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "F6600R": {
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "ONT-2GF-V-RFDW": {
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "ONT-2GF-V-RFW": {
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "ONT-4GE-V-USB-RFDW": {
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "HG114AT": {
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.PreSharedKey"
        },
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.MACAddress"
    },
    "IGD": {
        "wifi_2_4": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "wifi_5": {
            "ssid": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.SSID",
            "password": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.PreSharedKey"
        },
        "ip": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ExternalIPAddress",
        "mac": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.MACAddress"
    }
}

def load_devices_from_json():
    """Cargar dispositivos desde el archivo JSON más reciente"""
    global devices_cache, last_update

    try:
        # Buscar el archivo JSON más reciente
        json_files = [f for f in os.listdir('.') if f.startswith('genieacs_devices_') and f.endswith('.json')]

        if not json_files:
            return []

        # Ordenar por fecha de modificación
        json_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        latest_file = json_files[0]

        # Cargar el archivo
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            devices_cache = data.get('devices', [])
            last_update = datetime.now()

        return devices_cache
    except Exception as e:
        print(f"Error cargando dispositivos: {e}")
        return []

def send_genieacs_task(device_serial, parameter, value):
    """Enviar tarea a GenieACS para cambiar parámetro"""
    try:
        url = f"{GENIEACS_URL}/tasks"

        # Crear la tarea
        task = {
            "name": "setParameterValues",
            "parameterValues": [[parameter, value, "xsd:string"]]
        }

        params = {
            "connection_request": "",
            "device": device_serial
        }

        response = requests.post(
            url, 
            json=task, 
            params=params,
            auth=(USERNAME, PASSWORD) if USERNAME else None
        )

        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error enviando tarea a GenieACS: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """Obtener todos los dispositivos WiFi"""
    devices = load_devices_from_json()

    return jsonify({
        "success": True,
        "devices": devices,
        "total": len(devices),
        "last_update": last_update.isoformat() if last_update else None
    })

@app.route('/api/search')
def search_devices():
    """Buscar dispositivos por número de serie"""
    query = request.args.get('serial', '').lower()
    devices = load_devices_from_json()

    if not query:
        filtered_devices = devices
    else:
        filtered_devices = [
            device for device in devices 
            if query in device.get('serial_number', '').lower()
        ]

    return jsonify({
        "success": True,
        "devices": filtered_devices,
        "total": len(filtered_devices),
        "query": query
    })

@app.route('/api/device/<device_serial>')
def get_device_details(device_serial):
    """Obtener detalles completos de un dispositivo específico"""
    devices = load_devices_from_json()

    device = next((d for d in devices if d['serial_number'] == device_serial), None)

    if not device:
        return jsonify({"success": False, "message": "Dispositivo no encontrado"})

    return jsonify({
        "success": True,
        "device": device
    })

@app.route('/api/device/<device_serial>/wifi/<band>/ssid', methods=['PUT'])
def update_ssid(device_serial, band):
    """Actualizar SSID de una red específica"""
    data = request.get_json()
    new_ssid = data.get('ssid', '').strip()

    if not new_ssid:
        return jsonify({"success": False, "message": "SSID no puede estar vacío"})

    if len(new_ssid) > 32:
        return jsonify({"success": False, "message": "SSID no puede tener más de 32 caracteres"})

    # Buscar el dispositivo
    devices = load_devices_from_json()
    device = next((d for d in devices if d['serial_number'] == device_serial), None)

    if not device:
        return jsonify({"success": False, "message": "Dispositivo no encontrado"})

    # Buscar la red específica
    network = next((net for net in device['wifi_networks'] if net['band'] == band), None)

    if not network:
        return jsonify({"success": False, "message": f"Red {band} no encontrada"})

    # Obtener parámetro correcto
    ssid_parameter = network['ssid_parameter']

    # Enviar cambio a GenieACS
    if send_genieacs_task(device_serial, ssid_parameter, new_ssid):
        return jsonify({
            "success": True, 
            "message": f"SSID actualizado a '{new_ssid}'",
            "old_ssid": network['ssid'],
            "new_ssid": new_ssid
        })
    else:
        return jsonify({"success": False, "message": "Error comunicándose con GenieACS"})

@app.route('/api/device/<device_serial>/wifi/<band>/password', methods=['PUT'])
def update_password(device_serial, band):
    """Actualizar contraseña de una red específica"""
    data = request.get_json()
    new_password = data.get('password', '').strip()

    if new_password and (len(new_password) < 8 or len(new_password) > 63):
        return jsonify({"success": False, "message": "La contraseña debe tener entre 8 y 63 caracteres"})

    # Buscar dispositivo
    devices = load_devices_from_json()
    device = next((d for d in devices if d['serial_number'] == device_serial), None)

    if not device:
        return jsonify({"success": False, "message": "Dispositivo no encontrado"})

    # Buscar red específica
    network = next((net for net in device['wifi_networks'] if net['band'] == band), None)

    if not network:
        return jsonify({"success": False, "message": f"Red {band} no encontrada"})

    # Obtener parámetro correcto
    password_parameter = network['password_parameter']

    # Enviar cambio a GenieACS
    if send_genieacs_task(device_serial, password_parameter, new_password):
        message = "Contraseña actualizada correctamente" if new_password else "Contraseña eliminada - Red abierta"
        return jsonify({
            "success": True,
            "message": message,
            "has_password": bool(new_password)
        })
    else:
        return jsonify({"success": False, "message": "Error comunicándose con GenieACS"})

@app.route('/api/statistics')
def get_statistics():
    """Obtener estadísticas del sistema"""
    devices = load_devices_from_json()

    total_devices = len(devices)
    devices_with_wifi = len([d for d in devices if d.get('wifi_networks')])
    devices_with_passwords = len([
        d for d in devices 
        if any(net.get('password') for net in d.get('wifi_networks', []))
    ])
    total_networks = sum(len(d.get('wifi_networks', [])) for d in devices)

    return jsonify({
        "success": True,
        "statistics": {
            "total_devices": total_devices,
            "devices_with_wifi": devices_with_wifi,
            "devices_with_passwords": devices_with_passwords,
            "total_wifi_networks": total_networks
        }
    })

@app.route('/api/reload', methods=['POST'])
def reload_data():
    """Recargar datos desde GenieACS"""
    global devices_cache, last_update

    try:
        # Aquí podrías ejecutar el script de extracción
        # Por ahora, solo recargamos desde el archivo JSON
        devices_cache = load_devices_from_json()
        last_update = datetime.now()

        return jsonify({
            "success": True,
            "message": "Datos recargados correctamente",
            "total_devices": len(devices_cache)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error recargando datos: {str(e)}"
        })

if __name__ == '__main__':
    # Cargar datos iniciales
    print("🚀 Iniciando GenieACS WiFi Manager...")
    load_devices_from_json()
    print(f"📊 Cargados {len(devices_cache)} dispositivos con WiFi")
    print("🌐 Servidor disponible en http://localhost:5000")

    app.run(host='0.0.0.0', port=5000, debug=True)
