
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import requests
import json
import os
from datetime import datetime
from urllib.parse import unquote, quote
import logging

# Configuración
app = Flask(__name__)
CORS(app)

# ⚠️ CAMBIAR ESTAS CREDENCIALES POR LAS TUYAS
GENIEACS_URL = "http://192.168.0.237:7557"
GENIEACS_USERNAME = "admin"
GENIEACS_PASSWORD = "admin"

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Variables globales
wifi_devices = []
last_load_time = None

def load_wifi_devices():
    """Cargar dispositivos WiFi desde el JSON generado"""
    global wifi_devices, last_load_time
    
    # Buscar el archivo JSON más reciente
    json_files = [f for f in os.listdir('.') if f.startswith('wifi_devices_filtered_') and f.endswith('.json')]
    
    if not json_files:
        logger.warning("No se encontró archivo JSON de dispositivos WiFi")
        return False
    
    # Obtener el archivo más reciente
    latest_file = max(json_files, key=os.path.getctime)
    
    try:
        with open(latest_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            wifi_devices = data.get('devices', [])
            last_load_time = datetime.now()
            logger.info(f"✅ Cargados {len(wifi_devices)} dispositivos desde {latest_file}")
            return True
    except Exception as e:
        logger.error(f"❌ Error cargando dispositivos: {e}")
        return False

def send_task_to_genieacs_correct_api(device_serial, parameter_name, parameter_value):
    """Enviar tarea a GenieACS usando la API CORRECTA"""
    try:
        logger.info(f"🔧 Enviando tarea para {device_serial}")
        logger.info(f"📝 Parámetro: {parameter_name} = {parameter_value}")
        
        # API CORRECTA: POST /devices/{deviceId}/tasks
        device_id_encoded = quote(device_serial, safe='')
        task_url = f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks"
        
        # Estructura de tarea correcta para GenieACS
        task_data = {
            "name": "setParameterValues",
            "parameterValues": [
                [parameter_name, parameter_value, "xsd:string"]
            ]
        }
        
        # Headers
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Autenticación
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        
        logger.info(f"📤 API CORRECTA - Enviando tarea a: {task_url}")
        logger.info(f"📋 Estructura: {json.dumps(task_data, indent=2)}")
        
        # Enviar tarea con API correcta
        response = requests.post(
            task_url,
            json=task_data,
            headers=headers,
            auth=auth,
            timeout=10
        )
        
        logger.info(f"📋 Respuesta API: {response.status_code}")
        logger.info(f"📄 Respuesta texto: {response.text[:200]}")
        
        if response.status_code in [200, 201, 202]:
            logger.info("✅ Tarea creada exitosamente con API correcta")
            
            # Intentar connection request
            return send_connection_request_correct(device_serial)
        else:
            logger.error(f"❌ Error API correcta: {response.status_code} - {response.text}")
            
            # Intentar método alternativo
            return try_alternative_api(device_serial, parameter_name, parameter_value)
            
    except Exception as e:
        logger.error(f"❌ Excepción API correcta: {e}")
        return try_alternative_api(device_serial, parameter_name, parameter_value)

def try_alternative_api(device_serial, parameter_name, parameter_value):
    """Intentar API alternativa de GenieACS"""
    try:
        logger.info("🔄 Intentando API alternativa...")
        
        # Método 1: PUT directo al dispositivo
        device_id_encoded = quote(device_serial, safe='')
        device_url = f"{GENIEACS_URL}/devices/{device_id_encoded}"
        
        # Estructura para PUT directo
        device_data = {
            parameter_name: {
                "_value": parameter_value,
                "_writable": True
            }
        }
        
        headers = {'Content-Type': 'application/json'}
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        
        logger.info(f"📤 API Alternativa 1 - PUT a: {device_url}")
        
        response = requests.put(
            device_url,
            json=device_data,
            headers=headers,
            auth=auth,
            timeout=10
        )
        
        logger.info(f"📋 PUT Response: {response.status_code}")
        
        if response.status_code in [200, 201, 202, 204]:
            logger.info("✅ PUT directo exitoso")
            return send_connection_request_correct(device_serial)
        
        # Método 2: POST a /tasks global
        logger.info("🔄 Intentando POST /tasks global...")
        
        global_task_url = f"{GENIEACS_URL}/tasks"
        global_task_data = {
            "device": device_serial,
            "name": "setParameterValues",
            "parameterValues": [
                [parameter_name, parameter_value, "xsd:string"]
            ]
        }
        
        logger.info(f"📤 API Alternativa 2 - POST a: {global_task_url}")
        
        response = requests.post(
            global_task_url,
            json=global_task_data,
            headers=headers,
            auth=auth,
            timeout=10
        )
        
        logger.info(f"📋 Global Task Response: {response.status_code}")
        
        if response.status_code in [200, 201, 202]:
            logger.info("✅ Tarea global exitosa")
            return send_connection_request_correct(device_serial)
        
        return False, f"Todas las APIs fallaron. Último error: {response.status_code}"
        
    except Exception as e:
        logger.error(f"❌ Error en APIs alternativas: {e}")
        return False, str(e)

def send_connection_request_correct(device_serial):
    """Enviar connection request con API correcta"""
    try:
        device_id_encoded = quote(device_serial, safe='')
        
        # Método 1: Connection request específico
        cr_urls = [
            f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks?connection_request",
            f"{GENIEACS_URL}/devices/{device_id_encoded}/connection_request",
            f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks",
        ]
        
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        
        for i, cr_url in enumerate(cr_urls):
            try:
                logger.info(f"📞 Connection Request {i+1}: {cr_url}")
                
                # Intentar POST primero
                response = requests.post(cr_url, auth=auth, timeout=5)
                logger.info(f"📞 POST Response {i+1}: {response.status_code}")
                
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"✅ Connection request {i+1} exitoso")
                    return True, "Tarea creada y connection request enviado"
                
                # Si POST falla, intentar GET
                response = requests.get(cr_url, auth=auth, timeout=5)
                logger.info(f"📞 GET Response {i+1}: {response.status_code}")
                
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"✅ Connection request {i+1} exitoso (GET)")
                    return True, "Tarea creada y connection request enviado (GET)"
            except Exception as e:
                logger.warning(f"⚠️ Connection request {i+1} falló: {e}")
                continue
        
        # Si todos fallan, la tarea al menos se creó
        logger.info("⚠️ Tarea creada pero connection request falló")
        return True, "Tarea creada exitosamente. Usar botón COMMIT para aplicar cambios."
        
    except Exception as e:
        logger.error(f"❌ Error total en connection request: {e}")
        return True, "Tarea creada. Error en connection request - usar botón COMMIT."

def commit_tasks():
    """Enviar commit usando múltiples métodos"""
    try:
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        
        # Métodos de commit a probar
        commit_methods = [
            ('POST', f"{GENIEACS_URL}/commit", {}),
            ('GET', f"{GENIEACS_URL}/commit", {}),
            ('POST', f"{GENIEACS_URL}/tasks/commit", {}),
            ('POST', f"{GENIEACS_URL}/commit", {'action': 'commit'}),
        ]
        
        for method, url, data in commit_methods:
            try:
                logger.info(f"📤 Intentando commit: {method} {url}")
                
                if method == 'POST':
                    response = requests.post(url, json=data, auth=auth, timeout=10)
                else:
                    response = requests.get(url, auth=auth, timeout=10)
                
                logger.info(f"📋 Commit response: {response.status_code}")
                
                if response.status_code in [200, 201, 202, 204]:
                    logger.info("✅ Commit exitoso")
                    return True, "Tareas aplicadas exitosamente"
                    
            except Exception as e:
                logger.warning(f"Método commit falló: {e}")
                continue
        
        return False, "Error enviando commit - verificar GenieACS"
        
    except Exception as e:
        logger.error(f"❌ Error en commit: {e}")
        return False, str(e)

# Rutas de la aplicación
@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """Obtener lista de dispositivos WiFi"""
    try:
        return jsonify({
            'success': True,
            'devices': wifi_devices,
            'total': len(wifi_devices),
            'last_update': last_load_time.isoformat() if last_load_time else None
        })
    except Exception as e:
        logger.error(f"Error obteniendo dispositivos: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/search')
def search_devices():
    """Buscar dispositivos por número de serie"""
    try:
        serial_query = request.args.get('serial', '').lower()
        
        if not serial_query:
            filtered_devices = wifi_devices
        else:
            filtered_devices = [
                device for device in wifi_devices 
                if serial_query in device.get('serial_number', '').lower()
            ]
        
        return jsonify({
            'success': True,
            'devices': filtered_devices,
            'total': len(filtered_devices)
        })
    except Exception as e:
        logger.error(f"Error en búsqueda: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """Obtener estadísticas generales"""
    try:
        total_devices = len(wifi_devices)
        devices_with_wifi = len([d for d in wifi_devices if d.get('wifi_networks')])
        devices_with_passwords = len([
            d for d in wifi_devices 
            for network in d.get('wifi_networks', []) 
            if network.get('password')
        ])
        total_networks = sum(len(d.get('wifi_networks', [])) for d in wifi_devices)
        
        return jsonify({
            'success': True,
            'statistics': {
                'total_devices': total_devices,
                'devices_with_wifi': devices_with_wifi,
                'devices_with_passwords': devices_with_passwords,
                'total_wifi_networks': total_networks
            }
        })
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/device/<device_serial>/wifi/<band>/ssid', methods=['PUT'])
def update_ssid(device_serial, band):
    """Actualizar SSID de una red WiFi"""
    try:
        data = request.get_json()
        new_ssid = data.get('ssid', '').strip()
        
        if not new_ssid:
            return jsonify({'success': False, 'message': 'SSID no puede estar vacío'}), 400
        
        if len(new_ssid) > 32:
            return jsonify({'success': False, 'message': 'SSID no puede tener más de 32 caracteres'}), 400
        
        # Buscar el dispositivo
        device = next((d for d in wifi_devices if d['serial_number'] == device_serial), None)
        if not device:
            return jsonify({'success': False, 'message': 'Dispositivo no encontrado'}), 404
        
        # Buscar la red específica
        network = next((n for n in device.get('wifi_networks', []) if n['band'] == band), None)
        if not network:
            return jsonify({'success': False, 'message': 'Red WiFi no encontrada'}), 404
        
        # Obtener el parámetro correcto para el SSID
        ssid_parameter = network['parameter_paths']['ssid']
        
        logger.info(f"🔧 Actualizando SSID para {device_serial}")
        logger.info(f"📝 Banda: {band}, Nuevo SSID: {new_ssid}")
        logger.info(f"📋 Parámetro: {ssid_parameter}")
        
        # Enviar tarea a GenieACS con API CORRECTA
        success, message = send_task_to_genieacs_correct_api(device_serial, ssid_parameter, new_ssid)
        
        if success:
            # Actualizar datos locales
            network['ssid'] = new_ssid
            logger.info("✅ SSID actualizado exitosamente")
            
            return jsonify({
                'success': True,
                'message': message,
                'new_ssid': new_ssid
            })
        else:
            return jsonify({'success': False, 'message': message}), 500
            
    except Exception as e:
        logger.error(f"❌ Error actualizando SSID: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/device/<device_serial>/wifi/<band>/password', methods=['PUT'])
def update_password(device_serial, band):
    """Actualizar contraseña de una red WiFi"""
    try:
        data = request.get_json()
        new_password = data.get('password', '').strip()
        
        if new_password and (len(new_password) < 8 or len(new_password) > 63):
            return jsonify({'success': False, 'message': 'Contraseña debe tener entre 8 y 63 caracteres'}), 400
        
        # Buscar el dispositivo
        device = next((d for d in wifi_devices if d['serial_number'] == device_serial), None)
        if not device:
            return jsonify({'success': False, 'message': 'Dispositivo no encontrado'}), 404
        
        # Buscar la red específica
        network = next((n for n in device.get('wifi_networks', []) if n['band'] == band), None)
        if not network:
            return jsonify({'success': False, 'message': 'Red WiFi no encontrada'}), 404
        
        # Obtener el parámetro correcto para la contraseña
        password_parameter = network['parameter_paths']['password']
        
        logger.info(f"🔧 Actualizando contraseña para {device_serial}")
        logger.info(f"📝 Banda: {band}, Nueva contraseña: {'[OCULTA]' if new_password else '[VACÍA]'}")
        logger.info(f"📋 Parámetro: {password_parameter}")
        
        # Enviar tarea a GenieACS con API CORRECTA
        success, message = send_task_to_genieacs_correct_api(device_serial, password_parameter, new_password)
        
        if success:
            # Actualizar datos locales
            network['password'] = new_password
            logger.info("✅ Contraseña actualizada exitosamente")
            
            return jsonify({
                'success': True,
                'message': message,
                'has_password': bool(new_password)
            })
        else:
            return jsonify({'success': False, 'message': message}), 500
            
    except Exception as e:
        logger.error(f"❌ Error actualizando contraseña: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/commit-tasks', methods=['POST'])
def commit_tasks_endpoint():
    """Aplicar todas las tareas pendientes en GenieACS"""
    try:
        logger.info("🔄 Ejecutando commit de tareas...")
        success, message = commit_tasks()
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 500
            
    except Exception as e:
        logger.error(f"❌ Error en commit: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
def refresh_data():
    """Recargar datos desde GenieACS"""
    try:
        logger.info("🔄 Recargando datos...")
        success = load_wifi_devices()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Datos recargados correctamente',
                'total_devices': len(wifi_devices)
            })
        else:
            return jsonify({'success': False, 'message': 'Error recargando datos'}), 500
            
    except Exception as e:
        logger.error(f"❌ Error recargando datos: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Iniciando GenieACS WiFi Manager...")
    print(f"📡 Servidor GenieACS: {GENIEACS_URL}")
    print("🔧 API CORREGIDA: POST /devices/{deviceId}/tasks")
    
    # Cargar dispositivos al inicio
    if load_wifi_devices():
        total_networks = sum(len(d.get('wifi_networks', [])) for d in wifi_devices)
        product_classes = set(d.get('product_class') for d in wifi_devices if d.get('product_class'))
        
        print(f"📊 Cargados {len(wifi_devices)} dispositivos con WiFi")
        print(f"🔧 Product Classes: {len(product_classes)} tipos")
        print(f"📶 Redes WiFi totales: {total_networks}")
    else:
        print("⚠️ No se pudieron cargar dispositivos WiFi")
        print("💡 Ejecuta primero: python genieacs-api-improved.py")
    
    print(f"\n🌐 Servidor disponible en: http://localhost:5000")
    print("✅ Sistema listo para usar!")
    print("\n🔥 CAMBIOS IMPLEMENTADOS:")
    print("   • API CORRECTA de GenieACS")
    print("   • Múltiples métodos de respaldo")
    print("   • Logs detallados para debugging")
    print("   • Todos los Product Classes del Excel")
    print("\n⚠️ IMPORTANTE: Hacer COMMIT después de cambios!")
    
    # Ejecutar servidor
    app.run(debug=True, host='0.0.0.0', port=5000)