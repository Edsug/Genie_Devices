
from flask import Flask, abort, jsonify, request, render_template, redirect, url_for, session, send_from_directory, g
from flask_cors import CORS
import requests
import json
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote, quote
import logging
import hashlib
from functools import wraps
import re
from werkzeug.utils import secure_filename
from csv_processor import CSVProcessor

# Importar modelos y servicios corregidos
from config_db import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS, SQLALCHEMY_ENGINE_OPTIONS
# Nota: Debes renombrar estos archivos sin _fixed cuando los uses
from models import db, User, Device, CustomerInfo, WifiNetwork, ChangeHistory, CSVImportHistory
from db_services import DatabaseService
from csv_processor import CSVProcessor



# Configuración de la aplicación
app = Flask(
    __name__,
    static_folder='static',
    static_url_path='/static',
    template_folder='templates'
)

CORS(app)
app.secret_key = 'tu_clave_secreta_super_segura_aqui_cambiala'

# Configurar base de datos MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = SQLALCHEMY_ENGINE_OPTIONS

# Configuración para upload de archivos
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {'csv'}

# Crear carpetas necesarias
for folder in ['uploads', 'data', 'logs', 'backups']:
    os.makedirs(folder, exist_ok=True)

# Inicializar extensiones
db.init_app(app)



# CREDENCIALES GENIEACS
GENIEACS_URL = "http://192.168.0.237:7557"
GENIEACS_USERNAME = "admin"
GENIEACS_PASSWORD = "admin"

app.config['GENIEACS_URL'] = GENIEACS_URL
# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CACHE GLOBAL OPTIMIZADO - 5 MINUTOS
device_cache = {}
cache_timestamp = 0
CACHE_DURATION = 300  # 5 minutos para mejor rendimiento

# CONFIGURACIÓN DE PAGINACIÓN
DEVICES_PER_PAGE = 20

# Roles del sistema
USER_ROLES = {
    'noc': {'name': 'NOC', 'level': 3, 'description': 'Superadmin - Acceso completo'},
    'informatica': {'name': 'Informática', 'level': 2, 'description': 'Admin - Gestión de dispositivos'},
    'callcenter': {'name': 'Call Center', 'level': 1, 'description': 'Operador - Consulta y cambios básicos'}
}

# BASE DE CONOCIMIENTO del Excel ParametrosGenieACS.xlsx
DEVICE_KNOWLEDGE_BASE = {
    "HG114XT30": {
        "2.4GHz": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "5",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "F6600R": {
        "2.4GHz": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "5",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "ONT-2GF-V-RFDW": {
        "2.4GHz": {
            "wlan_config": "5",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "IGD": {
        "2.4GHz_primary": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "5GHz_primary": {
            "wlan_config": "5",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.MACAddress"
    }
}

def allowed_file(filename):
    """Verificar si el archivo tiene extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_ssid(ssid):
    """Verificar si el SSID es válido"""
    if not ssid or not ssid.strip():
        return False
    ssid = ssid.strip()
    # Filtrar SSIDs obviamente inválidos
    invalid_patterns = [
        r'^[\*\.\-_]+$',  # Solo caracteres especiales
        r'^\s*$',  # Solo espacios
        r'^[0-9A-Fa-f]{32}$',  # Hash MD5
        r'^[0-9A-Fa-f]{64}$',  # Hash SHA256
        'default', 'hidden'
    ]
    
    for pattern in invalid_patterns:
        if re.match(pattern, ssid):
            return False
    return 1 <= len(ssid) <= 32

def is_valid_password(password):
    """Verificar si la contraseña es válida"""
    if not password:
        return False
    password = password.strip()
    if not password:
        return False
    # Filtrar contraseñas obviamente inválidas
    invalid_patterns = [
        r'^[\*\.\-_\s]+$',  # Solo caracteres especiales y espacios
        r'^[0-9A-Fa-f]{32}$',  # Hash MD5
        r'^[0-9A-Fa-f]{64}$',  # Hash SHA256
        r'^\$[0-9]\$.*',  # Hash bcrypt
    ]
    
    for pattern in invalid_patterns:
        if re.match(pattern, password):
            return False
    return 8 <= len(password) <= 63

# Decoradores de autenticación
def login_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Autenticación requerida', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(min_level):
    """Decorador para requerir nivel mínimo de rol"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'success': False, 'message': 'Autenticación requerida'}), 401
                return redirect(url_for('login'))
            
            user_role = session.get('role', 'callcenter')
            user_level = USER_ROLES.get(user_role, {'level': 0})['level']
            
            if user_level < min_level:
                if request.is_json:
                    return jsonify({'success': False, 'message': 'Permisos insuficientes'}), 403
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Obtener usuario actual de la sesión"""
    if 'user_id' in session:
        user = DatabaseService.get_user_by_id(session['user_id'])
        if user:
            role_info = USER_ROLES.get(user.role, USER_ROLES['callcenter'])
            return {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'role_name': role_info['name'],
                'role_level': role_info['level']
            }
    return None



# Funciones de GenieACS OPTIMIZADAS
def get_devices_from_genieacs():
    """Obtener dispositivos desde GenieACS API con timeout optimizado"""
    try:
        url = f"{GENIEACS_URL}/devices"
        response = requests.get(
            url,
            auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None,
            timeout=15  # Reducido para mejor rendimiento
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Error conectando a GenieACS: {e}")
        return []

def safe_get_value(data, path):
    """Obtener valor de forma segura desde estructura anidada"""
    try:
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return ""
        if isinstance(current, dict) and '_value' in current:
            return str(current['_value'])
        elif isinstance(current, dict):
            return ""
        return str(current) if current is not None else ""
    except:
        return ""

def extract_device_info(device):
    """Extraer información básica del dispositivo"""
    serial_number = unquote(device.get("_id", ""))
    igw = device.get('InternetGatewayDevice', {})
    device_info = igw.get('DeviceInfo', {})
    
    # Product Class
    product_class = ""
    if '_deviceId' in device and isinstance(device['_deviceId'], dict):
        product_class = device['_deviceId'].get('_ProductClass', '')
    if not product_class:
        product_class = safe_get_value(device_info, ['ProductClass'])
    
    # Otros datos básicos
    software_version = safe_get_value(device_info, ['SoftwareVersion'])
    hardware_version = safe_get_value(device_info, ['HardwareVersion'])
    
    # Last inform simplificado
    last_inform = ""
    if '_lastInform' in device:
        try:
            timestamp = device['_lastInform']
            if isinstance(timestamp, (int, float)) and timestamp > 0:
                dt = datetime.fromtimestamp(timestamp / 1000)
                last_inform = dt.strftime("%d/%m/%Y %H:%M")
        except:
            pass
    
    # Tags simplificado
    tags = []
    if '_tags' in device:
        tags_data = device['_tags']
        if isinstance(tags_data, dict):
            tags = list(tags_data.keys())[:3]
        elif isinstance(tags_data, list):
            tags = tags_data[:3]
    
    return {
        "serial_number": serial_number,
        "product_class": product_class,
        "software_version": software_version,
        "hardware_version": hardware_version,
        "last_inform": last_inform,
        "tags": tags,
        "raw_device": device
    }

def extract_wifi_networks(device_info):
    """Extraer redes WiFi optimizado"""
    device = device_info["raw_device"]
    igw = device.get('InternetGatewayDevice', {})
    product_class = device_info["product_class"]
    serial_number = device_info["serial_number"]
    
    if product_class not in DEVICE_KNOWLEDGE_BASE:
        return [], "", "", []
    
    # Extraer IP y MAC
    ip, mac = extract_ip_mac_for_product_class(igw, product_class)
    if not ip or ip == "0.0.0.0":
        return [], ip, mac, []
    
    # Buscar WLANConfigurations
    wlan_configs = igw.get('LANDevice', {}).get('1', {}).get('WLANConfiguration', {})
    if not wlan_configs:
        return [], ip, mac, []
    
    # Extraer redes
    networks = extract_networks_by_knowledge(wlan_configs, product_class, serial_number)
    
    # Filtrar redes válidas
    valid_networks = []
    for network in networks:
        if is_valid_ssid(network['ssid']):
            if not is_valid_password(network['password']):
                network['password'] = ""
            valid_networks.append(network)
    
    return valid_networks, ip, mac, []

def extract_ip_mac_for_product_class(igw, product_class):
    """Extraer IP/MAC usando configuración específica"""
    config = DEVICE_KNOWLEDGE_BASE[product_class]
    ip_path = config["ip_param"].split('.')[1:]
    mac_path = config["mac_param"].split('.')[1:]
    
    ip = safe_get_value(igw, ip_path)
    mac = safe_get_value(igw, mac_path)
    
    return ip, mac

def extract_networks_by_knowledge(wlan_configs, product_class, serial_number):
    """Extraer redes usando base de conocimiento"""
    networks = []
    config = DEVICE_KNOWLEDGE_BASE[product_class]
    
    if product_class == "IGD":
        networks = extract_igd_networks(wlan_configs, config, serial_number)
    else:
        networks = extract_standard_networks(wlan_configs, config, product_class, serial_number)
    
    # Asegurar máximo 2 redes (una de cada banda)
    final_networks = []
    has_2_4 = False
    has_5 = False
    
    for network in networks:
        if network['band'] == '2.4GHz' and not has_2_4:
            final_networks.append(network)
            has_2_4 = True
        elif network['band'] == '5GHz' and not has_5:
            final_networks.append(network)
            has_5 = True
        
        if has_2_4 and has_5:
            break
    
    return final_networks

def extract_standard_networks(wlan_configs, config, product_class, serial_number):
    """Extraer redes para Product Classes estándar"""
    networks = []
    
    for band in ["2.4GHz", "5GHz"]:
        if band not in config:
            continue
        
        band_config = config[band]
        wlan_index = band_config["wlan_config"]
        
        if wlan_index in wlan_configs:
            wlan_config = wlan_configs[wlan_index]
            ssid = safe_get_value(wlan_config, ['SSID'])
            
            if ssid and ssid.strip():
                password = extract_password(wlan_config, band_config)
                network = {
                    "band": band,
                    "ssid": ssid,
                    "password": password,
                    "is_primary": (band == "5GHz"),
                    "wlan_configuration": wlan_index,
                    "parameter_paths": {
                        "ssid": band_config["ssid_param"],
                        "password": band_config["password_param"]
                    }
                }
                networks.append(network)
    
    return networks

def extract_igd_networks(wlan_configs, config, serial_number):
    """Extraer redes para dispositivos IGD"""
    networks = []
    
    # Intentar 2.4GHz
    for band_key in ["2.4GHz_primary", "2.4GHz_alt"]:
        if band_key in config:
            band_config = config[band_key]
            wlan_index = band_config["wlan_config"]
            
            if wlan_index in wlan_configs:
                wlan_config = wlan_configs[wlan_index]
                ssid = safe_get_value(wlan_config, ['SSID'])
                
                if ssid and ssid.strip():
                    if is_24ghz_network(ssid, wlan_index):
                        password = extract_password(wlan_config, band_config)
                        network = {
                            "band": "2.4GHz",
                            "ssid": ssid,
                            "password": password,
                            "is_primary": False,
                            "wlan_configuration": wlan_index,
                            "parameter_paths": {
                                "ssid": band_config["ssid_param"],
                                "password": band_config["password_param"]
                            }
                        }
                        networks.append(network)
                        break
    
    # Intentar 5GHz
    for band_key in ["5GHz_primary", "5GHz_alt"]:
        if band_key in config:
            band_config = config[band_key]
            wlan_index = band_config["wlan_config"]
            
            if wlan_index in wlan_configs:
                wlan_config = wlan_configs[wlan_index]
                ssid = safe_get_value(wlan_config, ['SSID'])
                
                if ssid and ssid.strip():
                    if is_5ghz_network(ssid, wlan_index):
                        password = extract_password(wlan_config, band_config)
                        network = {
                            "band": "5GHz",
                            "ssid": ssid,
                            "password": password,
                            "is_primary": True,
                            "wlan_configuration": wlan_index,
                            "parameter_paths": {
                                "ssid": band_config["ssid_param"],
                                "password": band_config["password_param"]
                            }
                        }
                        networks.append(network)
                        break
    
    return networks

def extract_password(wlan_config, band_config):
    """Extraer contraseña usando múltiples métodos"""
    # Intentar KeyPassphrase
    password = safe_get_value(wlan_config, ['KeyPassphrase'])
    if password:
        return password
    
    # Intentar PreSharedKey
    password = safe_get_value(wlan_config, ['PreSharedKey'])
    if password:
        return password
    
    # Buscar en objetos PreSharedKey
    psk_obj = wlan_config.get('PreSharedKey', {})
    if isinstance(psk_obj, dict):
        for key, value in psk_obj.items():
            if key != '_object' and isinstance(value, dict):
                psk_value = safe_get_value(value, ['Value'])
                if psk_value:
                    return psk_value
    
    return ""

def is_24ghz_network(ssid, wlan_index):
    """Determinar si es red 2.4GHz"""
    ssid_lower = ssid.lower()
    if '2.4g' in ssid_lower or '2.4ghz' in ssid_lower:
        return True
    if '5g' in ssid_lower or '5ghz' in ssid_lower:
        return False
    return wlan_index == "1"

def is_5ghz_network(ssid, wlan_index):
    """Determinar si es red 5GHz"""
    ssid_lower = ssid.lower()
    if '5g' in ssid_lower or '5ghz' in ssid_lower:
        return True
    if '2.4g' in ssid_lower or '2.4ghz' in ssid_lower:
        return False
    return wlan_index in ["5", "6"]

def refresh_genie_object(serial_number, parameter_path):
    """Crea una tarea en GenieACS para refrescar un parámetro del dispositivo."""
    try:
        url = f"{GENIEACS_URL}/devices/{quote(serial_number)}/tasks"
        payload = {"name": "refreshObject", "objectName": parameter_path}
        response = requests.post(url, json=payload, auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD), timeout=5)
        if response.status_code == 200:
            logger.info(f"✅ Tarea 'refreshObject' para {serial_number} en '{parameter_path}' creada.")
            return True
    except Exception as e:
        logger.warning(f"⚠️ No se pudo crear la tarea 'refreshObject': {e}")
    return False

def paginate_devices(devices, page, per_page):
    """Función de paginación"""
    total = len(devices)
    start = (page - 1) * per_page
    end = start + per_page
    return {
        'devices': devices[start:end],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'has_prev': page > 1,
        'has_next': end < total,
        'prev_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if end < total else None
    }

last_sync_time = None
SYNC_INTERVAL = timedelta(minutes=10)
is_syncing_lock = threading.Lock()
initial_sync_started = False # Bandera para controlar la primera ejecución

def sync_devices_job():
    """
    Trabajo de sincronización que se ejecuta en segundo plano.
    """
    global last_sync_time
    
    if not is_syncing_lock.acquire(blocking=False):
        logger.info("Sync job: Sincronización ya en progreso. Omitiendo.")
        return

    logger.info("🔄 Iniciando trabajo de sincronización con GenieACS...")
    try:
        genie_url_base = app.config.get('GENIEACS_URL')
        if not genie_url_base:
            logger.error("❌ GENIEACS_URL no está configurada. Abortando.")
            return

        genie_api_url = f"{genie_url_base}/devices/"
        params = { "projection": "_id,DeviceID.ProductClass,InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress,InternetGatewayDevice.LANIPAddress,lastInform" }
        
        response = requests.get(genie_api_url, params=params, timeout=30)
        response.raise_for_status()
        all_devices_data = response.json()
        
        if all_devices_data:
            with app.app_context():
                new, updated = DatabaseService.sync_devices_in_bulk(all_devices_data)
            logger.info(f"✅ Sincronización completada: {new} nuevos, {updated} actualizados.")
            
            # --- ¡LA CORRECCIÓN DEL ERROR! ---
            # Usamos datetime.utcnow() que es compatible con tu versión de Python.
            last_sync_time = datetime.now(timezone.utc)

    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error de red al conectar con GenieACS: {e}")
    except Exception as e:
        logger.error(f"❌ Error mayor durante el trabajo de sincronización: {e}", exc_info=True)
    finally:
        is_syncing_lock.release()

@app.before_request
def check_and_init_sync():
    """
    Se ejecuta antes de CADA petición, pero la bandera previene ejecuciones múltiples.
    """
    global initial_sync_started
    if not initial_sync_started:
        logger.info("🚀 Primera carga de la aplicación detectada. Lanzando sincronización inicial.")
        threading.Thread(target=sync_devices_job).start()
        initial_sync_started = True

# --- RUTA PARA REFRESCAR MANUALMENTE (Opcional pero recomendado) ---
@app.route('/api/refresh-sync', methods=['POST'])
@login_required
def refresh_sync():
    """
    Una ruta que el frontend puede llamar para forzar una nueva sincronización.
    """
    if is_syncing_lock.locked():
        return jsonify({'success': False, 'message': 'La sincronización ya está en progreso.'}), 429
    
    logger.info(f"🔄 Solicitud de refresco manual recibida.")
    threading.Thread(target=sync_devices_job).start()
    return jsonify({'success': True, 'message': 'Se ha iniciado una nueva sincronización en segundo plano.'})

@app.route('/api/user/theme')
@login_required
def get_user_theme():
    """Obtener tema del usuario"""
    return jsonify({'success': True, 'theme': 'system'})

@app.route('/api/user/theme', methods=['POST'])
@login_required
def set_user_theme():
    """Establecer tema del usuario"""
    return jsonify({'success': True, 'message': 'Tema guardado'})

@app.route('/')
@login_required
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/api/devices')
@login_required
def get_devices():
    """OBTENER DISPOSITIVOS CON PAGINACIÓN Y FILTROS"""

    try:
        # Obtener todos los dispositivos de la BD
        all_devices = DatabaseService.get_all_devices_with_status()
        
        # Separar dispositivos configurados y no configurados
        configured_devices = [d for d in all_devices if d.get('configured', False)]
        unconfigured_devices = [d for d in all_devices if not d.get('configured', False)]

        # Obtener parámetros de paginación
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', DEVICES_PER_PAGE))
        filter_type = request.args.get('filter', 'all')
        search_query = request.args.get('search', '').strip().lower()

        # Aplicar filtros
        if filter_type == 'configured':
            filtered_devices = configured_devices
        elif filter_type == 'unconfigured':
            filtered_devices = unconfigured_devices
        else:
            filtered_devices = all_devices

        # Aplicar búsqueda si existe
        if search_query:
            filtered_devices = [
                d for d in filtered_devices
                if search_query in d.get('serial_number','').lower() or \
                   search_query in d.get('ip','').lower() or \
                   search_query in d.get('product_class','').lower() or \
                   search_query in (d.get('mac') or '').lower() or \
                   (d.get('contract_number') and search_query in d.get('contract_number').lower()) or \
                   (d.get('customer_name') and search_query in d.get('customer_name').lower())
            ]

        # Aplicar paginación
        pagination = paginate_devices(filtered_devices, page, per_page)
        
        return jsonify({
            'success': True,
            'devices': pagination['devices'],
            'pagination': {
                'page': pagination['page'],
                'per_page': pagination['per_page'],
                'pages': pagination['pages'],
                'total': pagination['total'],
                'has_prev': pagination['has_prev'],
                'has_next': pagination['has_next'],
                'prev_page': pagination['prev_page'],
                'next_page': pagination['next_page']
            },
            'counts': {
                'total': len(all_devices),
                'configured': len(configured_devices),
                'unconfigured': len(unconfigured_devices),
                'filtered': pagination['total']
            }
        })
    except Exception as e:
        logger.error(f"❌ Error obteniendo dispositivos desde la base de datos: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Error al cargar dispositivos desde la base de datos.'}), 500
# Reemplaza tu función get_device_info actual con esta versión corregida

@app.route('/api/device-info/<path:serial_number>')
@login_required
def get_device_info(serial_number):
    """Obtener info detallada, priorizando la base de datos local para la coherencia."""
    try:
        # Primero, obtén el dispositivo y sus redes de tu base de datos local
        device = DatabaseService.get_device_by_serial(serial_number)
        if not device:
            return jsonify({'success': False, 'message': 'Dispositivo no encontrado localmente'}), 404

        wifi_networks_local = WifiNetwork.query.filter_by(device_id=device.id).all()

        wifi_data = []
        for net in wifi_networks_local:
            wifi_data.append({
                "band": net.band,
                "ssid": net.ssid_configured or net.ssid_current, # Prioriza el SSID configurado
                "password": net.password or "No disponible" # <--- ¡AQUÍ ESTÁ LA SOLUCIÓN!
            })

        # Ensamblar la respuesta final con datos locales
        full_device_data = {
            'serial_number': device.serial_number,
            'mac_address': device.mac_address,
            'product_class': device.product_class,
            'software_version': device.software_version,
            'hardware_version': device.hardware_version,
            'ip_address': device.ip_address,
            'last_inform': device.last_inform,
            'tags': json.loads(device.tags) if device.tags else [],
            'wifi_networks': wifi_data
        }
        return jsonify({'success': True, 'device': full_device_data})

    except Exception as e:
        logger.error(f"❌ Error obteniendo info local del dispositivo {serial_number}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/devices/refresh', methods=['POST'])
@login_required
def refresh_devices():
    """Forzar actualización del cache"""
    global device_cache, cache_timestamp
    device_cache = {}
    cache_timestamp = 0
    logger.info("🔄 Cache limpiado manualmente")
    return get_devices()

# Reemplaza tu función update_ssid actual con esta
@app.route('/api/device/update-ssid', methods=['POST'])
@login_required
@role_required(2)
def update_ssid():
    data = request.get_json()
    serial_number = data.get('serial_number')
    new_ssid = data.get('ssid')
    band = data.get('band')
    user_id = session.get('user_id') # Obtener el ID del usuario de la sesión

    if not all([serial_number, new_ssid, band]):
        return jsonify({'success': False, 'message': 'Datos incompletos'}), 400

    # Actualizar la base de datos local INMEDIATAMENTE
    if not DatabaseService.update_device_ssid(serial_number, band, new_ssid, user_id):
        return jsonify({'success': False, 'message': 'Error al actualizar la base de datos local'}), 500

    # Después, enviar la tarea a GenieACS (si falla, el cambio local ya está hecho)
    try:
        product_class = DatabaseService.get_product_class_by_serial(serial_number)
        if product_class not in DEVICE_KNOWLEDGE_BASE:
            return jsonify({'success': True, 'message': 'Cambio guardado localmente, pero producto no soportado por GenieACS.'})

        band_config = DEVICE_KNOWLEDGE_BASE[product_class].get(band, {})
        ssid_param = band_config.get('ssid_param')

        if ssid_param:
            url = f"{GENIEACS_URL}/devices/{quote(serial_number)}/tasks"
            payload = {"name": "setParameterValues", "parameterValues": [[ssid_param, new_ssid, "xsd:string"]]}
            response = requests.post(url, json=payload, auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD), timeout=15)
            
            if response.status_code in [200, 202]:
                logger.info(f"Tarea de SSID para {serial_number} aceptada por GenieACS.")
                refresh_genie_object(serial_number, ssid_param)
            else:
                logger.warning(f"GenieACS rechazó tarea de SSID: {response.text}")
        
        # Limpiar caché para que la lista principal se actualice
        global device_cache, cache_timestamp
        device_cache = {}
        cache_timestamp = 0

        return jsonify({'success': True, 'message': 'Cambio guardado localmente y tarea enviada a GenieACS.'})
    except Exception as e:
        logger.error(f"Error enviando tarea de SSID a GenieACS para {serial_number}: {e}")
        return jsonify({'success': True, 'message': f'Cambio guardado localmente, pero falló el envío a GenieACS: {e}'})
    
@app.route('/api/device/update-password', methods=['POST'])
@login_required
@role_required(2)
def update_password():
    data = request.get_json()
    serial_number = data.get('serial_number')
    new_password = data.get('password')
    band = data.get('band')
    user_id = session.get('user_id')

    if not all([serial_number, new_password, band]):
        return jsonify({'success': False, 'message': 'Datos incompletos'}), 400
    
    if not is_valid_password(new_password):
        return jsonify({'success': False, 'message': 'Contraseña inválida'}), 400

    # Actualizar la base de datos local INMEDIATAMENTE
    if not DatabaseService.update_device_password(serial_number, band, new_password, user_id):
        return jsonify({'success': False, 'message': 'Error al actualizar la base de datos local'}), 500

    # Después, enviar la tarea a GenieACS
    try:
        product_class = DatabaseService.get_product_class_by_serial(serial_number)
        if product_class not in DEVICE_KNOWLEDGE_BASE:
            return jsonify({'success': True, 'message': 'Cambio guardado localmente, pero producto no soportado por GenieACS.'})

        band_config = DEVICE_KNOWLEDGE_BASE[product_class].get(band, {})
        password_param = band_config.get('password_param')
        
        if password_param:
            url = f"{GENIEACS_URL}/devices/{quote(serial_number)}/tasks"
            payload = {"name": "setParameterValues", "parameterValues": [[password_param, new_password, "xsd:string"]]}
            response = requests.post(url, json=payload, auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD), timeout=15)
            
            if response.status_code in [200, 202]:
                logger.info(f"Tarea de contraseña para {serial_number} aceptada por GenieACS.")
                refresh_genie_object(serial_number, password_param)
            else:
                logger.warning(f"GenieACS rechazó tarea de contraseña: {response.text}")
        
        global device_cache, cache_timestamp
        device_cache = {}
        cache_timestamp = 0

        return jsonify({'success': True, 'message': 'Cambio guardado localmente y tarea enviada a GenieACS.'})
    except Exception as e:
        logger.error(f"Error enviando tarea de contraseña a GenieACS para {serial_number}: {e}")
        return jsonify({'success': True, 'message': f'Cambio guardado localmente, pero falló el envío a GenieACS: {e}'})


# CORRECCIÓN: Cambiar la ruta de LAN hosts para evitar error 405
@app.route('/api/device/<serial_number>/lan-hosts', methods=['GET'])
@login_required
@role_required(1)  # NOC, Informática, Call Center pueden ver
def get_lan_hosts(serial_number):
    try:
        url = f"{GENIEACS_URL}/devices/{quote(serial_number)}"
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        response = requests.get(url, auth=auth, timeout=15)
        response.raise_for_status()
        
        device_data = response.json()
        
        # Extraer hosts LAN del dispositivo
        lan_hosts = []
        igw = device_data.get('InternetGatewayDevice', {})
        lan_device = igw.get('LANDevice', {}).get('1', {})
        hosts = lan_device.get('Hosts', {}).get('Host', {})
        
        if isinstance(hosts, dict):
            for host_id, host_data in hosts.items():
                if isinstance(host_data, dict) and host_id != '_object':
                    host_info = {
                        'id': host_id,
                        'ip_address': safe_get_value(host_data, ['IPAddress']),
                        'mac_address': safe_get_value(host_data, ['MACAddress']),
                        'hostname': safe_get_value(host_data, ['HostName']),
                        'interface_type': safe_get_value(host_data, ['InterfaceType']),
                        'active': safe_get_value(host_data, ['Active'])
                    }
                    lan_hosts.append(host_info)
        
        return jsonify({'success': True, 'lan_hosts': lan_hosts})
        
    except Exception as e:
        logger.error(f"Error obteniendo hosts LAN para {serial_number}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/csv/upload', methods=['POST'])
@login_required
@role_required(2)  # Solo NOC e Informática
def upload_csv():
    """
    Subir y procesar CSV unificado.
    Esta función recibe el archivo desde la UI y lo procesa.
    """
    # 1. Validar que el archivo viene en la solicitud
    if 'file' not in request.files:
        # Tu script.js original podría estar usando 'file' como clave, se ajusta aquí
        if 'csv_file' not in request.files:
            return jsonify({'success': False, 'message': 'No se encontró el archivo en la solicitud (clave: file o csv_file)'}), 400
        file = request.files['csv_file']
    else:
        file = request.files['file']

    # 2. Validar que se seleccionó un archivo
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No se seleccionó ningún archivo'}), 400

    # 3. Validar la extensión y procesar
    if file and file.filename.lower().endswith('.csv'):
        try:
            filename = secure_filename(file.filename)
            user_id = session.get('user_id')
            
            if not user_id:
                return jsonify({'success': False, 'message': 'Sesión de usuario no válida.'}), 401
            
            # Instanciar el procesador con los argumentos correctos
            processor = CSVProcessor(file_stream=file.stream, filename=filename, user_id=user_id)
            
            # El método .process() devuelve una tupla (respuesta_json, status_code)
            response, status_code = processor.process()
            return response, status_code

        except Exception as e:
            logger.error(f"❌ Error fatal durante la carga del CSV: {e}", exc_info=True)
            return jsonify({'success': False, 'message': 'Ocurrió un error inesperado en el servidor.'}), 500
    else:
        return jsonify({'success': False, 'message': 'Formato de archivo no válido. Por favor, sube un archivo .csv'}), 400

@app.route('/api/history')
@login_required
def get_history():
    """Obtener historial de cambios"""
    try:
        device_id = request.args.get('device_id')
        limit = int(request.args.get('limit', 100))
        history = DatabaseService.get_change_history(device_id, limit)
        
        return jsonify({
            'success': True,
            'history': history,
            'total': len(history)
        })
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo historial: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/import-history')
@login_required
def get_import_history():
    """Obtener historial de importaciones CSV"""
    try:
        limit = int(request.args.get('limit', 50))
        imports = DatabaseService.get_csv_import_history(limit)
        
        return jsonify({
            'success': True,
            'imports': imports,
            'total': len(imports)
        })
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo historial de importaciones: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/statistics')
@login_required
def get_statistics():
    """Obtener estadísticas del sistema"""
    try:
        stats = DatabaseService.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo estadísticas: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# RUTAS DE AUTENTICACIÓN

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not username or not password:
                return jsonify({'success': False, 'message': 'Usuario y contraseña requeridos'}), 400
            
            user = DatabaseService.get_user_by_credentials(username, password)
            if user:
                session['user_id'] = user.id
                session['username'] = username
                session['role'] = user.role
                logger.info(f"✅ Login exitoso: {username}")
                return jsonify({'success': True, 'message': 'Login exitoso', 'redirect': '/'})
            else:
                logger.warning(f"❌ Login fallido: {username}")
                return jsonify({'success': False, 'message': 'Credenciales incorrectas'}), 401
                
        except Exception as e:
            logger.error(f"❌ Error en login: {e}")
            return jsonify({'success': False, 'message': 'Error interno'}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    username = session.get('username', 'Anónimo')
    session.clear()
    logger.info(f"✅ Logout: {username}")
    return redirect(url_for('login'))

@app.route('/api/current-user')
def current_user():
    """Obtener información del usuario actual"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'No autenticado'}), 401
    
    user = get_current_user()
    if user:
        return jsonify({'success': True, 'user': user})
    else:
        return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 401



if __name__ == '__main__':
    print("🚀 GenieACS WiFi Manager - VERSIÓN OPTIMIZADA")
    print(f"📡 Servidor GenieACS: {GENIEACS_URL}")
    print("")
    print("🎯 NUEVA LÓGICA CORREGIDA:")
    print(" • Base de datos relacional optimizada")
    print(" • Sincronización automática con GenieACS")
    print(" • CSV unificado por MAC address")
    print(" • Cache optimizado (5 minutos)")
    print(" • Dispositivo configurado = contrato + ambas contraseñas")
    print("")
    print("👥 Usuarios por defecto:")
    print(" • admin/admin123 (NOC - Superadmin)")
    print(" • informatica/info123 (Informática - Admin)")
    print(" • callcenter/call123 (Call Center - Operador)")
    
    try:
        from sqlalchemy import text
        
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            logger.info("✅ Conexión MySQL exitosa")
      
            print(f"\n🌐 Servidor disponible en: http://localhost:5000")
            print("🔐 MySQL integrado con XAMPP")
            print("📊 Paginación optimizada")
            print("🎯 Base de datos relacional")
            print("")
            
            app.run(debug=True, host='0.0.0.0', port=5000)
            
    except Exception as e:
        logger.error(f"❌ Error de conexión MySQL: {e}")
        logger.error("💡 Verifica que XAMPP esté ejecutándose")
        logger.error("💡 Ejecuta primero: python init_db_fixed.py")
        exit(1)
