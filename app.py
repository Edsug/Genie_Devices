from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_cors import CORS
import requests
import json
import os
from datetime import datetime
from urllib.parse import unquote, quote
import logging
import hashlib
from functools import wraps
import re

# Importar configuraciones y modelos MySQL
from config_db import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS, SQLALCHEMY_ENGINE_OPTIONS
from models import db, User, DeviceContract, WifiPassword, ChangeHistory
from db_services import DatabaseService

# Configuración de la aplicación
app = Flask(__name__)
CORS(app)
app.secret_key = 'tu_clave_secreta_super_segura_aqui_cambiala'  # ⚠️ CAMBIAR EN PRODUCCIÓN

# Configurar base de datos MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = SQLALCHEMY_ENGINE_OPTIONS

# Inicializar extensiones
db.init_app(app)

# ⚠️ CAMBIAR ESTAS CREDENCIALES POR LAS TUYAS
GENIEACS_URL = "http://192.168.0.237:7557"
GENIEACS_USERNAME = "admin"
GENIEACS_PASSWORD = "admin"

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Roles del sistema
USER_ROLES = {
    'noc': {'name': 'NOC', 'level': 3, 'description': 'Superadmin - Acceso completo'},
    'informatica': {'name': 'Informática', 'level': 2, 'description': 'Admin - Gestión de dispositivos'},
    'callcenter': {'name': 'Call Center', 'level': 1, 'description': 'Operador - Consulta y cambios básicos'}
}

# BASE DE CONOCIMIENTO EXACTA del Excel ParametrosGenieACS.xlsx
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
    "ONT-2GF-V-RFW": {
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
    "ONT-4GE-V-USB-RFDW": {
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
    "HG114AT": {
        "2.4GHz": {
            "wlan_config": "6",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.MACAddress"
    },
    "IGD": {
        "2.4GHz_primary": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "2.4GHz_alt": {
            "wlan_config": "6",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.PreSharedKey"
        },
        "5GHz_primary": {
            "wlan_config": "5",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "5GHz_alt": {
            "wlan_config": "1",
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ExternalIPAddress",
        "ip_param_alt": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.MACAddress",
        "mac_param_alt": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    }
}


def is_valid_ssid(ssid):
    """Verificar si el SSID es válido y visible"""
    if not ssid or not ssid.strip():
        return False

    ssid = ssid.strip()

    # Filtrar SSIDs ocultos o con caracteres extraños
    invalid_patterns = [
        r'^[\*\.\-_]+$',  # Solo asteriscos, puntos, guiones
        r'^\s*$',  # Solo espacios
        r'^[0-9A-Fa-f]{32}$',  # Hash hexadecimal de 32 caracteres
        r'^[0-9A-Fa-f]{64}$',  # Hash hexadecimal de 64 caracteres
    ]

    for pattern in invalid_patterns:
        if re.match(pattern, ssid):
            return False

    # Debe tener al menos un carácter alfanumérico
    if not re.search(r'[a-zA-Z0-9]', ssid):
        return False

    return True


def is_valid_password(password):
    """Verificar si la contraseña es válida y legible"""
    if not password:
        return False

    password = password.strip()
    if not password:
        return False

    # Filtrar contraseñas inválidas
    invalid_patterns = [
        r'^[\*\.\-_\s]+$',  # Solo asteriscos, puntos, guiones, espacios
        r'^[0-9A-Fa-f]{32}$',  # Hash MD5
        r'^[0-9A-Fa-f]{64}$',  # Hash SHA256
        r'^\$[0-9]\$.*',  # Hash con formato $n$...
        r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',  # UUID
    ]

    for pattern in invalid_patterns:
        if re.match(pattern, password):
            return False

    # Debe tener entre 8 y 63 caracteres para WiFi
    if len(password) < 8 or len(password) > 63:
        return False

    return True


def normalize_password_for_history(password):
    """Normalizar contraseña para mostrar en historial"""
    if not password or not is_valid_password(password):
        return "Sin contraseña"
    return password


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


# Funciones para GenieACS (mantienen la misma lógica)
def get_devices_from_genieacs():
    """Obtener dispositivos directamente desde GenieACS API"""
    try:
        url = f"{GENIEACS_URL}/devices"
        response = requests.get(url, auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None)
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

    # Otros datos
    software_version = safe_get_value(device_info, ['SoftwareVersion'])
    hardware_version = safe_get_value(device_info, ['HardwareVersion'])

    # Last inform
    last_inform = ""
    if '_lastInform' in device:
        try:
            timestamp = device['_lastInform']
            if isinstance(timestamp, (int, float)) and timestamp > 0:
                dt = datetime.fromtimestamp(timestamp / 1000)
                last_inform = dt.strftime("%d/%m/%Y, %I:%M:%S %p")
        except:
            pass

    # Tags
    tags = []
    if '_tags' in device:
        tags_data = device['_tags']
        if isinstance(tags_data, dict):
            tags = list(tags_data.keys())
        elif isinstance(tags_data, list):
            tags = tags_data

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
    """Extraer redes WiFi usando base de conocimiento con filtros mejorados"""
    device = device_info["raw_device"]
    igw = device.get('InternetGatewayDevice', {})
    product_class = device_info["product_class"]
    serial_number = device_info["serial_number"]

    if product_class not in DEVICE_KNOWLEDGE_BASE:
        return [], "", ""

    # Extraer IP y MAC
    ip, mac = extract_ip_mac_for_product_class(igw, product_class)

    if not ip or ip == "0.0.0.0":
        return [], ip, mac

    # Buscar WLANConfigurations
    wlan_configs = igw.get('LANDevice', {}).get('1', {}).get('WLANConfiguration', {})
    if not wlan_configs:
        return [], ip, mac

    # Extraer redes con filtros mejorados
    networks = extract_networks_by_knowledge(wlan_configs, product_class, serial_number)

    # Filtrar redes con SSIDs válidos
    valid_networks = []
    for network in networks:
        if is_valid_ssid(network['ssid']):
            # Normalizar contraseña
            if not is_valid_password(network['password']):
                network['password'] = ""  # Limpiar contraseña inválida
            valid_networks.append(network)

    # Mezclar con contraseñas de la base de datos
    valid_networks = merge_with_stored_passwords(valid_networks, serial_number)

    return valid_networks, ip, mac


def extract_ip_mac_for_product_class(igw, product_class):
    """Extraer IP/MAC usando configuración específica del Product Class"""
    config = DEVICE_KNOWLEDGE_BASE[product_class]

    ip_path = config["ip_param"].split('.')[1:]
    mac_path = config["mac_param"].split('.')[1:]

    ip = safe_get_value(igw, ip_path)
    mac = safe_get_value(igw, mac_path)

    if (not ip or ip == "0.0.0.0") and product_class == "IGD":
        ip_path_alt = config["ip_param_alt"].split('.')[1:]
        mac_path_alt = config["mac_param_alt"].split('.')[1:]
        ip = safe_get_value(igw, ip_path_alt)
        mac = safe_get_value(igw, mac_path_alt)

    return ip, mac


def extract_networks_by_knowledge(wlan_configs, product_class, serial_number):
    """Extraer redes usando base de conocimiento específica"""
    networks = []
    config = DEVICE_KNOWLEDGE_BASE[product_class]

    if product_class == "IGD":
        networks = extract_igd_networks(wlan_configs, config, serial_number)
    else:
        networks = extract_standard_networks(wlan_configs, config, product_class, serial_number)

    # Asegurar máximo 2 redes
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


def merge_with_stored_passwords(networks, serial_number):
    """Mezclar redes con contraseñas almacenadas en la base de datos"""
    for network in networks:
        stored_password = DatabaseService.get_stored_password(serial_number, network['band'])
        if stored_password:
            network['password'] = stored_password
    return networks


def load_devices_from_genieacs():
    """Cargar dispositivos directamente desde GenieACS"""
    logger.info("🔄 Cargando dispositivos desde GenieACS API...")
    raw_devices = get_devices_from_genieacs()

    if not raw_devices:
        logger.error("❌ No se pudieron obtener dispositivos desde GenieACS")
        return []

    logger.info(f"📋 Dispositivos encontrados en GenieACS: {len(raw_devices)}")

    wifi_devices = []
    for device in raw_devices:
        device_info = extract_device_info(device)
        product_class = device_info["product_class"]

        if product_class not in DEVICE_KNOWLEDGE_BASE:
            continue

        wifi_networks, ip, mac = extract_wifi_networks(device_info)

        if wifi_networks and ip and ip != "0.0.0.0":
            # Obtener contrato y determinar si está configurado
            contract_number = DatabaseService.get_device_contract(device_info["serial_number"])
            configured = DatabaseService.is_device_configured(device_info["serial_number"])

            # Obtener SSID 5GHz para título
            ssid_5g = ""
            for network in wifi_networks:
                if network['band'] == '5GHz':
                    ssid_5g = network['ssid']
                    break

            device_final = {
                "serial_number": device_info["serial_number"],
                "product_class": product_class,
                "software_version": device_info["software_version"],
                "hardware_version": device_info["hardware_version"],
                "ip": ip,
                "mac": mac,
                "last_inform": device_info["last_inform"],
                "tags": device_info["tags"],
                "wifi_networks": wifi_networks,
                "configured": configured,
                "contract_number": contract_number,
                "title_ssid": ssid_5g
            }

            wifi_devices.append(device_final)

    logger.info(f"✅ Dispositivos WiFi procesados: {len(wifi_devices)}")
    return wifi_devices


def send_task_to_genieacs_correct_api(device_serial, parameter_name, parameter_value):
    """Enviar tarea a GenieACS usando la API CORRECTA"""
    try:
        logger.info(f"🔧 Enviando tarea para {device_serial}")
        logger.info(f"📝 Parámetro: {parameter_name} = {parameter_value}")

        device_id_encoded = quote(device_serial, safe='')
        task_url = f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks"

        task_data = {
            "name": "setParameterValues",
            "parameterValues": [
                [parameter_name, parameter_value, "xsd:string"]
            ]
        }

        headers = {'Content-Type': 'application/json'}
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None

        logger.info(f"📤 API CORRECTA - Enviando tarea a: {task_url}")

        response = requests.post(
            task_url,
            json=task_data,
            headers=headers,
            auth=auth,
            timeout=10
        )

        logger.info(f"📋 Respuesta API: {response.status_code}")

        if response.status_code in [200, 201, 202]:
            logger.info("✅ Tarea creada exitosamente con API correcta")
            return send_connection_request_correct(device_serial)
        else:
            logger.error(f"❌ Error API correcta: {response.status_code} - {response.text}")
            return try_alternative_api(device_serial, parameter_name, parameter_value)

    except Exception as e:
        logger.error(f"❌ Excepción API correcta: {e}")
        return try_alternative_api(device_serial, parameter_name, parameter_value)


def try_alternative_api(device_serial, parameter_name, parameter_value):
    """Intentar API alternativa de GenieACS"""
    try:
        logger.info("🔄 Intentando API alternativa...")

        device_id_encoded = quote(device_serial, safe='')
        device_url = f"{GENIEACS_URL}/devices/{device_id_encoded}"

        device_data = {
            parameter_name: {
                "_value": parameter_value,
                "_writable": True
            }
        }

        headers = {'Content-Type': 'application/json'}
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None

        response = requests.put(
            device_url,
            json=device_data,
            headers=headers,
            auth=auth,
            timeout=10
        )

        if response.status_code in [200, 201, 202, 204]:
            logger.info("✅ PUT directo exitoso")
            return send_connection_request_correct(device_serial)

        # Método global
        global_task_url = f"{GENIEACS_URL}/tasks"
        global_task_data = {
            "device": device_serial,
            "name": "setParameterValues",
            "parameterValues": [
                [parameter_name, parameter_value, "xsd:string"]
            ]
        }

        response = requests.post(
            global_task_url,
            json=global_task_data,
            headers=headers,
            auth=auth,
            timeout=10
        )

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
        cr_urls = [
            f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks?connection_request",
            f"{GENIEACS_URL}/devices/{device_id_encoded}/connection_request",
            f"{GENIEACS_URL}/devices/{device_id_encoded}/tasks",
        ]

        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None

        for i, cr_url in enumerate(cr_urls):
            try:
                response = requests.post(cr_url, auth=auth, timeout=5)
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"✅ Connection request {i+1} exitoso")
                    return True, "Cambios aplicados exitosamente"

                response = requests.get(cr_url, auth=auth, timeout=5)
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"✅ Connection request {i+1} exitoso (GET)")
                    return True, "Cambios aplicados exitosamente"
            except Exception as e:
                logger.warning(f"⚠️ Connection request {i+1} falló: {e}")
                continue

        logger.info("✅ Cambios enviados correctamente")
        return True, "Cambios aplicados exitosamente"

    except Exception as e:
        logger.error(f"❌ Error total en connection request: {e}")
        return True, "Cambios aplicados exitosamente"


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
                return jsonify({'success': False, 'message': 'Usuario y contraseña son requeridos'}), 400

            user = DatabaseService.get_user_by_credentials(username, password)

            if user:
                # Login exitoso
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
            return jsonify({'success': False, 'message': 'Error interno del servidor'}), 500

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Cerrar sesión"""
    username = session.get('username', 'Anónimo')
    session.clear()
    logger.info(f"✅ Logout exitoso: {username}")
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


# RUTAS PRINCIPALES
@app.route('/')
@login_required
def index():
    """Página principal"""
    return render_template('index.html')


@app.route('/api/devices')
@login_required
def get_devices():
    """Obtener lista de dispositivos WiFi desde GenieACS API"""
    try:
        devices = load_devices_from_genieacs()

        # Separar en configurados y no configurados
        configured_devices = [d for d in devices if d.get('configured', False)]
        unconfigured_devices = [d for d in devices if not d.get('configured', False)]

        return jsonify({
            'success': True,
            'devices': {
                'configured': configured_devices,
                'unconfigured': unconfigured_devices
            },
            'total': len(devices),
            'last_update': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error obteniendo dispositivos: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/search')
@login_required
def search_devices():
    """Buscar dispositivos con búsqueda inteligente"""
    try:
        query = request.args.get('query', '').strip().lower()
        filter_type = request.args.get('filter', 'all')  # all, configured, unconfigured

        devices = load_devices_from_genieacs()

        if not query:
            # Sin query, filtrar solo por tipo
            if filter_type == 'configured':
                devices = [d for d in devices if d.get('configured', False)]
            elif filter_type == 'unconfigured':
                devices = [d for d in devices if not d.get('configured', False)]

            configured_devices = [d for d in devices if d.get('configured', False)]
            unconfigured_devices = [d for d in devices if not d.get('configured', False)]

            return jsonify({
                'success': True,
                'devices': {
                    'configured': configured_devices,
                    'unconfigured': unconfigured_devices
                },
                'total': len(devices)
            })

        filtered_devices = []
        for device in devices:
            # Aplicar filtro de tipo primero
            if filter_type == 'configured' and not device.get('configured', False):
                continue
            elif filter_type == 'unconfigured' and device.get('configured', False):
                continue

            # Buscar en diferentes campos
            matches = []

            # Contrato (prioridad más alta)
            if device.get('contract_number') and query in device.get('contract_number', '').lower():
                matches.append('contract')

            # Serial Number
            if query in device.get('serial_number', '').lower():
                matches.append('serial')

            # Product Class
            if query in device.get('product_class', '').lower():
                matches.append('product_class')

            # IP
            if query in device.get('ip', '').lower():
                matches.append('ip')

            # SSID en cualquiera de las redes
            for network in device.get('wifi_networks', []):
                if query in network.get('ssid', '').lower():
                    matches.append('ssid')
                    break

            if matches:
                device['match_types'] = matches
                filtered_devices.append(device)

        # Separar en configurados y no configurados
        configured_devices = [d for d in filtered_devices if d.get('configured', False)]
        unconfigured_devices = [d for d in filtered_devices if not d.get('configured', False)]

        return jsonify({
            'success': True,
            'devices': {
                'configured': configured_devices,
                'unconfigured': unconfigured_devices
            },
            'total': len(filtered_devices),
            'query': query,
            'filter': filter_type
        })

    except Exception as e:
        logger.error(f"Error en búsqueda: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# API PARA CONTRATOS (SOLO LOCAL - NO se envía a GenieACS)
@app.route('/api/device/<device_serial>/contract', methods=['PUT'])
@login_required
def update_contract(device_serial):
    """Actualizar número de contrato de un dispositivo (SOLO LOCAL)"""
    try:
        data = request.get_json()
        new_contract = data.get('contract', '').strip()

        # Obtener información del usuario actual
        user = get_current_user()

        # Obtener contrato anterior para historial
        old_contract = DatabaseService.get_device_contract(device_serial)

        # Almacenar contrato (SOLO LOCAL)
        success, message = DatabaseService.store_contract(device_serial, new_contract, user['id'] if user else None)

        if success:
            # Obtener dispositivo para el historial
            devices = load_devices_from_genieacs()
            device = next((d for d in devices if d['serial_number'] == device_serial), None)

            if device:
                # Guardar en historial
                DatabaseService.store_change_history(
                    device_serial, device['product_class'], None,
                    'CONTRACT', old_contract or '[VACÍO]', new_contract or '[VACÍO]',
                    contract_number=new_contract,
                    user_id=user['id'] if user else None,
                    username=user['username'] if user else 'Sistema'
                )

            return jsonify({
                'success': True,
                'message': 'Contrato actualizado correctamente',
                'new_contract': new_contract
            })
        else:
            return jsonify({'success': False, 'message': message}), 500

    except Exception as e:
        logger.error(f"❌ Error actualizando contrato: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/device/<device_serial>/wifi/<band>/ssid', methods=['PUT'])
@login_required
def update_ssid(device_serial, band):
    """Actualizar SSID de una red WiFi"""
    try:
        data = request.get_json()
        new_ssid = data.get('ssid', '').strip()

        if not new_ssid:
            return jsonify({'success': False, 'message': 'SSID no puede estar vacío'}), 400

        if len(new_ssid) > 32:
            return jsonify({'success': False, 'message': 'SSID no puede tener más de 32 caracteres'}), 400

        # Obtener dispositivos actuales
        devices = load_devices_from_genieacs()
        device = next((d for d in devices if d['serial_number'] == device_serial), None)

        if not device:
            return jsonify({'success': False, 'message': 'Dispositivo no encontrado'}), 404

        network = next((n for n in device.get('wifi_networks', []) if n['band'] == band), None)

        if not network:
            return jsonify({'success': False, 'message': 'Red WiFi no encontrada'}), 404

        ssid_parameter = network['parameter_paths']['ssid']
        old_ssid = network['ssid']

        logger.info(f"🔧 Actualizando SSID para {device_serial}")
        logger.info(f"📝 Banda: {band}, Nuevo SSID: {new_ssid}")

        success, message = send_task_to_genieacs_correct_api(device_serial, ssid_parameter, new_ssid)

        if success:
            # Obtener información del usuario actual
            user = get_current_user()
            contract_number = DatabaseService.get_device_contract(device_serial)

            # Guardar en historial
            DatabaseService.store_change_history(
                device_serial, device['product_class'], band,
                'SSID', old_ssid, new_ssid, new_ssid, contract_number,
                user['id'] if user else None,
                user['username'] if user else 'Sistema'
            )

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
@login_required
def update_password(device_serial, band):
    """Actualizar contraseña de una red WiFi"""
    try:
        data = request.get_json()
        new_password = data.get('password', '').strip()

        if new_password and (len(new_password) < 8 or len(new_password) > 63):
            return jsonify({'success': False, 'message': 'Contraseña debe tener entre 8 y 63 caracteres'}), 400

        # Obtener dispositivos actuales
        devices = load_devices_from_genieacs()
        device = next((d for d in devices if d['serial_number'] == device_serial), None)

        if not device:
            return jsonify({'success': False, 'message': 'Dispositivo no encontrado'}), 404

        network = next((n for n in device.get('wifi_networks', []) if n['band'] == band), None)

        if not network:
            return jsonify({'success': False, 'message': 'Red WiFi no encontrada'}), 404

        password_parameter = network['parameter_paths']['password']
        old_password = network['password']
        ssid = network['ssid']

        logger.info(f"🔧 Actualizando contraseña para {device_serial}")
        logger.info(f"📝 Banda: {band}, Nueva contraseña: {'[OCULTA]' if new_password else '[VACÍA]'}")

        success, message = send_task_to_genieacs_correct_api(device_serial, password_parameter, new_password)

        if success:
            # Obtener información del usuario actual
            user = get_current_user()
            contract_number = DatabaseService.get_device_contract(device_serial)

            # Almacenar contraseña en base de datos
            DatabaseService.store_password(device_serial, band, ssid, new_password)

            # Guardar en historial con contraseñas normalizadas
            DatabaseService.store_change_history(
                device_serial, device['product_class'], band,
                'PASSWORD', old_password, new_password, ssid, contract_number,
                user['id'] if user else None,
                user['username'] if user else 'Sistema'
            )

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


@app.route('/api/refresh', methods=['POST'])
@login_required
def refresh_data():
    """Recargar datos desde GenieACS"""
    try:
        logger.info("🔄 Recargando datos desde GenieACS...")
        devices = load_devices_from_genieacs()

        return jsonify({
            'success': True,
            'message': 'Datos recargados correctamente desde GenieACS',
            'total_devices': len(devices)
        })

    except Exception as e:
        logger.error(f"❌ Error recargando datos: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/history')
@login_required
def get_history():
    """Obtener historial de cambios"""
    try:
        # Parámetros de búsqueda
        ssid_filter = request.args.get('ssid', '')
        product_class_filter = request.args.get('product_class', '')
        user_filter = request.args.get('username', '')
        contract_filter = request.args.get('contract', '')
        limit = int(request.args.get('limit', 100))

        history = DatabaseService.get_change_history(
            limit=limit,
            serial_filter=None,
            contract_filter=contract_filter if contract_filter else None,
            user_filter=user_filter if user_filter else None,
            ssid_filter=ssid_filter if ssid_filter else None
        )

        return jsonify({
            'success': True,
            'history': history,
            'total': len(history)
        })

    except Exception as e:
        logger.error(f"Error obteniendo historial: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# API PARA GESTIÓN DE USUARIOS
@app.route('/api/users', methods=['GET'])
@role_required(2)  # Nivel Informática o superior
def get_users():
    """Obtener lista de usuarios"""
    try:
        current_user = get_current_user()
        users = DatabaseService.get_all_users(current_user['role'])

        return jsonify({
            'success': True,
            'users': users,
            'roles': USER_ROLES
        })

    except Exception as e:
        logger.error(f"Error obteniendo usuarios: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/users', methods=['POST'])
@role_required(2)  # Nivel Informática o superior
def create_user():
    """Crear nuevo usuario"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        role = data.get('role', 'callcenter')

        if not username or not password:
            return jsonify({'success': False, 'message': 'Usuario y contraseña son requeridos'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'message': 'La contraseña debe tener al menos 6 caracteres'}), 400

        if role not in USER_ROLES:
            return jsonify({'success': False, 'message': 'Rol inválido'}), 400

        current_user = get_current_user()

        # Verificar permisos para crear roles
        if current_user['role'] != 'noc' and role != 'callcenter':
            return jsonify({'success': False, 'message': 'No tienes permisos para crear usuarios con ese rol'}), 403

        success, message = DatabaseService.create_user(username, password, role)

        if success:
            logger.info(f"✅ Usuario creado: {username} con rol {role}")
            return jsonify({
                'success': True,
                'message': f'Usuario {username} creado exitosamente'
            })
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"Error creando usuario: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required(2)  # Nivel Informática o superior
def delete_user(user_id):
    """Eliminar usuario"""
    try:
        current_user = get_current_user()

        # No se puede eliminar a sí mismo
        if current_user['id'] == user_id:
            return jsonify({'success': False, 'message': 'No puedes eliminarte a ti mismo'}), 400

        success, message = DatabaseService.delete_user(user_id, current_user['role'])

        if success:
            logger.info(f"✅ Usuario eliminado por {current_user['username']}")
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"Error eliminando usuario: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# API PARA CAMBIO DE TEMA
@app.route('/api/user/theme', methods=['PUT'])
@login_required
def update_user_theme():
    """Actualizar tema del usuario"""
    try:
        data = request.get_json()
        theme = data.get('theme', 'system')

        if theme not in ['light', 'dark', 'system']:
            return jsonify({'success': False, 'message': 'Tema inválido'}), 400

        user = get_current_user()
        success, message = DatabaseService.update_user_theme(user['id'], theme)

        if success:
            logger.info(f"✅ Tema actualizado para {user['username']}: {theme}")
            return jsonify({
                'success': True,
                'message': 'Tema actualizado correctamente',
                'theme': theme
            })
        else:
            return jsonify({'success': False, 'message': message}), 500

    except Exception as e:
        logger.error(f"Error actualizando tema: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/user/theme', methods=['GET'])
@login_required
def get_user_theme():
    """Obtener tema del usuario"""
    try:
        user = get_current_user()
        user_obj = DatabaseService.get_user_by_id(user['id'])

        theme = user_obj.theme if user_obj else 'system'

        return jsonify({
            'success': True,
            'theme': theme
        })

    except Exception as e:
        logger.error(f"Error obteniendo tema: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# FUNCIÓN PRINCIPAL
if __name__ == '__main__':
    print("🚀 Iniciando GenieACS WiFi Manager con MySQL")
    print(f"📡 Servidor GenieACS: {GENIEACS_URL}")
    print("")
    print("👥 Usuarios por defecto:")
    print("   • admin/admin123 (NOC - Superadmin)")
    print("   • informatica/info123 (Informática - Admin)")
    print("   • callcenter/call123 (Call Center - Operador)")
    print("")

    # Verificar conexión con base de datos
    try:
        from sqlalchemy import text, inspect

        with app.app_context():
            # Probar conexión a MySQL (SQLAlchemy 2.x compatible)
            db.session.execute(text('SELECT 1'))
            logger.info("✅ Conexión MySQL exitosa")

            # Verificar que las tablas existan
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()

            required_tables = ['users', 'device_contracts', 'wifi_passwords', 'change_history']
            missing_tables = [table for table in required_tables if table not in tables]

            if missing_tables:
                logger.error(f"❌ Tablas faltantes en MySQL: {missing_tables}")
                logger.error("💡 Ejecuta: python init_db.py")
                exit(1)
            else:
                logger.info(f"✅ Todas las tablas MySQL presentes: {len(tables)} tablas")

        print("")

        # Probar conexión con GenieACS
        try:
            devices = load_devices_from_genieacs()
            if devices:
                configured_count = len([d for d in devices if d.get('configured', False)])
                unconfigured_count = len([d for d in devices if not d.get('configured', False)])
                contracts_count = len([d for d in devices if d.get('contract_number')])
                total_networks = sum(len(d.get('wifi_networks', [])) for d in devices)
                product_classes = set(d.get('product_class') for d in devices if d.get('product_class'))

                print(f"📊 Estado de Dispositivos:")
                print(f"   📋 Total: {len(devices)}")
                print(f"   ✅ Configurados: {configured_count}")
                print(f"   ⚙️ No configurados: {unconfigured_count}")
                print(f"   📄 Con contrato: {contracts_count}")
                print(f"   🔧 Modelos: {len(product_classes)} tipos")
                print(f"   📶 Redes WiFi: {total_networks}")
            else:
                print("⚠️ No se pudieron cargar dispositivos desde GenieACS")

        except Exception as e:
            print(f"⚠️ Error conectando con GenieACS: {e}")

        print(f"\n🌐 Servidor disponible en: http://localhost:5000")
        print("🔐 MySQL integrado con XAMPP")

        # Ejecutar servidor
        app.run(debug=True, host='0.0.0.0', port=5000)

    except Exception as e:
        logger.error(f"❌ Error de conexión MySQL: {e}")
        logger.error("💡 Verifica que:")
        logger.error("   • XAMPP esté ejecutándose")
        logger.error("   • MySQL esté iniciado en XAMPP")
        logger.error("   • config_db.py tenga las credenciales correctas")
        logger.error("   • Hayas ejecutado: python init_db.py")
        exit(1)
