from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import requests
import json
import os
import sqlite3
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

# Base de datos SQLite
DB_NAME = 'genieacs_data.db'

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

def init_database():
    """Inicializar base de datos SQLite"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tabla para almacenar contraseñas actuales
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wifi_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL,
            band TEXT NOT NULL,
            ssid TEXT NOT NULL,
            password TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(serial_number, band)
        )
    ''')
    
    # Tabla para historial de cambios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS change_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL,
            product_class TEXT,
            band TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            ssid TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla para cache de dispositivos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_cache (
            serial_number TEXT PRIMARY KEY,
            product_class TEXT,
            software_version TEXT,
            hardware_version TEXT,
            ip TEXT,
            mac TEXT,
            last_inform TEXT,
            tags TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

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
    """Extraer redes WiFi usando base de conocimiento"""
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
    
    # Extraer redes
    networks = extract_networks_by_knowledge(wlan_configs, product_class, serial_number)
    
    # Mezclar con contraseñas de la base de datos
    networks = merge_with_stored_passwords(networks, serial_number)
    
    return networks, ip, mac

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
    password = safe_get_value(wlan_config, ['KeyPassphrase'])
    if password:
        return password
    
    password = safe_get_value(wlan_config, ['PreSharedKey'])
    if password:
        return password
    
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
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    for network in networks:
        cursor.execute('''
            SELECT password FROM wifi_passwords 
            WHERE serial_number = ? AND band = ?
        ''', (serial_number, network['band']))
        
        stored_password = cursor.fetchone()
        if stored_password and stored_password[0]:
            network['password'] = stored_password[0]
    
    conn.close()
    return networks

def store_password(serial_number, band, ssid, password):
    """Almacenar contraseña en la base de datos"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO wifi_passwords 
        (serial_number, band, ssid, password, updated_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (serial_number, band, ssid, password, datetime.now()))
    
    conn.commit()
    conn.close()

def store_change_history(serial_number, product_class, band, change_type, old_value, new_value, ssid):
    """Almacenar historial de cambios"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO change_history 
        (serial_number, product_class, band, change_type, old_value, new_value, ssid, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (serial_number, product_class, band, change_type, old_value, new_value, ssid, datetime.now()))
    
    conn.commit()
    conn.close()

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
            device_final = {
                "serial_number": device_info["serial_number"],
                "product_class": product_class,
                "software_version": device_info["software_version"],
                "hardware_version": device_info["hardware_version"],
                "ip": ip,
                "mac": mac,
                "last_inform": device_info["last_inform"],
                "tags": device_info["tags"],
                "wifi_networks": wifi_networks
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
                    return True, "Tarea creada y connection request enviado"
                    
                response = requests.get(cr_url, auth=auth, timeout=5)
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"✅ Connection request {i+1} exitoso (GET)")
                    return True, "Tarea creada y connection request enviado (GET)"
            except Exception as e:
                logger.warning(f"⚠️ Connection request {i+1} falló: {e}")
                continue
        
        logger.info("⚠️ Tarea creada pero connection request falló")
        return True, "Tarea creada exitosamente. Usar botón COMMIT para aplicar cambios."
        
    except Exception as e:
        logger.error(f"❌ Error total en connection request: {e}")
        return True, "Tarea creada. Error en connection request - usar botón COMMIT."

def commit_tasks():
    """Enviar commit usando múltiples métodos"""
    try:
        auth = (GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None
        
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
    """Obtener lista de dispositivos WiFi desde GenieACS API"""
    try:
        devices = load_devices_from_genieacs()
        return jsonify({
            'success': True,
            'devices': devices,
            'total': len(devices),
            'last_update': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error obteniendo dispositivos: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/search')
def search_devices():
    """Buscar dispositivos por número de serie"""
    try:
        serial_query = request.args.get('serial', '').lower()
        devices = load_devices_from_genieacs()
        
        if not serial_query:
            filtered_devices = devices
        else:
            filtered_devices = [
                device for device in devices
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
        devices = load_devices_from_genieacs()
        total_devices = len(devices)
        devices_with_wifi = len([d for d in devices if d.get('wifi_networks')])
        devices_with_passwords = len([
            d for d in devices
            for network in d.get('wifi_networks', [])
            if network.get('password')
        ])
        total_networks = sum(len(d.get('wifi_networks', [])) for d in devices)
        
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
            # Guardar en historial
            store_change_history(
                device_serial, device['product_class'], band, 
                'SSID', old_ssid, new_ssid, new_ssid
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
            # Almacenar contraseña en base de datos
            store_password(device_serial, band, ssid, new_password)
            
            # Guardar en historial
            store_change_history(
                device_serial, device['product_class'], band, 
                'PASSWORD', '[OCULTA]', '[OCULTA]', ssid
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
def get_history():
    """Obtener historial de cambios"""
    try:
        # Parámetros de búsqueda
        ssid_filter = request.args.get('ssid', '').lower()
        product_class_filter = request.args.get('product_class', '').lower()
        limit = int(request.args.get('limit', 100))
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        query = '''
            SELECT id, serial_number, product_class, band, change_type, 
                   old_value, new_value, ssid, timestamp
            FROM change_history
            WHERE 1=1
        '''
        params = []
        
        if ssid_filter:
            query += ' AND LOWER(ssid) LIKE ?'
            params.append(f'%{ssid_filter}%')
        
        if product_class_filter:
            query += ' AND LOWER(product_class) LIKE ?'
            params.append(f'%{product_class_filter}%')
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'id': row[0],
                'serial_number': row[1],
                'product_class': row[2],
                'band': row[3],
                'change_type': row[4],
                'old_value': row[5],
                'new_value': row[6],
                'ssid': row[7],
                'timestamp': row[8]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'history': history,
            'total': len(history)
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo historial: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Iniciando GenieACS WiFi Manager MEJORADO...")
    print(f"📡 Servidor GenieACS: {GENIEACS_URL}")
    print("🔧 API DIRECTA: Conectando a GenieACS sin JSON")
    print("💾 Base de datos: SQLite para persistencia")
    
    # Inicializar base de datos
    init_database()
    print("✅ Base de datos inicializada")
    
    # Probar conexión con GenieACS
    try:
        devices = load_devices_from_genieacs()
        if devices:
            total_networks = sum(len(d.get('wifi_networks', [])) for d in devices)
            product_classes = set(d.get('product_class') for d in devices if d.get('product_class'))
            print(f"📊 Dispositivos cargados: {len(devices)}")
            print(f"🔧 Product Classes: {len(product_classes)} tipos")
            print(f"📶 Redes WiFi totales: {total_networks}")
        else:
            print("⚠️ No se pudieron cargar dispositivos desde GenieACS")
    except Exception as e:
        print(f"⚠️ Error conectando con GenieACS: {e}")
    
    print(f"\n🌐 Servidor disponible en: http://localhost:5000")
    print("✅ Sistema listo con persistencia de datos!")
    
    print("\n🔥 MEJORAS IMPLEMENTADAS:")
    print(" • Conexión directa a GenieACS API (sin JSON)")
    print(" • Base de datos SQLite para contraseñas")
    print(" • Historial completo de cambios")
    print(" • Búsquedas avanzadas en historial")
    print(" • Persistencia de datos entre reinicios")
    
    # Ejecutar servidor
    app.run(debug=True, host='0.0.0.0', port=5000)