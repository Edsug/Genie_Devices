
import requests
import json
import pandas as pd
from urllib.parse import unquote
from datetime import datetime

# ⚠️ CAMBIAR ESTAS CREDENCIALES POR LAS TUYAS
GENIEACS_URL = "http://192.168.0.237:7557"
GENIEACS_USERNAME = "admin"
GENIEACS_PASSWORD = "admin"

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
            "wlan_config": "5",  # En ONT-2GF-V-RFDW está al revés según Excel
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "1",  # En ONT-2GF-V-RFDW está al revés según Excel
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey"
        },
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    },
    "ONT-2GF-V-RFW": {
        "2.4GHz": {
            "wlan_config": "5",  # En ONT-2GF-V-RFW está al revés según Excel
            "ssid_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "password_param": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase",
            "password_alt": "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.PreSharedKey"
        },
        "5GHz": {
            "wlan_config": "1",  # En ONT-2GF-V-RFW está al revés según Excel
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
            "wlan_config": "6",  # HG114AT usa WLANConfiguration.6 para 2.4G según Excel
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
        # HG114AT usa WANConnectionDevice.3 según Excel
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1.MACAddress"
    },
    "IGD": {
        # IGD es más complejo, tiene múltiples configuraciones según Excel
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
        # IGD puede usar WANConnectionDevice.1 o 2 según Excel
        "ip_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.ExternalIPAddress",
        "ip_param_alt": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
        "mac_param": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1.MACAddress",
        "mac_param_alt": "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"
    }
}

def get_devices_from_genieacs():
    """Obtener dispositivos desde GenieACS"""
    try:
        url = f"{GENIEACS_URL}/devices"
        response = requests.get(url, auth=(GENIEACS_USERNAME, GENIEACS_PASSWORD) if GENIEACS_USERNAME else None)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"⚠️ Error conectando a GenieACS: {e}")
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

def extract_exactly_two_networks(device_info):
    """Extraer EXACTAMENTE 2 redes (2.4GHz y 5GHz) usando base de conocimiento"""
    device = device_info["raw_device"]
    igw = device.get('InternetGatewayDevice', {})
    product_class = device_info["product_class"]
    
    print(f"\n🔍 Procesando: {device_info['serial_number']} ({product_class})")
    
    # Solo procesar Product Classes conocidos
    if product_class not in DEVICE_KNOWLEDGE_BASE:
        print(f"⚠️ Product Class '{product_class}' no está en la base de conocimiento")
        return [], "", ""
    
    # Extraer IP y MAC usando configuración específica
    ip, mac = extract_ip_mac_for_product_class(igw, product_class)
    
    # Solo continuar si tiene IP válida
    if not ip or ip == "0.0.0.0":
        print(f"⚠️ Sin IP válida para {device_info['serial_number']}")
        return [], ip, mac
    
    # Buscar WLANConfigurations
    wlan_configs = igw.get('LANDevice', {}).get('1', {}).get('WLANConfiguration', {})
    if not wlan_configs:
        print(f"⚠️ Sin WLANConfigurations para {device_info['serial_number']}")
        return [], ip, mac
    
    print(f"📶 WLANConfigurations disponibles: {list(wlan_configs.keys())}")
    
    # Extraer exactamente 2 redes usando base de conocimiento
    networks = extract_networks_by_knowledge(wlan_configs, product_class, device_info['serial_number'])
    
    return networks, ip, mac

def extract_ip_mac_for_product_class(igw, product_class):
    """Extraer IP/MAC usando configuración específica del Product Class"""
    config = DEVICE_KNOWLEDGE_BASE[product_class]
    
    # Intentar parámetro principal
    ip_path = config["ip_param"].split('.')[1:]  # Remover 'InternetGatewayDevice'
    mac_path = config["mac_param"].split('.')[1:]  # Remover 'InternetGatewayDevice'
    
    ip = safe_get_value(igw, ip_path)
    mac = safe_get_value(igw, mac_path)
    
    # Si falla y es IGD, intentar alternativo
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
        # IGD es especial - probar múltiples configuraciones
        networks = extract_igd_networks(wlan_configs, config, serial_number)
    else:
        # Product Classes estándar
        networks = extract_standard_networks(wlan_configs, config, product_class, serial_number)
    
    # Asegurar que tenemos máximo 2 redes (una de cada banda)
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
        
        # Si ya tenemos las 2, parar
        if has_2_4 and has_5:
            break
    
    print(f"✅ Redes extraídas: {len(final_networks)}")
    for net in final_networks:
        print(f"   • {net['band']}: {net['ssid']} (WLANConfig.{net['wlan_configuration']})")
    
    return final_networks

def extract_standard_networks(wlan_configs, config, product_class, serial_number):
    """Extraer redes para Product Classes estándar"""
    networks = []
    
    # Buscar 2.4GHz y 5GHz según configuración
    for band in ["2.4GHz", "5GHz"]:
        if band not in config:
            continue
            
        band_config = config[band]
        wlan_index = band_config["wlan_config"]
        
        if wlan_index in wlan_configs:
            wlan_config = wlan_configs[wlan_index]
            
            # Extraer SSID
            ssid = safe_get_value(wlan_config, ['SSID'])
            if ssid and ssid.strip():
                # Extraer contraseña
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
                print(f"✅ {band} encontrada: {ssid} (WLANConfig.{wlan_index})")
    
    return networks

def extract_igd_networks(wlan_configs, config, serial_number):
    """Extraer redes para dispositivos IGD (más complejo)"""
    networks = []
    
    # Para IGD, probar múltiples configuraciones
    # Intentar 2.4GHz
    for band_key in ["2.4GHz_primary", "2.4GHz_alt"]:
        if band_key in config:
            band_config = config[band_key]
            wlan_index = band_config["wlan_config"]
            
            if wlan_index in wlan_configs:
                wlan_config = wlan_configs[wlan_index]
                ssid = safe_get_value(wlan_config, ['SSID'])
                
                if ssid and ssid.strip():
                    # Determinar si es 2.4GHz por SSID o por configuración
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
                        print(f"✅ 2.4GHz encontrada: {ssid} (WLANConfig.{wlan_index})")
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
                    # Determinar si es 5GHz por SSID o por configuración
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
                        print(f"✅ 5GHz encontrada: {ssid} (WLANConfig.{wlan_index})")
                        break
    
    return networks

def extract_password(wlan_config, band_config):
    """Extraer contraseña usando múltiples métodos"""
    # Método 1: KeyPassphrase
    password = safe_get_value(wlan_config, ['KeyPassphrase'])
    if password:
        return password
    
    # Método 2: PreSharedKey directo
    password = safe_get_value(wlan_config, ['PreSharedKey'])
    if password:
        return password
    
    # Método 3: PreSharedKey como objeto
    psk_obj = wlan_config.get('PreSharedKey', {})
    if isinstance(psk_obj, dict):
        for key, value in psk_obj.items():
            if key != '_object' and isinstance(value, dict):
                psk_value = safe_get_value(value, ['Value'])
                if psk_value:
                    return psk_value
    
    return ""

def is_24ghz_network(ssid, wlan_index):
    """Determinar si es red 2.4GHz por SSID o configuración"""
    ssid_lower = ssid.lower()
    
    # Por SSID
    if '2.4g' in ssid_lower or '2.4ghz' in ssid_lower:
        return True
    if '5g' in ssid_lower or '5ghz' in ssid_lower:
        return False
    
    # Por configuración (WLANConfig.1 generalmente es 2.4GHz para IGD)
    return wlan_index == "1"

def is_5ghz_network(ssid, wlan_index):
    """Determinar si es red 5GHz por SSID o configuración"""
    ssid_lower = ssid.lower()
    
    # Por SSID
    if '5g' in ssid_lower or '5ghz' in ssid_lower:
        return True
    if '2.4g' in ssid_lower or '2.4ghz' in ssid_lower:
        return False
    
    # Por configuración (WLANConfig.5 o 6 generalmente es 5GHz para IGD)
    return wlan_index in ["5", "6"]

def process_devices():
    """Procesar dispositivos con base de conocimiento"""
    print("🚀 Iniciando extracción inteligente...")
    print(f"📡 Conectando a GenieACS: {GENIEACS_URL}")
    print("🧠 Usando base de conocimiento del Excel")
    print("🎯 Objetivo: Exactamente 2 redes por dispositivo (2.4GHz + 5GHz)")
    
    # Mostrar base de conocimiento
    print(f"\n📋 Product Classes configurados: {len(DEVICE_KNOWLEDGE_BASE)}")
    for pc in DEVICE_KNOWLEDGE_BASE.keys():
        print(f"   • {pc}")
    
    # Obtener dispositivos
    raw_devices = get_devices_from_genieacs()
    if not raw_devices:
        print("❌ No se pudieron obtener dispositivos")
        return []
    
    print(f"\n📋 Dispositivos encontrados: {len(raw_devices)}")
    
    # Procesar solo dispositivos conocidos
    wifi_devices = []
    
    for device in raw_devices:
        device_info = extract_device_info(device)
        product_class = device_info["product_class"]
        
        # Solo procesar Product Classes conocidos
        if product_class not in DEVICE_KNOWLEDGE_BASE:
            continue
        
        # Extraer exactamente 2 redes
        wifi_networks, ip, mac = extract_exactly_two_networks(device_info)
        
        # Solo incluir si tiene redes WiFi e IP válida
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
    
    print(f"\n📊 RESULTADO FINAL: {len(wifi_devices)} dispositivos con WiFi extraídos")
    return wifi_devices

def save_results(wifi_devices):
    """Guardar resultados"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # JSON
    output_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "genieacs_url": GENIEACS_URL,
        "knowledge_base_product_classes": list(DEVICE_KNOWLEDGE_BASE.keys()),
        "extraction_method": "Exactamente 2 redes por dispositivo usando base de conocimiento",
        "total_devices_extracted": len(wifi_devices),
        "devices": wifi_devices
    }
    
    json_filename = f"wifi_devices_filtered_{timestamp}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    # CSV
    csv_data = []
    for device in wifi_devices:
        for network in device["wifi_networks"]:
            row = {
                "serial_number": device["serial_number"],
                "product_class": device["product_class"],
                "software_version": device["software_version"],
                "ip": device["ip"],
                "mac": device["mac"],
                "last_inform": device["last_inform"],
                "tags": "; ".join(device["tags"]),
                "wifi_band": network["band"],
                "wifi_ssid": network["ssid"],
                "wifi_password": network["password"],
                "wifi_is_primary": network["is_primary"],
                "wifi_wlan_config": network["wlan_configuration"],
                "ssid_parameter": network["parameter_paths"]["ssid"],
                "password_parameter": network["parameter_paths"]["password"]
            }
            csv_data.append(row)
    
    csv_filename = f"wifi_devices_filtered_{timestamp}.csv"
    df = pd.DataFrame(csv_data)
    df.to_csv(csv_filename, index=False, encoding='utf-8')
    
    return json_filename, csv_filename

def main():
    """Función principal"""
    print("🎯 GenieACS WiFi Extractor INTELIGENTE")
    print("🧠 Base de conocimiento precisa del Excel")
    print("📶 Solo 2 redes por dispositivo: 2.4GHz + 5GHz")
    print("-" * 80)
    
    # Procesar dispositivos
    wifi_devices = process_devices()
    
    if not wifi_devices:
        print("\n❌ No se encontraron dispositivos WiFi válidos")
        print("💡 Verifica:")
        print("   • Product Classes en la base de conocimiento")
        print("   • Dispositivos con IPs válidas")
        print("   • Configuraciones WLAN correctas")
        return
    
    # Guardar resultados
    print("\n💾 Guardando resultados...")
    json_file, csv_file = save_results(wifi_devices)
    
    # Mostrar resumen
    print("\n" + "="*80)
    print("✅ EXTRACCIÓN INTELIGENTE COMPLETADA")
    print("="*80)
    print(f"📄 Archivo JSON: {json_file}")
    print(f"📊 Archivo CSV: {csv_file}")
    print(f"📱 Dispositivos con WiFi: {len(wifi_devices)}")
    
    # Estadísticas detalladas
    total_networks = sum(len(d['wifi_networks']) for d in wifi_devices)
    band_stats = {"2.4GHz": 0, "5GHz": 0}
    
    for device in wifi_devices:
        for network in device["wifi_networks"]:
            band_stats[network["band"]] += 1
    
    print(f"📶 Total redes extraídas: {total_networks}")
    print(f"📶 Redes 2.4GHz: {band_stats['2.4GHz']}")
    print(f"📶 Redes 5GHz: {band_stats['5GHz']}")
    
    # Distribución por Product Class
    pc_stats = {}
    for device in wifi_devices:
        pc = device['product_class']
        pc_stats[pc] = pc_stats.get(pc, 0) + 1
    
    print(f"\n📋 Distribución por Product Class:")
    for pc, count in sorted(pc_stats.items()):
        print(f"   • {pc}: {count} dispositivos")
    
    print("\n💡 Próximos pasos:")
    print("   1. El archivo está listo para usar")
    print("   2. Ejecuta: python app-corregido.py (si aún no lo cambias)")
    print("   3. Abre: http://localhost:5000")
    print("   4. ¡Solo verás exactamente 2 redes por dispositivo!")
    print("\n🚀 ¡Sistema optimizado para gestión WiFi profesional!")

if __name__ == "__main__":
    main()