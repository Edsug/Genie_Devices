import requests
import json
from urllib.parse import unquote
from datetime import datetime
import re

GENIEACS_URL = "http://192.168.0.237:7557"
USERNAME = "admin"
PASSWORD = "admin"

def get_devices():
    """Obtener lista completa de dispositivos desde GenieACS"""
    url = f"{GENIEACS_URL}/devices"
    response = requests.get(url, auth=(USERNAME, PASSWORD) if USERNAME else None)
    response.raise_for_status()
    return response.json()

def safe_get_nested_value(data, path, default=""):
    """Obtener valor anidado de forma segura"""
    try:
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default

        if isinstance(current, dict) and '_value' in current:
            return str(current['_value'])
        elif isinstance(current, dict):
            return default
        return str(current) if current is not None else default
    except (KeyError, TypeError):
        return default

def clean_and_filter_ssids_with_passwords(wlan_configs):
    """Extraer y limpiar SSIDs con sus contraseñas correspondientes"""
    if not wlan_configs or not isinstance(wlan_configs, dict):
        return []

    # Patrones para identificar SSIDs principales
    main_patterns = [
        r'^[A-Za-z].*[0-9].*$',  # Contiene letras y números
        r'^[A-Za-z]{4,}.*$',     # Al menos 4 letras al inicio
        r'^FTTH.*$',             # Redes FTTH
        r'^.*WiFi.*$',           # Contiene WiFi
        r'^.*Net.*$'             # Contiene Net
    ]

    # Patrones para excluir
    exclude_patterns = [
        r'^AP-[0-9]+$',          # AP-1, AP-2, etc.
        r'^Test.*$',             # Redes de prueba
        r'^test.*$',             # test en minúsculas
        r'^Guest.*$',            # Redes de invitados genéricas
        r'^.*_test$',            # Terminan en _test
        r'^[0-9]+$'              # Solo números
    ]

    wifi_networks = []
    seen_ssids = set()

    for wlan_key, wlan_config in wlan_configs.items():
        if not isinstance(wlan_config, dict):
            continue

        # Extraer SSID
        ssid = safe_get_nested_value(wlan_config, ['SSID'], "")
        if not ssid or ssid in seen_ssids:
            continue

        # Verificar si debe ser excluido
        should_exclude = any(re.match(pattern, ssid, re.IGNORECASE) 
                           for pattern in exclude_patterns)
        if should_exclude:
            continue

        # Extraer contraseña (varios campos posibles)
        password = ""

        # Intentar KeyPassphrase primero
        password = safe_get_nested_value(wlan_config, ['KeyPassphrase'], "")

        # Si no hay KeyPassphrase, intentar PreSharedKey
        if not password:
            # PreSharedKey puede ser un objeto complejo
            psk_obj = wlan_config.get('PreSharedKey', {})
            if isinstance(psk_obj, dict):
                # Buscar dentro del objeto PreSharedKey
                for psk_key, psk_value in psk_obj.items():
                    if isinstance(psk_value, dict) and '_value' in psk_value:
                        password = str(psk_value['_value'])
                        break

        # Extraer información adicional de seguridad
        auth_mode = safe_get_nested_value(wlan_config, ['WPAAuthenticationMode'], "")
        encryption_mode = safe_get_nested_value(wlan_config, ['WPAEncryptionModes'], "")
        enabled = safe_get_nested_value(wlan_config, ['Enable'], "")

        # Determinar si es red principal
        is_main = any(re.match(pattern, ssid, re.IGNORECASE) 
                     for pattern in main_patterns)

        wifi_network = {
            'wlan_id': wlan_key,
            'ssid': ssid,
            'password': password,
            'auth_mode': auth_mode,
            'encryption_mode': encryption_mode,
            'enabled': enabled,
            'is_main': is_main
        }

        wifi_networks.append(wifi_network)
        seen_ssids.add(ssid)

    # Ordenar: principales primero, luego otros
    wifi_networks.sort(key=lambda x: (not x['is_main'], x['ssid']))

    # Retornar máximo 4 redes (2 principales + 2 secundarias)
    return wifi_networks[:4]

def extract_interface_data(device):
    """Extraer datos específicos del dispositivo desde GenieACS"""
    serial_number = unquote(device.get("_id", ""))

    device_data = {
        "serial_number": serial_number,
        "product_class": "",
        "software_version": "",
        "hardware_version": "",
        "manufacturer": "",
        "model_name": "",
        "ip": "",
        "wifi_networks": [],  # Lista de redes WiFi con contraseñas
        "last_inform": "",
        "connection_url": "",
        "mac_address": "",
        "tags": []
    }

    # Acceder a InternetGatewayDevice
    igw = device.get('InternetGatewayDevice', {})

    if igw:
        # DeviceInfo
        device_info = igw.get('DeviceInfo', {})
        device_data["product_class"] = safe_get_nested_value(device_info, ['ProductClass'], "")
        device_data["software_version"] = safe_get_nested_value(device_info, ['SoftwareVersion'], "")  
        device_data["hardware_version"] = safe_get_nested_value(device_info, ['HardwareVersion'], "")
        device_data["manufacturer"] = safe_get_nested_value(device_info, ['Manufacturer'], "")
        device_data["model_name"] = safe_get_nested_value(device_info, ['ModelName'], "")

        # IP Externa desde WANDevice
        wan_devices = igw.get('WANDevice', {})
        for wan_key, wan_device in wan_devices.items():
            if isinstance(wan_device, dict):
                wan_conn_devices = wan_device.get('WANConnectionDevice', {})
                for conn_key, conn_device in wan_conn_devices.items():
                    if isinstance(conn_device, dict):
                        wan_ip_conns = conn_device.get('WANIPConnection', {})
                        for ip_key, ip_conn in wan_ip_conns.items():
                            if isinstance(ip_conn, dict):
                                ip_addr = safe_get_nested_value(ip_conn, ['ExternalIPAddress'], "")
                                if ip_addr and ip_addr != "0.0.0.0" and not device_data["ip"]:
                                    device_data["ip"] = ip_addr

                                if not device_data["mac_address"]:
                                    mac_addr = safe_get_nested_value(ip_conn, ['MACAddress'], "")
                                    if mac_addr:
                                        device_data["mac_address"] = mac_addr

        # Redes WiFi con contraseñas desde LANDevice -> WLANConfiguration
        lan_devices = igw.get('LANDevice', {})
        for lan_key, lan_device in lan_devices.items():
            if isinstance(lan_device, dict):
                wlan_configs = lan_device.get('WLANConfiguration', {})
                if wlan_configs:
                    device_data["wifi_networks"] = clean_and_filter_ssids_with_passwords(wlan_configs)
                    break  # Solo procesar el primer LANDevice que tenga WLANConfiguration

        # Connection Request URL
        mgmt_server = igw.get('ManagementServer', {})
        device_data["connection_url"] = safe_get_nested_value(mgmt_server, ['ConnectionRequestURL'], "")

    # Last inform
    if '_lastInform' in device:
        timestamp = device['_lastInform']
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            try:
                dt = datetime.fromtimestamp(timestamp / 1000)
                device_data["last_inform"] = dt.strftime("%d/%m/%Y, %I:%M:%S %p")
            except:
                device_data["last_inform"] = str(timestamp)

    # Tags
    if '_tags' in device:
        tags_data = device['_tags']
        if isinstance(tags_data, dict):
            device_data["tags"] = list(tags_data.keys())
        elif isinstance(tags_data, list):
            device_data["tags"] = tags_data

    # Product class desde deviceId si no se encontró
    if not device_data["product_class"] and '_deviceId' in device:
        device_id = device['_deviceId']
        if isinstance(device_id, dict) and '_ProductClass' in device_id:
            device_data["product_class"] = str(device_id['_ProductClass'])

    # Asegurar tipos string
    for key, value in device_data.items():
        if key not in ['wifi_networks', 'tags']:
            device_data[key] = str(value) if value is not None else ""

    return device_data

def save_devices_to_json():
    """Obtener dispositivos y guardar en JSON con WiFi y contraseñas"""
    try:
        print("🔄 Conectando a GenieACS...")
        devices = get_devices()
        print(f"📋 Encontrados {len(devices)} dispositivos")

        clean_devices = []
        unique_serials = set()

        for device in devices:
            device_data = extract_interface_data(device)

            if device_data["serial_number"] not in unique_serials:
                unique_serials.add(device_data["serial_number"])
                clean_devices.append(device_data)

        output_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_devices": len(clean_devices),
            "genieacs_url": GENIEACS_URL,
            "devices": clean_devices
        }

        filename = f"genieacs_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Datos guardados en: {filename}")
        print(f"📊 Total de dispositivos únicos: {len(clean_devices)}")

        # Mostrar resumen con WiFi y contraseñas
        print("\n📱 Resumen de dispositivos con WiFi:")
        print("-" * 120)
        print(f"{'Serial Number':<25} {'Product Class':<20} {'WiFi Networks':<50} {'Contraseñas':<25}")
        print("-" * 120)

        for device in clean_devices:
            serial = str(device.get('serial_number', ''))[:24] + "..." if len(str(device.get('serial_number', ''))) > 24 else str(device.get('serial_number', ''))
            product = str(device.get('product_class', ''))[:19] + "..." if len(str(device.get('product_class', ''))) > 19 else str(device.get('product_class', ''))

            wifi_networks = device.get('wifi_networks', [])
            if wifi_networks:
                # Mostrar SSIDs
                ssids = ', '.join([net['ssid'] for net in wifi_networks[:2]])
                if len(wifi_networks) > 2:
                    ssids += f" (+{len(wifi_networks)-2})"

                # Mostrar contraseñas (ocultas por seguridad)
                passwords = ', '.join([f"{'*' * len(net['password'][:8])}" if net['password'] else 'N/A' for net in wifi_networks[:2]])
            else:
                ssids = "N/A"
                passwords = "N/A"

            print(f"{serial:<25} {product:<20} {ssids:<50} {passwords:<25}")

        # Estadísticas de WiFi
        print("\n📊 Estadísticas de WiFi:")
        devices_with_wifi = sum(1 for d in clean_devices if d.get('wifi_networks'))
        devices_with_passwords = sum(1 for d in clean_devices if any(net.get('password') for net in d.get('wifi_networks', [])))

        print(f"Dispositivos con WiFi configurado: {devices_with_wifi}")
        print(f"Dispositivos con contraseñas WiFi: {devices_with_passwords}")

        # Mostrar ejemplo detallado de redes WiFi
        print("\n🔧 Ejemplo detallado de redes WiFi:")
        for device in clean_devices[:2]:
            if device.get('wifi_networks'):
                print(f"\n  📍 {device.get('serial_number', 'N/A')[:30]}...")
                for i, net in enumerate(device['wifi_networks'][:3]):
                    print(f"    🌐 Red {i+1}: {net['ssid']}")
                    print(f"       🔐 Contraseña: {net['password'] if net['password'] else 'Sin contraseña'}")
                    print(f"       🔒 Seguridad: {net['auth_mode']} / {net['encryption_mode']}")
                    print(f"       ✅ Estado: {'Activa' if net['enabled'] == 'true' else 'Inactiva'}")

        return filename

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error de conexión con GenieACS: {e}")
        return None
    except Exception as e:
        print(f"⚠️ Error inesperado: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    filename = save_devices_to_json()
    if filename:
        print(f"\n🎯 Archivo JSON creado exitosamente: {filename}")
        print("💡 El archivo incluye SSIDs, contraseñas y configuración WiFi completa")
        print("🌐 Ahora puedes usar la interfaz web para visualizar y editar")

        show_content = input("\n¿Quieres ver el contenido del archivo JSON? (s/n): ").lower().strip()
        if show_content == 's':
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                print("\n📄 Contenido del archivo JSON:")
                print(json.dumps(content, indent=2, ensure_ascii=False))
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
    else:
        print("❌ No se pudo crear el archivo JSON")
