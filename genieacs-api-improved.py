
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

        # Si llegamos aquí y current es un dict con _value, devolverlo
        if isinstance(current, dict) and '_value' in current:
            return str(current['_value'])  # Asegurar que siempre sea string
        elif isinstance(current, dict):
            return default  # Si es dict pero no tiene _value, devolver default
        return str(current) if current is not None else default
    except (KeyError, TypeError):
        return default

def clean_and_filter_ssids(ssid_list):
    """Limpiar y filtrar SSIDs para mostrar solo los principales y útiles"""
    if not ssid_list or not isinstance(ssid_list, list):
        return []

    # Patrones para identificar SSIDs principales vs secundarios/prueba
    main_patterns = [
        r'^[A-Za-z].*[0-9].*$',  # Contiene letras y números (ej: Fastnet_F8B1_5G)
        r'^[A-Za-z]{4,}.*$',     # Al menos 4 letras al inicio
        r'^FTTH.*$',             # Redes FTTH
        r'^.*WiFi.*$',           # Contiene WiFi
        r'^.*Net.*$'             # Contiene Net
    ]

    # Patrones para filtrar SSIDs no deseados
    exclude_patterns = [
        r'^AP-[0-9]+$',          # AP-1, AP-2, etc.
        r'^Test.*$',             # Redes de prueba
        r'^test.*$',             # test en minúsculas
        r'^Guest.*$',            # Redes de invitados genéricas
        r'^.*_test$',            # Terminan en _test
        r'^[0-9]+$'              # Solo números
    ]

    cleaned_ssids = []
    seen_ssids = set()

    # Primera pasada: recopilar y limpiar SSIDs
    for ssid in ssid_list:
        ssid_clean = str(ssid).strip()
        if not ssid_clean or ssid_clean in seen_ssids:
            continue

        # Verificar si debe ser excluido
        should_exclude = any(re.match(pattern, ssid_clean, re.IGNORECASE) 
                           for pattern in exclude_patterns)

        if not should_exclude:
            cleaned_ssids.append(ssid_clean)
            seen_ssids.add(ssid_clean)

    # Segunda pasada: priorizar SSIDs principales
    priority_ssids = []
    other_ssids = []

    for ssid in cleaned_ssids:
        is_main = any(re.match(pattern, ssid, re.IGNORECASE) 
                     for pattern in main_patterns)

        if is_main:
            priority_ssids.append(ssid)
        else:
            other_ssids.append(ssid)

    # Combinar: máximo 2 SSIDs, priorizando los principales
    final_ssids = priority_ssids[:2]
    if len(final_ssids) < 2:
        remaining_slots = 2 - len(final_ssids)
        final_ssids.extend(other_ssids[:remaining_slots])

    return final_ssids

def extract_interface_data(device):
    """Extraer datos específicos del dispositivo desde GenieACS"""
    # Serial number (ID del dispositivo decodificado)
    serial_number = unquote(device.get("_id", ""))

    device_data = {
        "serial_number": serial_number,
        "product_class": "",
        "software_version": "",
        "hardware_version": "",
        "manufacturer": "",
        "model_name": "",
        "ip": "",
        "ssid": [],  # Lista para múltiples SSIDs
        "last_inform": "",
        "connection_url": "",
        "mac_address": "",
        "tags": []
    }

    # Acceder a InternetGatewayDevice si existe
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

                                # También obtener MAC Address
                                if not device_data["mac_address"]:
                                    mac_addr = safe_get_nested_value(ip_conn, ['MACAddress'], "")
                                    if mac_addr:
                                        device_data["mac_address"] = mac_addr

        # SSIDs desde LANDevice -> WLANConfiguration
        lan_devices = igw.get('LANDevice', {})
        raw_ssids = []
        for lan_key, lan_device in lan_devices.items():
            if isinstance(lan_device, dict):
                wlan_configs = lan_device.get('WLANConfiguration', {})
                for wlan_key, wlan_config in wlan_configs.items():
                    if isinstance(wlan_config, dict):
                        ssid = safe_get_nested_value(wlan_config, ['SSID'], "")
                        if ssid and ssid.strip():
                            raw_ssids.append(ssid)

        # Limpiar y filtrar SSIDs
        device_data["ssid"] = clean_and_filter_ssids(raw_ssids)

        # Connection Request URL desde ManagementServer
        mgmt_server = igw.get('ManagementServer', {})
        device_data["connection_url"] = safe_get_nested_value(mgmt_server, ['ConnectionRequestURL'], "")

    # Last inform (timestamp)
    if '_lastInform' in device:
        timestamp = device['_lastInform']
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            try:
                # GenieACS usa milisegundos
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

    # Si no se encontró product class en DeviceInfo, intentar extraerlo del deviceId
    if not device_data["product_class"] and '_deviceId' in device:
        device_id = device['_deviceId']
        if isinstance(device_id, dict) and '_ProductClass' in device_id:
            device_data["product_class"] = str(device_id['_ProductClass'])

    # Asegurar que todos los campos de string sean strings
    for key, value in device_data.items():
        if key != 'ssid' and key != 'tags':  # Estos son listas
            device_data[key] = str(value) if value is not None else ""

    return device_data

def save_devices_to_json():
    """Obtener dispositivos y guardar en JSON con formato de la interfaz"""
    try:
        print("🔄 Conectando a GenieACS...")
        devices = get_devices()
        print(f"📋 Encontrados {len(devices)} dispositivos")

        # Extraer datos de cada dispositivo
        clean_devices = []
        unique_serials = set()  # Para evitar duplicados

        for device in devices:
            device_data = extract_interface_data(device)

            # Solo agregar si no es duplicado
            if device_data["serial_number"] not in unique_serials:
                unique_serials.add(device_data["serial_number"])
                clean_devices.append(device_data)

        # Crear estructura final
        output_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_devices": len(clean_devices),
            "genieacs_url": GENIEACS_URL,
            "devices": clean_devices
        }

        # Guardar en archivo JSON
        filename = f"genieacs_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Datos guardados en: {filename}")
        print(f"📊 Total de dispositivos únicos: {len(clean_devices)}")

        # Mostrar resumen en consola con manejo seguro de tipos
        print("\n📱 Resumen de dispositivos:")
        print("-" * 100)
        print(f"{'Serial Number':<25} {'Product Class':<20} {'Software Version':<20} {'IP':<15} {'SSIDs Principales':<25}")
        print("-" * 100)

        for device in clean_devices:
            # Asegurar que todos los valores sean strings
            serial = str(device.get('serial_number', ''))[:24] + "..." if len(str(device.get('serial_number', ''))) > 24 else str(device.get('serial_number', ''))
            product = str(device.get('product_class', ''))[:19] + "..." if len(str(device.get('product_class', ''))) > 19 else str(device.get('product_class', ''))
            software = str(device.get('software_version', ''))[:19] + "..." if len(str(device.get('software_version', ''))) > 19 else str(device.get('software_version', ''))
            ip = str(device.get('ip', ''))

            # Manejar SSIDs de forma segura
            ssid_list = device.get('ssid', [])
            if isinstance(ssid_list, list) and ssid_list:
                ssids = ', '.join(str(s) for s in ssid_list)
            else:
                ssids = "N/A"

            print(f"{serial:<25} {product:<20} {software:<20} {ip:<15} {ssids:<25}")

        # Mostrar estadísticas adicionales
        print("\n📊 Estadísticas:")
        devices_with_product = sum(1 for d in clean_devices if d.get('product_class'))
        devices_with_software = sum(1 for d in clean_devices if d.get('software_version'))
        devices_with_ip = sum(1 for d in clean_devices if d.get('ip'))
        devices_with_ssid = sum(1 for d in clean_devices if d.get('ssid'))

        print(f"Dispositivos con Product Class: {devices_with_product}")
        print(f"Dispositivos con Software Version: {devices_with_software}")
        print(f"Dispositivos con IP: {devices_with_ip}")
        print(f"Dispositivos con SSID: {devices_with_ssid}")

        # Mostrar ejemplo de SSIDs limpiados
        print("\n🔧 Ejemplo de limpieza de SSIDs:")
        for device in clean_devices[:3]:  # Mostrar primeros 3 dispositivos
            if device.get('ssid'):
                print(f"  {device.get('serial_number', 'N/A')[:20]}... -> SSIDs: {device['ssid']}")

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
        print("💡 El archivo contiene campos limpios y SSIDs filtrados")
        print("🌐 Ahora puedes usar la interfaz web ejecutando: python app.py")

        # Opción para mostrar el contenido del archivo
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
