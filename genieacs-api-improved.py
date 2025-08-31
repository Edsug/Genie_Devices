
import requests
import json
from urllib.parse import unquote
from datetime import datetime

GENIEACS_URL = "http://192.168.0.237:7557"
USERNAME = "admin"
PASSWORD = "admin"

# Configuración de parámetros específicos por Product Class según tu Excel
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

def get_devices():
    """Obtener lista completa de dispositivos desde GenieACS"""
    url = f"{GENIEACS_URL}/devices"
    response = requests.get(url, auth=(USERNAME, PASSWORD) if USERNAME else None)
    response.raise_for_status()
    return response.json()

def get_parameter_value(device, parameter_path):
    """Obtener valor de un parámetro específico del dispositivo"""
    try:
        # Navegar por la ruta del parámetro
        current = device
        path_parts = parameter_path.split('.')

        for part in path_parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return ""

        # Si llegamos aquí y current es un dict con _value, devolverlo
        if isinstance(current, dict) and '_value' in current:
            return str(current['_value'])
        elif isinstance(current, dict):
            return ""
        return str(current) if current is not None else ""
    except (KeyError, TypeError, AttributeError):
        return ""

def extract_wifi_networks(device):
    """Extraer redes WiFi específicas basado en Product Class"""
    serial_number = unquote(device.get("_id", ""))

    # Obtener product class
    product_class = ""
    if '_deviceId' in device and isinstance(device['_deviceId'], dict):
        product_class = device['_deviceId'].get('_ProductClass', '')

    # Si no encontramos product class en _deviceId, buscar en DeviceInfo
    if not product_class:
        device_info_path = "InternetGatewayDevice.DeviceInfo.ProductClass"
        product_class = get_parameter_value(device, device_info_path)

    if not product_class or product_class not in DEVICE_PARAMETERS:
        return None

    device_config = DEVICE_PARAMETERS[product_class]

    # Obtener información básica del dispositivo
    device_info = {
        "serial_number": serial_number,
        "product_class": product_class,
        "software_version": get_parameter_value(device, "InternetGatewayDevice.DeviceInfo.SoftwareVersion"),
        "hardware_version": get_parameter_value(device, "InternetGatewayDevice.DeviceInfo.HardwareVersion"),
        "ip": get_parameter_value(device, device_config["ip"]),
        "mac": get_parameter_value(device, device_config["mac"]),
        "last_inform": "",
        "wifi_networks": []
    }

    # Procesar last inform
    if '_lastInform' in device:
        timestamp = device['_lastInform']
        if isinstance(timestamp, (int, float)) and timestamp > 0:
            try:
                dt = datetime.fromtimestamp(timestamp / 1000)
                device_info["last_inform"] = dt.strftime("%d/%m/%Y, %I:%M:%S %p")
            except:
                device_info["last_inform"] = str(timestamp)

    # Extraer redes WiFi (2.4G y 5G)
    networks = []

    # Red 2.4GHz
    if "wifi_2_4" in device_config:
        wifi_2_4 = device_config["wifi_2_4"]
        ssid_2_4 = get_parameter_value(device, wifi_2_4["ssid"])
        if ssid_2_4:
            password_2_4 = get_parameter_value(device, wifi_2_4["password"])
            if not password_2_4:  # Intentar parámetro alternativo
                password_2_4 = get_parameter_value(device, wifi_2_4["password_alt"])

            networks.append({
                "band": "2.4GHz",
                "ssid": ssid_2_4,
                "password": password_2_4,
                "ssid_parameter": wifi_2_4["ssid"],
                "password_parameter": wifi_2_4["password"],
                "password_parameter_alt": wifi_2_4["password_alt"],
                "is_primary": True
            })

    # Red 5GHz
    if "wifi_5" in device_config:
        wifi_5 = device_config["wifi_5"]
        ssid_5 = get_parameter_value(device, wifi_5["ssid"])
        if ssid_5:
            password_5 = get_parameter_value(device, wifi_5["password"])
            if not password_5:  # Intentar parámetro alternativo
                password_5 = get_parameter_value(device, wifi_5["password_alt"])

            networks.append({
                "band": "5GHz",
                "ssid": ssid_5,
                "password": password_5,
                "ssid_parameter": wifi_5["ssid"],
                "password_parameter": wifi_5["password"],
                "password_parameter_alt": wifi_5["password_alt"],
                "is_primary": len(networks) == 0  # Es principal si es la primera red
            })

    device_info["wifi_networks"] = networks

    # Solo retornar si tiene al menos una red WiFi
    if networks:
        return device_info
    return None

def save_devices_to_json():
    """Obtener dispositivos con WiFi y guardar en JSON"""
    try:
        print("🔄 Conectando a GenieACS...")
        devices = get_devices()
        print(f"📋 Encontrados {len(devices)} dispositivos")

        # Extraer dispositivos con WiFi
        wifi_devices = []
        for device in devices:
            wifi_data = extract_wifi_networks(device)
            if wifi_data:
                wifi_devices.append(wifi_data)

        # Crear estructura final
        output_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_devices": len(wifi_devices),
            "genieacs_url": GENIEACS_URL,
            "devices": wifi_devices
        }

        # Guardar archivo
        filename = f"genieacs_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Datos guardados en: {filename}")
        print(f"📊 Total dispositivos con WiFi: {len(wifi_devices)}")

        # Mostrar resumen
        print("\n📱 Resumen de dispositivos WiFi:")
        print("-" * 100)
        print(f"{'Serial Number':<30} {'Product Class':<20} {'Redes WiFi':<25} {'IP':<15}")
        print("-" * 100)

        for device in wifi_devices:
            serial = device['serial_number'][:29] + "..." if len(device['serial_number']) > 29 else device['serial_number']
            product = device['product_class']
            networks = ", ".join([f"{net['band']}: {net['ssid']}" for net in device['wifi_networks']])
            networks = networks[:24] + "..." if len(networks) > 24 else networks
            ip = device['ip']

            print(f"{serial:<30} {product:<20} {networks:<25} {ip:<15}")

        # Mostrar estadísticas
        print("\n📊 Estadísticas:")
        total_networks = sum(len(d['wifi_networks']) for d in wifi_devices)
        devices_with_password = sum(1 for d in wifi_devices 
                                  if any(net['password'] for net in d['wifi_networks']))

        print(f"Total redes WiFi encontradas: {total_networks}")
        print(f"Dispositivos con contraseñas: {devices_with_password}")

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
        print("💡 Solo dispositivos con redes WiFi 2.4G y/o 5G incluidos")

        # Opción para mostrar contenido
        show_content = input("\n¿Ver contenido del archivo JSON? (s/n): ").lower().strip()
        if show_content == 's':
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                print("\n📄 Contenido del archivo JSON:")
                print(json.dumps(content, indent=2, ensure_ascii=False))
            except Exception as e:
                print(f"Error al leer archivo: {e}")
    else:
        print("❌ No se pudo crear el archivo JSON")
