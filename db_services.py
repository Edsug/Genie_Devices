from models import db, User, Device, CustomerInfo, WifiNetwork, ChangeHistory, CSVImportHistory
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import and_, or_, func, text
from sqlalchemy.orm import joinedload
import logging
import json

logger = logging.getLogger(__name__)

def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.strip().upper().replace('-', ':').replace(' ', '')
    if len(mac) == 12 and ':' not in mac:
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    return mac

class DatabaseService:

    """Servicios optimizados para el nuevo esquema de base de datos"""

    @staticmethod
    def create_default_users():
        """Crear usuarios por defecto del sistema"""
        try:
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='noc', theme='system')
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                logger.info("✅ Usuario admin (NOC) creado")

            if not User.query.filter_by(username='informatica').first():
                info_user = User(username='informatica', role='informatica', theme='system')
                info_user.set_password('info123')
                db.session.add(info_user)
                logger.info("✅ Usuario informatica creado")

            if not User.query.filter_by(username='callcenter').first():
                call_user = User(username='callcenter', role='callcenter', theme='system')
                call_user.set_password('call123')
                db.session.add(call_user)
                logger.info("✅ Usuario callcenter creado")

            db.session.commit()
            logger.info("✅ Usuarios por defecto creados exitosamente")
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error creando usuarios por defecto: {e}")
            raise

    @staticmethod
    def get_user_by_credentials(username, password):
        """Obtener usuario por credenciales"""
        try:
            user = User.query.filter_by(username=username, is_active=True).first()
            if user and user.check_password(password):
                user.last_login = datetime.utcnow()
                db.session.commit()
                return user
            return None
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo usuario: {e}")
            return None

    @staticmethod
    def get_user_by_id(user_id):
        """Obtener usuario por ID"""
        try:
            return User.query.filter_by(id=user_id, is_active=True).first()
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo usuario por ID: {e}")
            return None

    @staticmethod
    def store_or_update_device(device_data):
        """Almacenar o actualizar información del dispositivo desde GenieACS"""
        try:
            normalized_mac = normalize_mac(device_data.get('mac'))
            device_data['mac'] = normalized_mac
            device = Device.query.filter_by(serial_number=device_data['serial_number']).first()
            if device:
                device.mac_address = normalized_mac or device.mac_address
                device.product_class = device_data.get('product_class', device.product_class)
                device.software_version = device_data.get('software_version', device.software_version)
                device.hardware_version = device_data.get('hardware_version', device.hardware_version)
                device.ip_address = device_data.get('ip', device.ip_address)
                device.last_inform = device_data.get('last_inform', device.last_inform)
                device.tags = json.dumps(device_data.get('tags', [])) if device_data.get('tags') else device.tags
                device.updated_at = datetime.utcnow()
            else:
                device = Device(
                    serial_number=device_data['serial_number'],
                    mac_address=normalized_mac or '',
                    product_class=device_data.get('product_class', ''),
                    software_version=device_data.get('software_version', ''),
                    hardware_version=device_data.get('hardware_version', ''),
                    ip_address=device_data.get('ip', ''),
                    last_inform=device_data.get('last_inform', ''),
                    tags=json.dumps(device_data.get('tags', [])) if device_data.get('tags') else None
                )
                db.session.add(device)
                db.session.flush()  # Para obtener el ID

            if 'wifi_networks' in device_data:
                DatabaseService._update_wifi_networks(device.id, device_data['wifi_networks'])

            db.session.commit()
            return device
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error almacenando dispositivo: {e}")
            return None

    @staticmethod
    def _update_wifi_networks(device_id, networks_data):
        """Actualizar redes WiFi del dispositivo"""
        try:
            for network_data in networks_data:
                network = WifiNetwork.query.filter_by(
                    device_id=device_id,
                    band=network_data['band']
                ).first()
                if network:
                    network.ssid_current = network_data.get('ssid', network.ssid_current)
                    network.is_primary = network_data.get('is_primary', network.is_primary)
                    network.wlan_configuration = network_data.get('wlan_configuration', network.wlan_configuration)
                    network.parameter_paths = json.dumps(network_data.get('parameter_paths', {}))
                    network.updated_at = datetime.utcnow()
                else:
                    network = WifiNetwork(
                        device_id=device_id,
                        band=network_data['band'],
                        ssid_current=network_data.get('ssid', ''),
                        is_primary=network_data.get('is_primary', False),
                        wlan_configuration=network_data.get('wlan_configuration', ''),
                        parameter_paths=json.dumps(network_data.get('parameter_paths', {}))
                    )
                    db.session.add(network)
        except Exception as e:
            logger.error(f"❌ Error actualizando redes WiFi: {e}")
            raise

    @staticmethod
    def configure_device_from_csv(mac_address, contract_number, customer_name, ssid_24, password_24, ssid_5, password_5, user_id=None):
        """Configurar dispositivo con información del CSV"""
        try:
            normalized_mac = normalize_mac(mac_address)
            device = Device.query.filter_by(mac_address=normalized_mac).first()
            if not device:
                logger.warning(f"⚠️ Dispositivo no encontrado con MAC: {mac_address}")
                return False, "Dispositivo no encontrado"

            customer_info = CustomerInfo.query.filter_by(device_id=device.id).first()
            if customer_info:
                old_contract = customer_info.contract_number
                old_customer = customer_info.get_customer_name()
                customer_info.contract_number = contract_number
                customer_info.set_customer_name(customer_name)
                customer_info.updated_by = user_id
                customer_info.updated_at = datetime.utcnow()
            else:
                customer_info = CustomerInfo(
                    device_id=device.id,
                    contract_number=contract_number,
                    updated_by=user_id
                )
                customer_info.set_customer_name(customer_name)
                db.session.add(customer_info)
                old_contract = None
                old_customer = None

            network_24 = WifiNetwork.query.filter_by(device_id=device.id, band='2.4GHz').first()
            if network_24:
                old_ssid_24 = network_24.ssid_configured
                old_password_24 = network_24.password
                network_24.ssid_configured = ssid_24
                network_24.password = password_24
                network_24.updated_at = datetime.utcnow()
            else:
                network_24 = WifiNetwork(
                    device_id=device.id,
                    band='2.4GHz',
                    ssid_configured=ssid_24,
                    password=password_24,
                    is_primary=False
                )
                db.session.add(network_24)
                old_ssid_24 = None
                old_password_24 = None

            network_5 = WifiNetwork.query.filter_by(device_id=device.id, band='5GHz').first()
            if network_5:
                old_ssid_5 = network_5.ssid_configured
                old_password_5 = network_5.password
                network_5.ssid_configured = ssid_5
                network_5.password = password_5
                network_5.updated_at = datetime.utcnow()
            else:
                network_5 = WifiNetwork(
                    device_id=device.id,
                    band='5GHz',
                    ssid_configured=ssid_5,
                    password=password_5,
                    is_primary=True
                )
                db.session.add(network_5)
                old_ssid_5 = None
                old_password_5 = None

            DatabaseService._record_configuration_changes(
                device.id, user_id,
                old_contract, contract_number,
                old_customer, customer_name,
                old_ssid_24, ssid_24, old_password_24, password_24,
                old_ssid_5, ssid_5, old_password_5, password_5
            )

            db.session.commit()
            logger.info(f"✅ Dispositivo configurado: {device.serial_number} ({mac_address}) - {contract_number}")
            return True, "Dispositivo configurado exitosamente"
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Error configurando dispositivo: {e}")
            return False, str(e)

    @staticmethod
    def _record_configuration_changes(device_id, user_id, old_contract, new_contract, old_customer, new_customer,
                                      old_ssid_24, new_ssid_24, old_password_24, new_password_24,
                                      old_ssid_5, new_ssid_5, old_password_5, new_password_5):
        """Registrar cambios de configuración en el historial"""
        try:
            changes = []
            if old_contract != new_contract:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='CONTRACT',
                    old_value=old_contract or 'Sin contrato',
                    new_value=new_contract,
                    user_id=user_id
                ))
            if old_customer != new_customer:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='CUSTOMER',
                    old_value=old_customer or 'Sin cliente',
                    new_value=new_customer,
                    user_id=user_id
                ))
            if old_ssid_24 != new_ssid_24:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='SSID',
                    field_name='2.4GHz',
                    old_value=old_ssid_24 or 'Sin SSID',
                    new_value=new_ssid_24,
                    user_id=user_id
                ))
            if old_password_24 != new_password_24:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='PASSWORD',
                    field_name='2.4GHz',
                    old_value='Sin contraseña' if not old_password_24 else '***',
                    new_value='***' if new_password_24 else 'Sin contraseña',
                    user_id=user_id
                ))
            if old_ssid_5 != new_ssid_5:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='SSID',
                    field_name='5GHz',
                    old_value=old_ssid_5 or 'Sin SSID',
                    new_value=new_ssid_5,
                    user_id=user_id
                ))
            if old_password_5 != new_password_5:
                changes.append(ChangeHistory(
                    device_id=device_id,
                    change_type='PASSWORD',
                    field_name='5GHz',
                    old_value='Sin contraseña' if not old_password_5 else '***',
                    new_value='***' if new_password_5 else 'Sin contraseña',
                    user_id=user_id
                ))
            for change in changes:
                db.session.add(change)
        except Exception as e:
            logger.error(f"❌ Error registrando cambios: {e}")
            raise

    @staticmethod
    def is_device_configured(device_id):
        """Verificar si un dispositivo está completamente configurado"""
        try:
            customer_info = CustomerInfo.query.filter_by(device_id=device_id).first()
            if not customer_info or not customer_info.contract_number:
                return False
            networks = WifiNetwork.query.filter_by(device_id=device_id).all()
            has_24ghz = False
            has_5ghz = False
            for network in networks:
                if network.band == '2.4GHz' and network.ssid_configured and network.password:
                    has_24ghz = True
                elif network.band == '5GHz' and network.ssid_configured and network.password:
                    has_5ghz = True
            return has_24ghz and has_5ghz
        except SQLAlchemyError as e:
            logger.error(f"❌ Error verificando configuración: {e}")
            return False

    @staticmethod
    def get_all_devices_with_status():
        """Obtener todos los dispositivos con su estado de configuración"""
        try:
            devices = db.session.query(Device) \
                .options(joinedload(Device.customer_info)) \
                .options(joinedload(Device.wifi_networks)) \
                .all()
            result = []
            for device in devices:
                is_configured = DatabaseService.is_device_configured(device.id)
                wifi_networks = []
                for network in device.wifi_networks:
                    wifi_networks.append({
                        'band': network.band,
                        'ssid': network.effective_ssid,
                        'ssid_current': network.ssid_current,
                        'ssid_configured': network.ssid_configured,
                        'password': network.password if is_configured else '',
                        'is_primary': network.is_primary,
                        'wlan_configuration': network.wlan_configuration
                    })
                device_data = {
                    'serial_number': device.serial_number,
                    'mac': device.mac_address,
                    'product_class': device.product_class,
                    'software_version': device.software_version,
                    'hardware_version': device.hardware_version,
                    'ip': device.ip_address,
                    'last_inform': device.last_inform,
                    'tags': json.loads(device.tags) if device.tags else [],
                    'wifi_networks': wifi_networks,
                    'configured': is_configured,
                    'contract_number': device.customer_info.contract_number if device.customer_info else None,
                    'customer_name': device.customer_info.get_customer_name() if device.customer_info else None,
                    'title_ssid': ''
                }
                for network in wifi_networks:
                    if network['band'] == '5GHz' and network['ssid']:
                        device_data['title_ssid'] = network['ssid']
                        break
                result.append(device_data)
            return result
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo dispositivos: {e}")
            return []

    @staticmethod
    def get_unconfigured_devices():
        all_devices = DatabaseService.get_all_devices_with_status()
        return [device for device in all_devices if not device['configured']]

    @staticmethod
    def get_configured_devices():
        all_devices = DatabaseService.get_all_devices_with_status()
        return [device for device in all_devices if device['configured']]

    @staticmethod
    def get_device_by_mac(mac_address):
        try:
            normalized_mac = normalize_mac(mac_address)
            device = Device.query.filter_by(mac_address=normalized_mac).first()
            return device
        except SQLAlchemyError as e:
            logger.error(f"❌ Error buscando dispositivo por MAC: {e}")
            return None

    @staticmethod
    def get_change_history(device_id=None, limit=100):
        try:
            query = db.session.query(ChangeHistory) \
                .join(Device, ChangeHistory.device_id == Device.id) \
                .add_columns(Device.serial_number, Device.mac_address)
            if device_id:
                query = query.filter(ChangeHistory.device_id == device_id)
            history = query.order_by(ChangeHistory.timestamp.desc()).limit(limit).all()
            result = []
            for record in history:
                change = record[0]
                serial = record[1]
                mac = record[2]
                result.append({
                    'id': change.id,
                    'device_id': change.device_id,
                    'serial_number': serial,
                    'mac_address': mac,
                    'change_type': change.change_type,
                    'field_name': change.field_name,
                    'old_value': change.old_value,
                    'new_value': change.new_value,
                    'user_id': change.user_id,
                    'username': change.username,
                    'timestamp': change.timestamp.isoformat() if change.timestamp else None
                })
            return result
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo historial: {e}")
            return []

    @staticmethod
    def get_csv_import_history(limit=50):
        try:
            imports = CSVImportHistory.query.order_by(
                CSVImportHistory.created_at.desc()
            ).limit(limit).all()
            return [import_record.to_dict() for import_record in imports]
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo historial CSV: {e}")
            return []

    @staticmethod
    def get_statistics():
        try:
            stats = {}
            all_devices = DatabaseService.get_all_devices_with_status()
            configured_devices = [d for d in all_devices if d['configured']]
            unconfigured_devices = [d for d in all_devices if not d['configured']]
            stats['devices'] = {
                'total': len(all_devices),
                'configured': len(configured_devices),
                'unconfigured': len(unconfigured_devices),
                'completion_percentage': round((len(configured_devices) / len(all_devices) * 100), 2) if all_devices else 0
            }
            since_date = datetime.utcnow() - timedelta(days=30)
            recent_imports = CSVImportHistory.query.filter(
                CSVImportHistory.created_at >= since_date
            ).all()
            stats['imports'] = {
                'total_imports': len(recent_imports),
                'successful_imports': len([i for i in recent_imports if i.status == 'completed']),
                'failed_imports': len([i for i in recent_imports if i.status == 'failed']),
                'total_devices_processed': sum(i.records_processed or 0 for i in recent_imports),
                'total_devices_configured': sum(i.devices_configured or 0 for i in recent_imports)
            }
            return stats
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo estadísticas: {e}")
            return {}

    @staticmethod
    def cleanup_old_data(days_old=90):
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            deleted_changes = ChangeHistory.query.filter(
                ChangeHistory.timestamp < cutoff_date
            ).delete()
            deleted_imports = CSVImportHistory.query.filter(
                CSVImportHistory.created_at < cutoff_date
            ).delete()
            db.session.commit()
            logger.info(f"🧹 Limpieza completada: {deleted_changes} cambios, {deleted_imports} importaciones")
            return deleted_changes + deleted_imports
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error en limpieza: {e}")
            return 0
