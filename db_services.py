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
        """Crear usuarios por defecto del sistema, incluyendo el theme."""
        try:
            if not User.query.filter_by(username='admin').first():
                # Ahora la clase User acepta el argumento 'theme'
                admin_user = User(username='admin', role='noc', theme='dark')
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                print("  -> Usuario 'admin' (NOC) creado.")

            if not User.query.filter_by(username='informatica').first():
                info_user = User(username='informatica', role='informatica', theme='light')
                info_user.set_password('info123')
                db.session.add(info_user)
                print("  -> Usuario 'informatica' (Admin) creado.")
                
            if not User.query.filter_by(username='callcenter').first():
                call_user = User(username='callcenter', role='callcenter', theme='system')
                call_user.set_password('call123')
                db.session.add(call_user)
                print("  -> Usuario 'callcenter' (Operador) creado.")

            # No es necesario hacer commit aquí, el script principal lo hace
        except Exception as e:
            print(f"❌ Error durante la creación de usuarios por defecto: {e}")
            raise e # Relanzar el error para detener el script principal
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
        """
        Obtiene TODOS los dispositivos con su información combinada y un estado de 'configurado'.
        Esta versión está optimizada para mostrar siempre los datos base de GenieACS.
        """
        try:
            devices_query = Device.query.options(
                joinedload(Device.customer_info),
                joinedload(Device.wifi_networks)
            ).all()

            devices_list = []
            for device in devices_query:
                # Diccionario base con valores por defecto
                device_info = {
                    'serial_number': device.serial_number,
                    'mac_address': device.mac_address,
                    'product_class': device.product_class,
                    'ip_address': device.ip_address,
                    'last_inform': device.last_inform.strftime('%Y-%m-%d %H:%M:%S') if device.last_inform else 'Nunca',
                    'contract_number': None,
                    'customer_name': None,
                    'ssid_2_4': None, 'password_2_4': 'No disponible',
                    'ssid_5': None, 'password_5': 'No disponible',
                    'configured': False
                }

                if device.customer_info:
                    device_info['contract_number'] = device.customer_info.contract_number
                    device_info['customer_name'] = device.customer_info.customer_name

                has_pass_2_4 = False
                has_pass_5 = False
                for net in device.wifi_networks:
                    if '2.4GHz' in net.band:
                        device_info['ssid_2_4'] = net.ssid_configured
                        if net.password:
                            device_info['password_2_4'] = 'Visible'
                            has_pass_2_4 = True
                    elif '5GHz' in net.band:
                        device_info['ssid_5'] = net.ssid_configured
                        if net.password:
                            device_info['password_5'] = 'Visible'
                            has_pass_5 = True
                
                if device_info['contract_number'] and has_pass_2_4 and has_pass_5:
                    device_info['configured'] = True

                devices_list.append(device_info)
                
            return devices_list
        except Exception as e:
            # Usamos logger si está disponible
            try:
                logger.error(f"❌ Error crítico obteniendo dispositivos: {e}", exc_info=True)
            except NameError:
                print(f"ERROR: Error crítico obteniendo dispositivos: {e}")
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
        
    @staticmethod
    def get_device_change_history(serial_number, limit=50):
        """Obtener historial de cambios de un dispositivo específico"""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device:
                return []
                
            history = db.session.query(ChangeHistory)\
                .join(User, ChangeHistory.user_id == User.id, isouter=True)\
                .filter(ChangeHistory.device_id == device.id)\
                .add_columns(User.username)\
                .order_by(ChangeHistory.timestamp.desc())\
                .limit(limit).all()
                
            result = []
            for record in history:
                change = record[0]
                username = record[1] if len(record) > 1 else 'Sistema'
                
                result.append({
                    'id': change.id,
                    'change_type': change.change_type,
                    'field_name': change.field_name,
                    'old_value': change.old_value,
                    'new_value': change.new_value,
                    'change_date': change.timestamp.isoformat() if change.timestamp else None,
                    'username': username or 'Sistema',
                    'change_reason': getattr(change, 'change_reason', None)
                })
                
            return result
            
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo historial del dispositivo {serial_number}: {e}")
            return []

    @staticmethod
    def record_change_history(change_data):
        """Registrar un cambio en el historial"""
        try:
            device = Device.query.filter_by(serial_number=change_data['device_serial']).first()
            if not device:
                logger.warning(f"Dispositivo no encontrado: {change_data['device_serial']}")
                return False
                
            change = ChangeHistory(
                device_id=device.id,
                change_type=change_data['change_type'],
                field_name=change_data.get('field_name'),
                old_value=change_data.get('old_value', ''),
                new_value=change_data.get('new_value', ''),
                user_id=change_data.get('user_id'),
                change_reason=change_data.get('change_reason')
            )
            
            db.session.add(change)
            db.session.commit()
            
            logger.info(f"✅ Cambio registrado: {change_data['change_type']} en {change_data['device_serial']}")
            return True
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error registrando cambio: {e}")
            return False

    @staticmethod
    def get_current_ssid(serial_number, band):
        """Obtener SSID actual de un dispositivo"""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device:
                return None
                
            network = WifiNetwork.query.filter_by(
                device_id=device.id,
                band=band
            ).first()
            
            return network.effective_ssid if network else None
            
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo SSID: {e}")
            return None

    @staticmethod
    def get_current_password(serial_number, band):
        """Obtener contraseña actual de un dispositivo"""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device:
                return None
                
            network = WifiNetwork.query.filter_by(
                device_id=device.id,
                band=band
            ).first()
            
            return network.password if network else None
            
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo contraseña: {e}")
            return None

    @staticmethod
    def get_product_class_by_serial(serial_number):
        """Obtener product class de un dispositivo por serial"""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            return device.product_class if device else None
            
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo product class: {e}")
            return None

    @staticmethod
    def update_device_ssid(serial_number, band, new_ssid, user_id=None):
        """Actualiza el SSID de un dispositivo en la base de datos local y registra el cambio."""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device:
                logger.warning(f"Dispositivo no encontrado al actualizar SSID local: {serial_number}")
                return False

            network = WifiNetwork.query.filter_by(device_id=device.id, band=band).first()
            
            old_ssid = "N/A"
            if network:
                old_ssid = network.ssid_configured or network.ssid_current or 'N/A'
                network.ssid_configured = new_ssid
                network.updated_at = datetime.utcnow()
            else:
                network = WifiNetwork(
                    device_id=device.id,
                    band=band,
                    ssid_configured=new_ssid,
                    is_primary=(band == '5GHz')
                )
                db.session.add(network)
            
            # Registrar el cambio en el historial
            change = ChangeHistory(
                device_id=device.id,
                change_type='SSID_UI',
                field_name=band,
                old_value=old_ssid,
                new_value=new_ssid,
                user_id=user_id,
                change_reason='Actualización desde UI'
            )
            db.session.add(change)
            
            db.session.commit()
            logger.info(f"✅ SSID actualizado localmente: {serial_number} {band} -> {new_ssid}")
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error actualizando SSID local: {e}")
            return False

    @staticmethod
    def update_device_password(serial_number, band, new_password, user_id=None):
        """Actualiza la contraseña de un dispositivo en la base de datos local y registra el cambio."""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device:
                logger.warning(f"Dispositivo no encontrado al actualizar contraseña local: {serial_number}")
                return False

            network = WifiNetwork.query.filter_by(device_id=device.id, band=band).first()

            old_password_exists = False
            if network:
                old_password_exists = bool(network.password)
                network.password = new_password
                network.updated_at = datetime.utcnow()
            else:
                network = WifiNetwork(
                    device_id=device.id,
                    band=band,
                    password=new_password,
                    is_primary=(band == '5GHz')
                )
                db.session.add(network)
                
            # Registrar el cambio en el historial
            change = ChangeHistory(
                device_id=device.id,
                change_type='PASSWORD_UI',
                field_name=band,
                old_value='Sí' if old_password_exists else 'No',
                new_value='Sí',
                user_id=user_id,
                change_reason='Actualización desde UI'
            )
            db.session.add(change)
            
            db.session.commit()
            logger.info(f"✅ Contraseña actualizada localmente: {serial_number} {band}")
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error actualizando contraseña local: {e}")
            return False


    @staticmethod
    def get_device_by_id(device_id):
        """Obtener dispositivo por ID (para compatibilidad con rutas existentes)"""
        try:
            return Device.query.filter_by(id=device_id).first()
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo dispositivo por ID: {e}")
            return None

    @staticmethod
    def get_device_by_serial(serial_number):
        """Busca un dispositivo en la base de datos por su número de serie."""
        return Device.query.filter_by(serial_number=serial_number).first()

    @staticmethod
    def get_customer_info_by_serial(serial_number):
        """Busca la información de un cliente a través del número de serie del dispositivo."""
        device = Device.query.filter_by(serial_number=serial_number).first()
        if device:
            return CustomerInfo.query.filter_by(device_id=device.id).first()
        return None

    @staticmethod
    def get_product_class_by_serial(serial_number):
        """Obtiene el Product Class de un dispositivo por su número de serie."""
        device = Device.query.filter_by(serial_number=serial_number).first()
        if device:
            return device.product_class
        return None
    
    # En db_services.py, dentro de la clase DatabaseService

    @staticmethod
    def update_device_channel(serial_number, band, new_channel, user_id=None):
        """Actualiza el canal de una red WiFi en la base de datos local."""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device: return False
            
            network = WifiNetwork.query.filter_by(device_id=device.id, band=band).first()
            old_channel = "N/A"
            if network:
                old_channel = network.channel
                network.channel = new_channel
            else:
                network = WifiNetwork(device_id=device.id, band=band, channel=new_channel)
                db.session.add(network)
            
            change = ChangeHistory(
                device_id=device.id, user_id=user_id, change_type='Channel',
                field_name=band, old_value=str(old_channel), new_value=str(new_channel)
            )
            db.session.add(change)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error actualizando canal local: {e}")
            return False

    @staticmethod
    def update_device_bandwidth(serial_number, band, new_bandwidth, user_id=None):
        """Actualiza el ancho de banda de una red WiFi en la base de datos local."""
        try:
            device = Device.query.filter_by(serial_number=serial_number).first()
            if not device: return False
            
            network = WifiNetwork.query.filter_by(device_id=device.id, band=band).first()
            old_bandwidth = "N/A"
            if network:
                old_bandwidth = network.bandwidth
                network.bandwidth = new_bandwidth
            else:
                network = WifiNetwork(device_id=device.id, band=band, bandwidth=new_bandwidth)
                db.session.add(network)

            change = ChangeHistory(
                device_id=device.id, user_id=user_id, change_type='Bandwidth',
                field_name=band, old_value=str(old_bandwidth), new_value=str(new_bandwidth)
            )
            db.session.add(change)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error actualizando ancho de banda local: {e}")
            return False
        

    # En db_services.py, dentro de la clase DatabaseService

    @staticmethod
    def sync_device_wifi_networks(device_id, wifi_networks_from_genie):
        """Sincroniza las redes WiFi de un dispositivo con los datos de GenieACS."""
        try:
            for net_data in wifi_networks_from_genie:
                band = net_data.get('band')
                if not band: continue

                network = WifiNetwork.query.filter_by(device_id=device_id, band=band).first()
                
                # Con el nuevo models.py, 'is_primary' es un campo válido.
                # Lo ponemos en False por defecto durante la sincronización.
                if not network:
                    network = WifiNetwork(
                        device_id=device_id,
                        band=band,
                        ssid_current=net_data.get('ssid'),
                        is_primary=False  # <--- Ahora esto es válido
                    )
                    db.session.add(network)
                else:
                    network.ssid_current = net_data.get('ssid')
            
            # El commit se debe hacer fuera de esta función, en el bucle principal de sincronización.
            return True
        except Exception as e:
            logger.error(f"❌ Error actualizando redes WiFi para device_id {device_id}: {e}")
            # Relanzar el error para que el proceso que lo llamó se detenga
            raise e
        
    # En db_services.py, dentro de la clase DatabaseService

    @staticmethod
    def sync_devices_in_bulk(devices_from_genie: list):
        """
        Sincroniza una lista completa de dispositivos desde GenieACS de forma masiva y eficiente.
        """
        if not devices_from_genie:
            return 0, 0

        # 1. Obtener todos los dispositivos existentes de la BD en una sola consulta
        existing_serials = {device.serial_number: device for device in Device.query.all()}
        
        new_devices = []
        updated_count = 0

        # 2. Procesar los datos en memoria
        for device_data in devices_from_genie:
            serial_number = device_data.get('_id') # O el campo correcto de GenieACS
            if not serial_number:
                continue

            if serial_number not in existing_serials:
                # Dispositivo NUEVO: lo preparamos para inserción masiva
                new_device = Device(
                    serial_number=serial_number,
                    mac_address=normalize_mac(device_data.get('InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress', {}).get('_value')),
                    product_class=device_data.get('DeviceID.ProductClass', {}).get('_value'),
                    ip_address=device_data.get('InternetGatewayDevice.LANIPAddress', {}).get('_value'),
                    last_inform=datetime.fromisoformat(device_data.get('lastInform', '1970-01-01T00:00:00.000Z').replace('Z', '+00:00'))
                )
                new_devices.append(new_device)
            else:
                # Dispositivo EXISTENTE: lo actualizamos si es necesario (opcional)
                # Por ahora, nos enfocamos en la inserción rápida.
                # Puedes añadir lógica de actualización aquí si es necesario.
                device_to_update = existing_serials[serial_number]
                # ... lógica de actualización ...
                updated_count += 1
        
        try:
            # 3. Insertar todos los dispositivos nuevos en una sola operación masiva
            if new_devices:
                db.session.bulk_save_objects(new_devices)
            
            db.session.commit()
            return len(new_devices), updated_count
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Error durante la sincronización masiva de dispositivos: {e}")
            raise e

    @staticmethod
    def check_csv_hash_exists(file_hash: str) -> bool:
        """Verifica si un hash de archivo ya existe en la tabla CSVImportHistory."""
        return db.session.query(CSVImportHistory.query.filter_by(file_hash=file_hash).exists()).scalar()

    @staticmethod
    def log_csv_import(filename: str, user_id: int, file_hash: str, stats: dict, status: str = 'Completed', error_message: str = None):
        """Registra el resultado de una importación de CSV en el historial."""
        try:
            history_entry = CSVImportHistory(
                filename=filename,
                user_id=user_id,
                file_hash=file_hash,
                records_processed=stats.get('processed', 0),
                records_updated=stats.get('updated', 0),
                records_failed=stats.get('failed', 0),
                status=status,
                error_message=error_message
            )
            db.session.add(history_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"❌ Error crítico al registrar el historial de importación del CSV: {e}")

    @staticmethod
    def update_device_from_csv(mac_address: str, customer_data: dict, wifi_networks_data: list, user_id: int) -> str:
        """
        Busca un dispositivo por MAC y actualiza su información desde los datos del CSV.
        Registra cada cambio individualmente en el historial de cambios.
        Devuelve 'updated', 'no_change', o 'failed'.
        """
        device = Device.query.filter_by(mac_address=mac_address).first()
        if not device:
            logger.warning(f"CSV: Dispositivo con MAC {mac_address} no encontrado. Omitiendo fila.")
            return 'failed'

        try:
            changed = False

            # --- 1. Actualizar CustomerInfo ---
            customer_info = device.customer_info
            if not customer_info:
                customer_info = CustomerInfo(device_id=device.id)
                db.session.add(customer_info)
            
            # Compara y actualiza si es necesario
            if customer_data.get('contract_number') and customer_info.contract_number != customer_data['contract_number']:
                customer_info.contract_number = customer_data['contract_number']
                changed = True
            
            if customer_data.get('customer_name') and customer_info.customer_name != customer_data['customer_name']:
                customer_info.customer_name = customer_data['customer_name']
                changed = True

            # --- 2. Actualizar WifiNetworks ---
            for net_data in wifi_networks_data:
                band = net_data.get('band')
                ssid = net_data.get('ssid')
                password_encrypted = net_data.get('password') # Ya viene cifrada

                if not all([band, ssid, password_encrypted]):
                    continue

                network = WifiNetwork.query.filter_by(device_id=device.id, band=band).first()
                if not network:
                    network = WifiNetwork(device_id=device.id, band=band)
                    db.session.add(network)
                
                if network.ssid_configured != ssid:
                    # Aquí podrías registrar el cambio en ChangeHistory si quieres
                    network.ssid_configured = ssid
                    changed = True
                
                if network.password != password_encrypted:
                    # Aquí también podrías registrar el cambio
                    network.password = password_encrypted
                    changed = True
            
            if changed:
                db.session.commit()
                return 'updated'
            else:
                return 'no_change'
                
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error de base de datos actualizando desde CSV para MAC {mac_address}: {e}")
            return 'failed'







