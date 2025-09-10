from models import db, User, DeviceContract, WifiPassword, ChangeHistory, DeviceInfo, CSVImportHistory, DeviceCache
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import and_, or_, func
import logging

logger = logging.getLogger(__name__)

class DatabaseService:
    """Servicio actualizado para operaciones de base de datos con soporte CSV"""

    @staticmethod
    def create_default_users():
        """Crear usuarios por defecto del sistema"""
        try:
            # Usuario NOC (superadmin)
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', role='noc', theme='system')
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                logger.info("✅ Usuario admin (NOC) creado")

            # Usuario Informática
            if not User.query.filter_by(username='informatica').first():
                info_user = User(username='informatica', role='informatica', theme='system')
                info_user.set_password('info123')
                db.session.add(info_user)
                logger.info("✅ Usuario informatica creado")

            # Usuario Call Center
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
                # Actualizar último login
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
    def create_user(username, password, role='callcenter', theme='system'):
        """Crear nuevo usuario"""
        try:
            if User.query.filter_by(username=username).first():
                return False, "El usuario ya existe"

            user = User(username=username, role=role, theme=theme)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"✅ Usuario {username} creado con rol {role}")
            return True, "Usuario creado exitosamente"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error creando usuario: {e}")
            return False, str(e)

    @staticmethod
    def update_user_theme(user_id, theme):
        """Actualizar tema del usuario"""
        try:
            user = User.query.get(user_id)
            if user:
                user.theme = theme
                user.updated_at = datetime.utcnow()
                db.session.commit()
                return True, "Tema actualizado"
            return False, "Usuario no encontrado"
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error actualizando tema: {e}")
            return False, str(e)

    @staticmethod
    def get_device_contract(serial_number):
        """Obtener contrato de dispositivo"""
        try:
            contract = DeviceContract.query.filter_by(serial_number=serial_number).first()
            return contract.contract_number if contract else ""
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo contrato: {e}")
            return ""

    @staticmethod
    def store_contract(serial_number, contract_number, user_id=None):
        """Almacenar contrato de dispositivo"""
        try:
            contract = DeviceContract.query.filter_by(serial_number=serial_number).first()

            if contract:
                contract.contract_number = contract_number
                contract.updated_by = user_id
                contract.updated_at = datetime.utcnow()
            else:
                contract = DeviceContract(
                    serial_number=serial_number,
                    contract_number=contract_number,
                    updated_by=user_id
                )
                db.session.add(contract)

            db.session.commit()
            logger.info(f"✅ Contrato actualizado: {serial_number} -> {contract_number}")
            return True, "Contrato actualizado"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error almacenando contrato: {e}")
            return False, str(e)

    @staticmethod
    def store_password(serial_number, band, ssid, password):
        """Almacenar contraseña WiFi cifrada"""
        try:
            wifi_pass = WifiPassword.query.filter_by(
                serial_number=serial_number,
                band=band
            ).first()

            if wifi_pass:
                wifi_pass.ssid = ssid
                wifi_pass.password = password  # Se cifra automáticamente
                wifi_pass.updated_at = datetime.utcnow()
            else:
                wifi_pass = WifiPassword(
                    serial_number=serial_number,
                    band=band,
                    ssid=ssid
                )
                wifi_pass.password = password  # Se cifra automáticamente
                db.session.add(wifi_pass)

            db.session.commit()
            logger.info(f"✅ Contraseña WiFi actualizada: {serial_number}:{band}")
            return True, "Contraseña almacenada"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error almacenando contraseña: {e}")
            return False, str(e)

    @staticmethod
    def get_stored_password(serial_number, band):
        """Obtener contraseña WiFi almacenada y descifrada"""
        try:
            wifi_pass = WifiPassword.query.filter_by(
                serial_number=serial_number,
                band=band
            ).first()
            return wifi_pass.password if wifi_pass else ""  # Se descifra automáticamente
        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo contraseña: {e}")
            return ""

    @staticmethod
    def store_change_history(serial_number, product_class, band, change_type,
                           old_value, new_value, ssid=None, contract_number=None,
                           user_id=None, username=None):
        """Almacenar historial de cambios"""
        try:
            # Normalizar contraseñas para el historial
            if change_type == 'PASSWORD':
                old_value = "Sin contraseña" if not old_value or len(old_value) < 8 else old_value
                new_value = "Sin contraseña" if not new_value or len(new_value) < 8 else new_value

            history = ChangeHistory(
                serial_number=serial_number,
                product_class=product_class,
                band=band,
                change_type=change_type,
                old_value=old_value,
                new_value=new_value,
                ssid=ssid,
                contract_number=contract_number,
                user_id=user_id,
                username=username
            )

            db.session.add(history)
            db.session.commit()
            logger.info(f"✅ Historial guardado: {serial_number}:{change_type}")
            return True, "Historial guardado"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error guardando historial: {e}")
            return False, str(e)

    @staticmethod
    def get_change_history(limit=100, serial_filter=None, contract_filter=None,
                          user_filter=None, ssid_filter=None):
        """Obtener historial de cambios con filtros"""
        try:
            query = ChangeHistory.query

            if serial_filter:
                query = query.filter(ChangeHistory.serial_number.contains(serial_filter))
            if contract_filter:
                query = query.filter(ChangeHistory.contract_number.contains(contract_filter))
            if user_filter:
                query = query.filter(ChangeHistory.username.contains(user_filter))
            if ssid_filter:
                query = query.filter(ChangeHistory.ssid.contains(ssid_filter))

            history = query.order_by(ChangeHistory.timestamp.desc()).limit(limit).all()
            return [h.to_dict() for h in history]

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo historial: {e}")
            return []

    @staticmethod
    def is_device_configured(serial_number):
        """Verificar si un dispositivo está configurado"""
        try:
            # Verificar cambios de contraseña en ambas bandas
            password_changes = ChangeHistory.query.filter_by(
                serial_number=serial_number,
                change_type='PASSWORD'
            ).all()

            bands_changed = set(change.band for change in password_changes)
            has_passwords = '2.4GHz' in bands_changed and '5GHz' in bands_changed

            # Verificar contrato
            contract = DeviceContract.query.filter_by(serial_number=serial_number).first()
            has_contract = contract and contract.contract_number and contract.contract_number.strip()

            return has_passwords and has_contract

        except SQLAlchemyError as e:
            logger.error(f"❌ Error verificando configuración: {e}")
            return False

    @staticmethod
    def get_all_users(current_user_role='callcenter'):
        """Obtener todos los usuarios según permisos"""
        try:
            if current_user_role == 'noc':
                users = User.query.filter_by(is_active=True).order_by(User.username).all()
            else:
                # Informática solo puede ver callcenter
                users = User.query.filter_by(role='callcenter', is_active=True).order_by(User.username).all()

            return [user.to_dict() for user in users]

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo usuarios: {e}")
            return []

    @staticmethod
    def delete_user(user_id, current_user_role='callcenter'):
        """Eliminar usuario"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, "Usuario no encontrado"

            if user.username == 'admin':
                return False, "No se puede eliminar el usuario admin principal"

            # Verificar permisos
            if current_user_role != 'noc' and user.role != 'callcenter':
                return False, "Sin permisos para eliminar este usuario"

            # Soft delete
            user.is_active = False
            user.updated_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"✅ Usuario deshabilitado: {user.username}")
            return True, f"Usuario {user.username} eliminado"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error eliminando usuario: {e}")
            return False, str(e)

    # NUEVAS FUNCIONES PARA SOPORTE CSV

    @staticmethod
    def store_device_info(device_serial, mac_address=None, ip_address=None, 
                         ns=None, model=None):
        """Almacenar información adicional del dispositivo"""
        try:
            device_info = DeviceInfo.query.filter_by(device_serial=device_serial).first()

            if device_info:
                # Actualizar información existente
                if mac_address:
                    device_info.mac_address = mac_address
                if ip_address:
                    device_info.ip_address = ip_address
                if ns:
                    device_info.ns = ns
                if model:
                    device_info.model = model
                device_info.updated_at = datetime.utcnow()
            else:
                # Crear nueva información
                device_info = DeviceInfo(
                    device_serial=device_serial,
                    mac_address=mac_address,
                    ip_address=ip_address,
                    ns=ns,
                    model=model
                )
                db.session.add(device_info)

            db.session.commit()
            logger.info(f"✅ Información de dispositivo actualizada: {device_serial}")
            return True, "Información almacenada"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error almacenando información del dispositivo: {e}")
            return False, str(e)

    @staticmethod
    def get_device_full_info(device_serial):
        """Obtener información completa de un dispositivo"""
        try:
            # Información básica
            contract = DeviceContract.query.filter_by(serial_number=device_serial).first()
            device_info = DeviceInfo.query.filter_by(device_serial=device_serial).first()
            
            # Contraseñas WiFi
            wifi_passwords = WifiPassword.query.filter_by(serial_number=device_serial).all()
            
            result = {
                'serial_number': device_serial,
                'contract_number': contract.contract_number if contract else None,
                'customer_name': contract.get_customer_name() if contract else None,
                'mac_address': device_info.mac_address if device_info else None,
                'ip_address': device_info.ip_address if device_info else None,
                'ns': device_info.ns if device_info else None,
                'model': device_info.model if device_info else None,
                'wifi_passwords': {pwd.band: pwd.password for pwd in wifi_passwords},
                'last_updated': max(
                    contract.updated_at if contract else datetime.min,
                    device_info.updated_at if device_info else datetime.min
                ).isoformat() if (contract or device_info) else None
            }
            
            return result

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo información completa: {e}")
            return {}

    @staticmethod
    def get_csv_import_history(limit=50):
        """Obtener historial de importaciones CSV"""
        try:
            imports = CSVImportHistory.query.order_by(
                CSVImportHistory.created_at.desc()
            ).limit(limit).all()
            
            return [import_record.to_dict() for import_record in imports]

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo historial CSV: {e}")
            return []

    @staticmethod
    def get_devices_with_missing_data():
        """Obtener estadísticas de dispositivos con datos faltantes"""
        try:
            # Dispositivos sin contrato
            devices_without_contract = db.session.query(func.count(ChangeHistory.serial_number.distinct())).filter(
                and_(
                    ChangeHistory.change_type != 'CONTRACT',
                    ~ChangeHistory.serial_number.in_(
                        db.session.query(DeviceContract.serial_number)
                    )
                )
            ).scalar() or 0

            # Dispositivos sin contraseñas WiFi
            devices_without_wifi = db.session.query(func.count(ChangeHistory.serial_number.distinct())).filter(
                and_(
                    ChangeHistory.change_type != 'PASSWORD',
                    ~ChangeHistory.serial_number.in_(
                        db.session.query(WifiPassword.serial_number)
                    )
                )
            ).scalar() or 0

            # Dispositivos sin información adicional
            devices_without_info = db.session.query(func.count(ChangeHistory.serial_number.distinct())).filter(
                ~ChangeHistory.serial_number.in_(
                    db.session.query(DeviceInfo.device_serial)
                )
            ).scalar() or 0

            # Total de dispositivos únicos en historial
            total_devices = db.session.query(func.count(ChangeHistory.serial_number.distinct())).scalar() or 0

            return {
                'total_devices': total_devices,
                'devices_without_contract': devices_without_contract,
                'devices_without_wifi': devices_without_wifi,
                'devices_without_info': devices_without_info,
                'completion_percentage': round(
                    ((total_devices - max(devices_without_contract, devices_without_wifi)) / total_devices * 100) 
                    if total_devices > 0 else 0, 2
                )
            }

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo estadísticas: {e}")
            return {
                'total_devices': 0,
                'devices_without_contract': 0,
                'devices_without_wifi': 0,
                'devices_without_info': 0,
                'completion_percentage': 0
            }

    @staticmethod
    def find_device_by_mac(mac_address):
        """Buscar dispositivo por MAC address"""
        try:
            device_info = DeviceInfo.query.filter_by(mac_address=mac_address.upper()).first()
            return device_info.device_serial if device_info else None
        except SQLAlchemyError as e:
            logger.error(f"❌ Error buscando dispositivo por MAC: {e}")
            return None

    @staticmethod
    def store_contract_with_customer_info(serial_number, contract_number, customer_name, user_id=None):
        """Almacenar contrato con información de cliente"""
        try:
            contract = DeviceContract.query.filter_by(serial_number=serial_number).first()

            if contract:
                contract.contract_number = contract_number
                contract.set_customer_name(customer_name)  # Cifrado automático
                contract.updated_by = user_id
                contract.updated_at = datetime.utcnow()
            else:
                contract = DeviceContract(
                    serial_number=serial_number,
                    contract_number=contract_number,
                    updated_by=user_id
                )
                contract.set_customer_name(customer_name)  # Cifrado automático
                db.session.add(contract)

            db.session.commit()
            logger.info(f"✅ Contrato con cliente actualizado: {serial_number} -> {contract_number}")
            return True, "Contrato y cliente actualizados"

        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error almacenando contrato con cliente: {e}")
            return False, str(e)

    @staticmethod
    def get_import_statistics_summary():
        """Obtener resumen de estadísticas de importación"""
        try:
            # Últimas 24 horas
            since_24h = datetime.utcnow() - timedelta(hours=24)
            
            recent_imports = CSVImportHistory.query.filter(
                CSVImportHistory.created_at >= since_24h
            ).all()
            
            stats = {
                'last_24h': {
                    'total_imports': len(recent_imports),
                    'successful_imports': len([i for i in recent_imports if i.status == 'completed']),
                    'failed_imports': len([i for i in recent_imports if i.status == 'failed']),
                    'records_processed': sum(i.records_processed or 0 for i in recent_imports)
                },
                'by_type': {}
            }
            
            # Por tipo de archivo
            for file_type in ['info1060', 'matched_items']:
                type_imports = [i for i in recent_imports if i.file_type == file_type]
                stats['by_type'][file_type] = {
                    'imports': len(type_imports),
                    'records_processed': sum(i.records_processed or 0 for i in type_imports),
                    'last_import': max([i.created_at for i in type_imports]).isoformat() if type_imports else None
                }
            
            return stats

        except SQLAlchemyError as e:
            logger.error(f"❌ Error obteniendo estadísticas de importación: {e}")
            return {}