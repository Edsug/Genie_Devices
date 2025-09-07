from models import db, User, DeviceContract, WifiPassword, ChangeHistory, DeviceCache
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

class DatabaseService:
    """Servicio para operaciones de base de datos"""

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
        """Almacenar contraseña WiFi"""
        try:
            wifi_pass = WifiPassword.query.filter_by(
                serial_number=serial_number, 
                band=band
            ).first()

            if wifi_pass:
                wifi_pass.ssid = ssid
                wifi_pass.password = password
                wifi_pass.updated_at = datetime.utcnow()
            else:
                wifi_pass = WifiPassword(
                    serial_number=serial_number,
                    band=band,
                    ssid=ssid,
                    password=password
                )
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
        """Obtener contraseña WiFi almacenada"""
        try:
            wifi_pass = WifiPassword.query.filter_by(
                serial_number=serial_number, 
                band=band
            ).first()
            return wifi_pass.password if wifi_pass else ""
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
            db.session.commit()
            logger.info(f"✅ Usuario deshabilitado: {user.username}")
            return True, f"Usuario {user.username} eliminado"
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"❌ Error eliminando usuario: {e}")
            return False, str(e)
