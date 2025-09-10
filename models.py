from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet
import base64
import os

db = SQLAlchemy()

# Clave de cifrado para datos sensibles (cambiar en producción)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'GenieACS_WiFi_Manager_2024_Key_32!')
cipher_suite = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY[:32].encode().ljust(32, b'0')))

def hash_password(password):
    """Encriptar contraseña usando SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(data):
    """Cifrar datos sensibles"""
    if not data:
        return ""
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except:
        return data  # Si falla el cifrado, retornar datos originales

def decrypt_data(encrypted_data):
    """Descifrar datos sensibles"""
    if not encrypted_data:
        return ""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return encrypted_data  # Si falla el descifrado, retornar datos originales

class User(db.Model):
    """Modelo de usuario del sistema"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(256), nullable=False)  # SHA-256 hash
    role = db.Column(db.String(20), nullable=False, default='callcenter')
    theme = db.Column(db.String(10), nullable=False, default='system')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Relaciones
    device_contracts = db.relationship('DeviceContract', backref='updated_by_user', lazy=True)
    change_history = db.relationship('ChangeHistory', backref='user', lazy=True)
    csv_imports = db.relationship('CSVImportHistory', backref='user', lazy=True)

    def set_password(self, password):
        """Establecer contraseña encriptada"""
        self.password = hash_password(password)

    def check_password(self, password):
        """Verificar contraseña"""
        return self.password == hash_password(password)

    def to_dict(self):
        """Convertir a diccionario"""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'theme': self.theme,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }

    def __repr__(self):
        return f'<User {self.username}>'

class DeviceContract(db.Model):
    """Modelo para almacenar contratos de dispositivos"""
    __tablename__ = 'device_contracts'

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    contract_number = db.Column(db.String(50), nullable=True, index=True)
    customer_name_encrypted = db.Column(db.Text, nullable=True)  # Nombre cifrado
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def set_customer_name(self, customer_name):
        """Establecer nombre de cliente cifrado"""
        self.customer_name_encrypted = encrypt_data(customer_name) if customer_name else None

    def get_customer_name(self):
        """Obtener nombre de cliente descifrado"""
        return decrypt_data(self.customer_name_encrypted) if self.customer_name_encrypted else None

    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'contract_number': self.contract_number,
            'customer_name': self.get_customer_name(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by
        }

    def __repr__(self):
        return f'<DeviceContract {self.serial_number}:{self.contract_number}>'

class WifiPassword(db.Model):
    """Modelo para almacenar contraseñas WiFi actuales cifradas"""
    __tablename__ = 'wifi_passwords'

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), nullable=False, index=True)
    band = db.Column(db.String(10), nullable=False)  # '2.4GHz' o '5GHz'
    ssid = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.Text, nullable=True)  # Contraseña cifrada
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Índice único compuesto
    __table_args__ = (
        db.UniqueConstraint('serial_number', 'band', name='unique_device_band'),
        db.Index('idx_serial_band', 'serial_number', 'band'),
    )

    def set_password(self, password):
        """Establecer contraseña cifrada"""
        self.password_encrypted = encrypt_data(password) if password else None

    def get_password(self):
        """Obtener contraseña descifrada"""
        return decrypt_data(self.password_encrypted) if self.password_encrypted else ""

    # Propiedad para compatibilidad con código existente
    @property
    def password(self):
        return self.get_password()

    @password.setter
    def password(self, value):
        self.set_password(value)

    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'band': self.band,
            'ssid': self.ssid,
            'password': self.get_password(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<WifiPassword {self.serial_number}:{self.band}>'

class DeviceInfo(db.Model):
    """Modelo para información adicional de dispositivos"""
    __tablename__ = 'device_info'

    id = db.Column(db.Integer, primary_key=True)
    device_serial = db.Column(db.String(100), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=True, index=True)  # MAC address
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4/IPv6
    ns = db.Column(db.String(50), nullable=True)  # Número de NS
    model = db.Column(db.String(50), nullable=True)  # Modelo del dispositivo
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'device_serial': self.device_serial,
            'mac_address': self.mac_address,
            'ip_address': self.ip_address,
            'ns': self.ns,
            'model': self.model,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<DeviceInfo {self.device_serial}>'

class ChangeHistory(db.Model):
    """Modelo para historial de cambios"""
    __tablename__ = 'change_history'

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), nullable=False, index=True)
    product_class = db.Column(db.String(50), nullable=True)
    band = db.Column(db.String(10), nullable=True)  # '2.4GHz', '5GHz' o NULL para contratos
    change_type = db.Column(db.String(20), nullable=False)  # 'SSID', 'PASSWORD', 'CONTRACT'
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    ssid = db.Column(db.String(100), nullable=True)
    contract_number = db.Column(db.String(50), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)  # Respaldo del username
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Índices para búsquedas comunes
    __table_args__ = (
        db.Index('idx_serial_timestamp', 'serial_number', 'timestamp'),
        db.Index('idx_contract_timestamp', 'contract_number', 'timestamp'),
        db.Index('idx_change_type_timestamp', 'change_type', 'timestamp'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'product_class': self.product_class,
            'band': self.band,
            'change_type': self.change_type,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'ssid': self.ssid,
            'contract_number': self.contract_number,
            'user_id': self.user_id,
            'username': self.username,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        return f'<ChangeHistory {self.serial_number}:{self.change_type}>'

class CSVImportHistory(db.Model):
    """Modelo para historial de importaciones CSV"""
    __tablename__ = 'csv_import_history'

    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)  # Nombre del archivo
    file_type = db.Column(db.String(20), nullable=False)  # 'info1060', 'matched_items'
    file_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash para evitar duplicados
    records_processed = db.Column(db.Integer, nullable=True, default=0)
    records_imported = db.Column(db.Integer, nullable=True, default=0)
    records_updated = db.Column(db.Integer, nullable=True, default=0)
    records_skipped = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(20), nullable=False, default='processing')  # 'processing', 'completed', 'failed'
    error_message = db.Column(db.Text, nullable=True)
    processing_time = db.Column(db.Integer, nullable=True)  # Tiempo en segundos
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Índices para búsquedas
    __table_args__ = (
        db.Index('idx_file_type_status', 'file_type', 'status'),
        db.Index('idx_created_at', 'created_at'),
        db.Index('idx_file_hash', 'file_hash'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'file_name': self.file_name,
            'file_type': self.file_type,
            'file_hash': self.file_hash,
            'records_processed': self.records_processed,
            'records_imported': self.records_imported,
            'records_updated': self.records_updated,
            'records_skipped': self.records_skipped,
            'status': self.status,
            'error_message': self.error_message,
            'processing_time': self.processing_time,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<CSVImportHistory {self.file_name}:{self.status}>'

class DeviceCache(db.Model):
    """Modelo para cache de dispositivos (opcional para optimización)"""
    __tablename__ = 'device_cache'

    serial_number = db.Column(db.String(100), primary_key=True)
    product_class = db.Column(db.String(50), nullable=True)
    software_version = db.Column(db.String(50), nullable=True)
    hardware_version = db.Column(db.String(50), nullable=True)
    ip = db.Column(db.String(45), nullable=True)  # IPv4/IPv6
    mac = db.Column(db.String(17), nullable=True)
    last_inform = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.Text, nullable=True)  # JSON string
    cached_data = db.Column(db.Text, nullable=True)  # JSON con datos completos
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    def is_expired(self, current_time=None):
        """Verificar si el cache está expirado"""
        if current_time is None:
            current_time = datetime.utcnow()
        return current_time > self.expires_at

    def to_dict(self):
        return {
            'serial_number': self.serial_number,
            'product_class': self.product_class,
            'software_version': self.software_version,
            'hardware_version': self.hardware_version,
            'ip': self.ip,
            'mac': self.mac,
            'last_inform': self.last_inform,
            'tags': self.tags,
            'cached_data': self.cached_data,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

    def __repr__(self):
        return f'<DeviceCache {self.serial_number}>'