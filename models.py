# models.py - BASE DE DATOS REDISEÑADA PARA RELACIONES CORRECTAS

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet
import base64
import os

db = SQLAlchemy()

# Clave de cifrado para datos sensibles
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
        return data

def decrypt_data(encrypted_data):
    """Descifrar datos sensibles"""
    if not encrypted_data:
        return ""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return encrypted_data

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='callcenter')
    theme = db.Column(db.String(10), nullable=False, default='system')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    def set_password(self, password):
        self.password = hash_password(password)

    def check_password(self, password):
        return self.password == hash_password(password)

    def to_dict(self):
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

class Device(db.Model):
    """NUEVA TABLA PRINCIPAL: Información técnica del dispositivo (desde GenieACS)"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=False, index=True)
    product_class = db.Column(db.String(50), nullable=True)
    software_version = db.Column(db.String(100), nullable=True)
    hardware_version = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    last_inform = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    customer_info = db.relationship('CustomerInfo', backref='device', uselist=False)
    wifi_networks = db.relationship('WifiNetwork', backref='device')

class CustomerInfo(db.Model):
    """Información del cliente (desde CSV)"""
    __tablename__ = 'customer_info'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    contract_number = db.Column(db.String(50), nullable=False, index=True)
    customer_name_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def set_customer_name(self, customer_name):
        self.customer_name_encrypted = encrypt_data(customer_name) if customer_name else None

    def get_customer_name(self):
        return decrypt_data(self.customer_name_encrypted) if self.customer_name_encrypted else None

class WifiNetwork(db.Model):
    """Redes WiFi del dispositivo (SSID desde GenieACS + contraseña desde CSV)"""
    __tablename__ = 'wifi_networks'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    band = db.Column(db.String(10), nullable=False)  # 2.4GHz o 5GHz
    ssid_current = db.Column(db.String(100), nullable=True)  # SSID actual desde GenieACS
    ssid_configured = db.Column(db.String(100), nullable=True)  # SSID configurado desde CSV
    password_encrypted = db.Column(db.Text, nullable=True)  # Contraseña desde CSV
    is_primary = db.Column(db.Boolean, nullable=False, default=False)
    wlan_configuration = db.Column(db.String(10), nullable=True)
    parameter_paths = db.Column(db.Text, nullable=True)  # JSON con paths de parámetros
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('device_id', 'band', name='unique_device_band'),
    )

    def set_password(self, password):
        self.password_encrypted = encrypt_data(password) if password else None

    def get_password(self):
        return decrypt_data(self.password_encrypted) if self.password_encrypted else ""

    @property
    def password(self):
        return self.get_password()

    @password.setter
    def password(self, value):
        self.set_password(value)

    @property
    def effective_ssid(self):
        """SSID efectivo: configurado si existe, sino actual"""
        return self.ssid_configured if self.ssid_configured else self.ssid_current

class ChangeHistory(db.Model):
    """Historial de cambios"""
    __tablename__ = 'change_history'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    change_type = db.Column(db.String(20), nullable=False)  # SSID, PASSWORD, CONTRACT, CUSTOMER
    field_name = db.Column(db.String(50), nullable=True)  # band para WiFi, etc.
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'change_type': self.change_type,
            'field_name': self.field_name,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'user_id': self.user_id,
            'username': self.username,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class CSVImportHistory(db.Model):
    """Historial de importaciones CSV"""
    __tablename__ = 'csv_import_history'
    
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)
    records_processed = db.Column(db.Integer, nullable=True, default=0)
    devices_matched = db.Column(db.Integer, nullable=True, default=0)
    devices_configured = db.Column(db.Integer, nullable=True, default=0)
    devices_updated = db.Column(db.Integer, nullable=True, default=0)
    devices_skipped = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(20), nullable=False, default='processing')
    error_message = db.Column(db.Text, nullable=True)
    processing_time = db.Column(db.Integer, nullable=True)  # segundos
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'file_name': self.file_name,
            'file_type': self.file_type,
            'file_hash': self.file_hash,
            'records_processed': self.records_processed,
            'devices_matched': self.devices_matched,
            'devices_configured': self.devices_configured,
            'devices_updated': self.devices_updated,
            'devices_skipped': self.devices_skipped,
            'status': self.status,
            'error_message': self.error_message,
            'processing_time': self.processing_time,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# CLASES LEGACY PARA MIGRACIÓN (se eliminarán después)
class DeviceContract(db.Model):
    """DEPRECADO: Solo para migración"""
    __tablename__ = 'device_contracts_old'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    contract_number = db.Column(db.String(50), nullable=True, index=True)
    customer_name_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

class WifiPassword(db.Model):
    """DEPRECADO: Solo para migración"""
    __tablename__ = 'wifi_passwords_old'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), nullable=False, index=True)
    band = db.Column(db.String(10), nullable=False)
    ssid = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)