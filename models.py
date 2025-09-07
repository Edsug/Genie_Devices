from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib

db = SQLAlchemy()

def hash_password(password):
    """Encriptar contraseña usando SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

class User(db.Model):
    """Modelo de usuario del sistema"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(256), nullable=False)  # SHA-256 hash
    role = db.Column(db.String(20), nullable=False, default='callcenter')
    theme = db.Column(db.String(10), nullable=False, default='system')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Relaciones
    device_contracts = db.relationship('DeviceContract', backref='updated_by_user', lazy=True)
    change_history = db.relationship('ChangeHistory', backref='user', lazy=True)

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
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }

    def __repr__(self):
        return f'<User {self.username}>'

class DeviceContract(db.Model):
    """Modelo para almacenar contratos de dispositivos (SOLO LOCAL)"""
    __tablename__ = 'device_contracts'

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    contract_number = db.Column(db.String(50), nullable=True, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'contract_number': self.contract_number,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by
        }

    def __repr__(self):
        return f'<DeviceContract {self.serial_number}: {self.contract_number}>'

class WifiPassword(db.Model):
    """Modelo para almacenar contraseñas WiFi actuales"""
    __tablename__ = 'wifi_passwords'

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), nullable=False, index=True)
    band = db.Column(db.String(10), nullable=False)  # '2.4GHz' o '5GHz'
    ssid = db.Column(db.String(100), nullable=False)
    password = db.Column(db.Text, nullable=True)  # Contraseña en texto plano para WiFi
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Índice único compuesto
    __table_args__ = (
        db.UniqueConstraint('serial_number', 'band', name='unique_device_band'),
        db.Index('idx_serial_band', 'serial_number', 'band'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'serial_number': self.serial_number,
            'band': self.band,
            'ssid': self.ssid,
            'password': self.password,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<WifiPassword {self.serial_number}:{self.band}>'

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

class DeviceCache(db.Model):
    """Modelo para cache de dispositivos (opcional para optimización futura)"""
    __tablename__ = 'device_cache'

    serial_number = db.Column(db.String(100), primary_key=True)
    product_class = db.Column(db.String(50), nullable=True)
    software_version = db.Column(db.String(50), nullable=True)
    hardware_version = db.Column(db.String(50), nullable=True)
    ip = db.Column(db.String(45), nullable=True)  # IPv4/IPv6
    mac = db.Column(db.String(17), nullable=True)
    last_inform = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.Text, nullable=True)  # JSON string
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

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
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<DeviceCache {self.serial_number}>'
