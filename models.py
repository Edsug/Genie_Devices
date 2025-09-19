# models.py - VERSIÓN MAESTRA FINAL

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Lógica de Cifrado
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'GenieACS_WiFi_Manager_2024_Key_32!')
cipher_suite = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY[:32].encode().ljust(32, b'0')))
def encrypt_data(data):
    if not data: return ""
    try: return cipher_suite.encrypt(data.encode()).decode()
    except: return data
def decrypt_data(encrypted_data):
    if not encrypted_data: return ""
    try: return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except: return encrypted_data

db = SQLAlchemy()

# --- Modelos de la Base de Datos ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='guest')
    is_active = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(20), default='system')
    changes = db.relationship('ChangeHistory', back_populates='user', lazy=True)
    csv_imports = db.relationship('CSVImportHistory', back_populates='user', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(255), unique=True, nullable=False)
    mac_address = db.Column(db.String(17), unique=True)
    product_class = db.Column(db.String(100))
    software_version = db.Column(db.String(100))
    hardware_version = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    last_inform = db.Column(db.DateTime)
    tags = db.Column(db.Text)
    customer_info = db.relationship('CustomerInfo', back_populates='device', uselist=False, cascade="all, delete-orphan")
    wifi_networks = db.relationship('WifiNetwork', back_populates='device', cascade="all, delete-orphan")
    history = db.relationship('ChangeHistory', back_populates='device', cascade="all, delete-orphan")

class CustomerInfo(db.Model):
    __tablename__ = 'customer_info'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), unique=True, nullable=False)
    contract_number = db.Column(db.String(100), unique=True)
    customer_name = db.Column(db.String(255))
    device = db.relationship('Device', back_populates='customer_info')

class WifiNetwork(db.Model):
    __tablename__ = 'wifi_networks'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    band = db.Column(db.String(10), nullable=False)
    channel = db.Column(db.Integer)
    bandwidth = db.Column(db.String(20))
    ssid_configured = db.Column(db.String(255))
    ssid_current = db.Column(db.String(255))
    password = db.Column(db.String(512))
    is_primary = db.Column(db.Boolean, default=False)
    device = db.relationship('Device', back_populates='wifi_networks')
    __table_args__ = (db.UniqueConstraint('device_id', 'band', name='_device_band_uc'),)

class ChangeHistory(db.Model):
    __tablename__ = 'change_history'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    change_type = db.Column(db.String(50), nullable=False)
    field_name = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    change_reason = db.Column(db.String(255), nullable=True, default='UI Change')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device = db.relationship('Device', back_populates='history')
    user = db.relationship('User', back_populates='changes')

class CSVImportHistory(db.Model):
    __tablename__ = 'csv_import_history'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    import_time = db.Column(db.DateTime, default=datetime.utcnow)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    records_processed = db.Column(db.Integer, default=0)
    records_added = db.Column(db.Integer, default=0)
    records_updated = db.Column(db.Integer, default=0)
    records_failed = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default='Completed')
    error_message = db.Column(db.Text)
    user = db.relationship('User', back_populates='csv_imports')
