# config_db.py - Configuración actualizada con soporte CSV
import os

# Configuración MySQL con XAMPP (mantén tus credenciales)
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 3306,
    'database': 'genieasc_db',  # Tu base de datos actual
    'username': 'admin',         # Tu usuario actual  
    'password': 'admin',         # Tu contraseña actual
    'charset': 'utf8mb4'
}

# URI de conexión SQLAlchemy
SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_CONFIG['username']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}?charset={DB_CONFIG['charset']}"

SQLALCHEMY_TRACK_MODIFICATIONS = False

SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20,
    'connect_args': {
        'connect_timeout': 60,
        'read_timeout': 60,
        'write_timeout': 60,
        'charset': 'utf8mb4'
    }
}

# Configuración de cifrado para datos sensibles
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'GenieACS_WiFi_Manager_2024_Key_32!')

# Configuración de archivos CSV
CSV_CONFIG = {
    'max_file_size': 50 * 1024 * 1024,  # 50MB
    'allowed_extensions': ['csv'],
    'upload_folder': 'uploads',
    'data_folder': 'data',
    'backup_folder': 'backups',
    'processing_timeout': 300,  # 5 minutos
    'batch_size': 100,  # Procesar en lotes de 100 registros
}

# Configuración de modelos de dispositivos soportados
SUPPORTED_DEVICE_MODELS = [
    'HG114XT30',
    'F6600R', 
    'ONT-2GF-V-RFDW',
    'ONT-2GF-V-RFW',
    'ONT-4GE-V-USB-RFDW',
    'HG114AT',
    'IGD'
]

# Configuración de validación de datos
VALIDATION_CONFIG = {
    'ssid': {
        'min_length': 1,
        'max_length': 32,
        'invalid_patterns': [
            r'^[\*\.\-_\s]+$',  # Solo caracteres especiales
            r'^[0-9A-Fa-f]{32}$',  # Hash hexadecimal 32
            r'^[0-9A-Fa-f]{64}$',  # Hash hexadecimal 64
        ]
    },
    'password': {
        'min_length': 8,
        'max_length': 63,
        'invalid_patterns': [
            r'^[\*\.\-_\s]+$',  # Solo caracteres especiales
            r'^[0-9A-Fa-f]{32}$',  # Hash MD5
            r'^[0-9A-Fa-f]{64}$',  # Hash SHA256
            r'^\$[0-9]\$.*',  # Hash con formato $n$...
        ]
    },
    'mac_address': {
        'pattern': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    },
    'contract_number': {
        'max_length': 50,
        'pattern': r'^[A-Za-z0-9\-_]+$'
    }
}

print(f"📊 Configuración cargada:")
print(f"   • Base de datos: {DB_CONFIG['database']}")
print(f"   • Host: {DB_CONFIG['host']}:{DB_CONFIG['port']}")
print(f"   • Usuario: {DB_CONFIG['username']}")
print(f"   • Modelos soportados: {len(SUPPORTED_DEVICE_MODELS)}")
print(f"   • CSV max size: {CSV_CONFIG['max_file_size'] // (1024*1024)}MB")