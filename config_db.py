# Configuración de la base de datos MySQL con XAMPP
# ⚠️ IMPORTANTE: Cambiar estos valores por los tuyos

# Configuración MySQL con XAMPP
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 3306,
    'database': 'genieasc_db',  # Cambiar por el nombre de tu base
    'username': 'admin',  # Cambiar por tu usuario
    'password': 'admin',  # Cambiar por tu contraseña
    'charset': 'utf8mb4'
}

# URI de conexión SQLAlchemy
SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_CONFIG['username']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}?charset={DB_CONFIG['charset']}"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'connect_timeout': 60,
        'read_timeout': 60,
        'write_timeout': 60
    }
}
