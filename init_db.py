# init_db_fixed.py - INICIALIZADOR CORREGIDO PARA NUEVA BASE DE DATOS

from flask import Flask
from models import db, User, Device, CustomerInfo, WifiNetwork, ChangeHistory, CSVImportHistory
from db_services import DatabaseService
from config_db import SQLALCHEMY_DATABASE_URI
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear aplicación Flask temporal
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar base de datos
db.init_app(app)

def create_tables():
    """Crear todas las tablas de la nueva base de datos"""
    with app.app_context():
        try:
            logger.info("🔧 Creando tablas de base de datos OPTIMIZADA...")

            # Crear todas las tablas
            db.create_all()

            # Verificar tablas creadas
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()

            required_tables = [
                'users', 'devices', 'customer_info', 'wifi_networks', 
                'change_history', 'csv_import_history'
            ]

            created_tables = []
            missing_tables = []
            
            for table in required_tables:
                if table in tables:
                    created_tables.append(table)
                else:
                    missing_tables.append(table)

            if missing_tables:
                logger.error(f"❌ Tablas faltantes: {missing_tables}")
                return False

            logger.info("✅ Todas las tablas creadas exitosamente:")
            for table in created_tables:
                logger.info(f" • {table}")

            # Crear usuarios por defecto
            logger.info("👥 Creando usuarios por defecto...")
            DatabaseService.create_default_users()

            # Crear algunos datos de ejemplo
            create_sample_data()

            logger.info("🎉 Base de datos inicializada completamente")
            return True

        except Exception as e:
            logger.error(f"❌ Error creando tablas: {e}")
            return False

def create_sample_data():
    """Crear dispositivos de ejemplo"""
    try:
        logger.info("📝 Creando datos de ejemplo...")

        # Verificar si ya existen datos
        if Device.query.first():
            logger.info(" • Ya existen datos, omitiendo creación de ejemplos")
            return

        # Crear dispositivo de ejemplo
        device = Device(
            serial_number='TEST001',
            mac_address='AA:BB:CC:DD:EE:FF',
            product_class='F6600R',
            software_version='1.0.0',
            hardware_version='1.0',
            ip_address='192.168.1.100',
            last_inform='12/09/2025 14:30'
        )
        db.session.add(device)
        db.session.flush()

        # Crear redes WiFi de ejemplo
        wifi_24 = WifiNetwork(
            device_id=device.id,
            band='2.4GHz',
            ssid_current='WiFiTest_2.4G',
            is_primary=False,
            wlan_configuration='1'
        )
        db.session.add(wifi_24)

        wifi_5 = WifiNetwork(
            device_id=device.id,
            band='5GHz',
            ssid_current='WiFiTest_5G',
            is_primary=True,
            wlan_configuration='5'
        )
        db.session.add(wifi_5)

        db.session.commit()
        logger.info("✅ Datos de ejemplo creados")

    except Exception as e:
        db.session.rollback()
        logger.error(f"❌ Error creando datos de ejemplo: {e}")

def verify_database_connection():
    """Verificar conexión a la base de datos"""
    try:
        with app.app_context():
            db.session.execute(db.text('SELECT 1'))
            logger.info("✅ Conexión a base de datos verificada")
            return True
    except Exception as e:
        logger.error(f"❌ Error de conexión: {e}")
        logger.error("💡 Verifica que:")
        logger.error(" • XAMPP esté ejecutándose")
        logger.error(" • MySQL esté iniciado")
        logger.error(" • Las credenciales sean correctas")
        return False

def show_connection_info():
    """Mostrar información de conexión"""
    print("=" * 60)
    print("🔧 INICIALIZADOR - GenieACS WiFi Manager OPTIMIZADO")
    print("=" * 60)
    print(f"🔗 Conectando a: {SQLALCHEMY_DATABASE_URI}")
    print("📋 Tablas a crear:")
    print(" • users - Usuarios del sistema")
    print(" • devices - Dispositivos (info técnica desde GenieACS)")
    print(" • customer_info - Información del cliente (desde CSV)")
    print(" • wifi_networks - Redes WiFi (SSID + contraseñas)")
    print(" • change_history - Historial de cambios")
    print(" • csv_import_history - Historial de importaciones")
    print("=" * 60)

def main():
    """Función principal"""
    show_connection_info()

    # Verificar conexión
    if not verify_database_connection():
        return False

    # Crear tablas
    if create_tables():
        print("\n🎉 ¡Inicialización completada exitosamente!")
        print("\n📋 Próximos pasos:")
        print(" 1. Ejecutar: python app_fixed.py")
        print(" 2. Abrir navegador en: http://localhost:5000")
        print(" 3. Iniciar sesión con:")
        print(" • admin/admin123 (Superadmin)")
        print(" • informatica/info123 (Admin)")
        print(" • callcenter/call123 (Operador)")
        print("\n📂 CSV unificado soportado:")
        print(" Formato: mac_address,contract_number,customer_name,ssid_2_4ghz,password_2_4ghz,ssid_5ghz,password_5ghz")
        print(" • Los dispositivos se relacionan por MAC address")
        print(" • Solo se procesan dispositivos NO configurados")
        print(" • Un dispositivo configurado = contrato + ambas contraseñas")
        return True
    else:
        print("\n❌ Error en la inicialización")
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)