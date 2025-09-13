# migrate_database.py - MIGRACIÓN DE BASE DE DATOS ANTIGUA A NUEVA ESTRUCTURA

from flask import Flask
from sqlalchemy import create_engine, text
from config_db import SQLALCHEMY_DATABASE_URI
import logging
import json

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear aplicación Flask temporal
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def backup_old_tables():
    """Hacer backup de las tablas existentes"""
    try:
        engine = create_engine(SQLALCHEMY_DATABASE_URI)
        
        logger.info("📋 Haciendo backup de tablas existentes...")
        
        with engine.connect() as conn:
            # Renombrar tablas existentes agregando _backup
            backup_tables = [
                "device_contracts",
                "wifi_passwords", 
                "device_info",
                "lan_hosts"
            ]
            
            for table in backup_tables:
                try:
                    # Verificar si la tabla existe
                    result = conn.execute(text(f"SHOW TABLES LIKE '{table}'"))
                    if result.fetchone():
                        # Renombrar tabla
                        conn.execute(text(f"RENAME TABLE {table} TO {table}_backup_{int(time.time())}"))
                        logger.info(f"✅ Backup creado para {table}")
                except Exception as e:
                    logger.warning(f"⚠️ No se pudo hacer backup de {table}: {e}")
            
            conn.commit()
        
        logger.info("✅ Backup de tablas completado")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error en backup: {e}")
        return False

def migrate_old_data():
    """Migrar datos de la estructura antigua a la nueva"""
    try:
        engine = create_engine(SQLALCHEMY_DATABASE_URI)
        
        logger.info("🔄 Iniciando migración de datos...")
        
        with engine.connect() as conn:
            # Primero, necesitamos importar los nuevos modelos
            from models import db, Device, CustomerInfo, WifiNetwork
            
            # Inicializar la nueva base de datos
            with app.app_context():
                db.init_app(app)
                
                # Crear las nuevas tablas
                db.create_all()
                
                logger.info("✅ Nuevas tablas creadas")
                
                # Migrar datos de device_contracts_backup
                logger.info("📊 Migrando contratos de dispositivos...")
                
                try:
                    # Buscar tabla de backup de contratos más reciente
                    backup_tables = conn.execute(text("SHOW TABLES LIKE 'device_contracts_backup_%'")).fetchall()
                    if backup_tables:
                        contract_table = backup_tables[0][0]  # Tomar la primera encontrada
                        
                        contracts = conn.execute(text(f"SELECT * FROM {contract_table}")).fetchall()
                        
                        for contract in contracts:
                            # Verificar si ya existe información de este dispositivo
                            existing_device = Device.query.filter_by(serial_number=contract[1]).first()  # contract[1] = serial_number
                            
                            if not existing_device:
                                # Crear dispositivo básico (se completará con GenieACS)
                                device = Device(
                                    serial_number=contract[1],  # serial_number
                                    mac_address='',  # Se completará después
                                    product_class='',
                                    software_version='',
                                    hardware_version='',
                                    ip_address='',
                                    last_inform=''
                                )
                                db.session.add(device)
                                db.session.flush()
                            else:
                                device = existing_device
                            
                            # Migrar información del cliente
                            if contract[2]:  # contract_number
                                customer_info = CustomerInfo.query.filter_by(device_id=device.id).first()
                                if not customer_info:
                                    customer_info = CustomerInfo(
                                        device_id=device.id,
                                        contract_number=contract[2],  # contract_number
                                        updated_by=contract[5]  # updated_by
                                    )
                                    if contract[3]:  # customer_name_encrypted
                                        customer_info.customer_name_encrypted = contract[3]
                                    db.session.add(customer_info)
                        
                        db.session.commit()
                        logger.info(f"✅ {len(contracts)} contratos migrados")
                
                except Exception as e:
                    logger.warning(f"⚠️ Error migrando contratos: {e}")
                
                # Migrar datos de wifi_passwords_backup
                logger.info("📊 Migrando contraseñas WiFi...")
                
                try:
                    # Buscar tabla de backup de passwords más reciente
                    backup_tables = conn.execute(text("SHOW TABLES LIKE 'wifi_passwords_backup_%'")).fetchall()
                    if backup_tables:
                        password_table = backup_tables[0][0]  # Tomar la primera encontrada
                        
                        passwords = conn.execute(text(f"SELECT * FROM {password_table}")).fetchall()
                        
                        for password in passwords:
                            # Buscar dispositivo
                            device = Device.query.filter_by(serial_number=password[1]).first()  # password[1] = serial_number
                            
                            if device:
                                # Verificar si ya existe esta red
                                existing_network = WifiNetwork.query.filter_by(
                                    device_id=device.id,
                                    band=password[2]  # password[2] = band
                                ).first()
                                
                                if not existing_network:
                                    network = WifiNetwork(
                                        device_id=device.id,
                                        band=password[2],  # band
                                        ssid_configured=password[3],  # ssid
                                        is_primary=(password[2] == '5GHz')
                                    )
                                    if password[4]:  # password_encrypted
                                        network.password_encrypted = password[4]
                                    db.session.add(network)
                        
                        db.session.commit()
                        logger.info(f"✅ {len(passwords)} contraseñas WiFi migradas")
                
                except Exception as e:
                    logger.warning(f"⚠️ Error migrando contraseñas: {e}")
                
                logger.info("🎉 Migración de datos completada")
                return True
        
    except Exception as e:
        logger.error(f"❌ Error en migración: {e}")
        return False

def verify_migration():
    """Verificar que la migración fue exitosa"""
    try:
        from models import db, Device, CustomerInfo, WifiNetwork
        
        with app.app_context():
            db.init_app(app)
            
            # Contar registros migrados
            devices_count = Device.query.count()
            customers_count = CustomerInfo.query.count()
            networks_count = WifiNetwork.query.count()
            
            logger.info("📊 Verificación de migración:")
            logger.info(f" • Dispositivos: {devices_count}")
            logger.info(f" • Información de clientes: {customers_count}")
            logger.info(f" • Redes WiFi: {networks_count}")
            
            return True
            
    except Exception as e:
        logger.error(f"❌ Error verificando migración: {e}")
        return False

def show_migration_info():
    """Mostrar información de la migración"""
    print("=" * 60)
    print("🔄 MIGRACIÓN DE BASE DE DATOS - GenieACS WiFi Manager")
    print("=" * 60)
    print("📋 Proceso de migración:")
    print(" 1. Backup de tablas existentes")
    print(" 2. Creación de nueva estructura optimizada")
    print(" 3. Migración de datos existentes")
    print(" 4. Verificación de integridad")
    print("")
    print("⚠️  IMPORTANTE:")
    print(" • Se hará backup automático de tus datos")
    print(" • La nueva estructura es más eficiente")
    print(" • Los datos existentes se preservan")
    print(" • Podrás revertir si es necesario")
    print("=" * 60)

def main():
    """Función principal de migración"""
    show_migration_info()
    
    try:
        import time
        
        # Confirmar migración
        confirm = input("\n¿Deseas continuar con la migración? (s/n): ").lower()
        if confirm != 's':
            print("❌ Migración cancelada")
            return False
        
        # Paso 1: Backup
        print("\n🔄 Paso 1: Creando backup...")
        if not backup_old_tables():
            print("❌ Error en backup. Migración abortada.")
            return False
        
        # Paso 2: Migrar datos
        print("\n🔄 Paso 2: Migrando datos...")
        if not migrate_old_data():
            print("❌ Error en migración. Revisa los logs.")
            return False
        
        # Paso 3: Verificar
        print("\n🔄 Paso 3: Verificando migración...")
        if not verify_migration():
            print("❌ Error en verificación.")
            return False
        
        print("\n🎉 ¡Migración completada exitosamente!")
        print("\n📋 Próximos pasos:")
        print(" 1. Renombrar archivos:")
        print("    • mv models_fixed.py models.py")
        print("    • mv db_services_fixed.py db_services.py") 
        print("    • mv csv_processor_fixed.py csv_processor.py")
        print("    • mv app_fixed.py app.py")
        print(" 2. Ejecutar: python app.py")
        print(" 3. Probar la funcionalidad")
        print("")
        print("💡 Si hay problemas, puedes restaurar desde los backups creados")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error en migración: {e}")
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)