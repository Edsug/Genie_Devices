# clean_database.py - Script para limpiar y resetear la base de datos

import os
import sys
from datetime import datetime
from sqlalchemy import text

# Configurar el path para importar los módulos de la aplicación
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    from models import db, User, DeviceContract, WifiPassword, ChangeHistory, CSVImportHistory, DeviceInfo, LANHost, DeviceCache
    from db_services import DatabaseService
except ImportError as e:
    print(f"❌ Error importando módulos: {e}")
    print("💡 Asegúrate de que todos los archivos estén en la misma carpeta")
    exit(1)

def clean_all_tables():
    """Limpiar todas las tablas de datos (mantener usuarios)"""
    print("🧹 Limpiando todas las tablas de datos...")
    
    try:
        with app.app_context():
            # Tablas a limpiar (en orden por dependencias)
            tables_to_clean = [
                ('change_history', 'Historial de cambios'),
                ('csv_import_history', 'Historial de importaciones CSV'),
                ('wifi_passwords', 'Contraseñas WiFi'),
                ('device_contracts', 'Contratos de dispositivos'),
                ('lan_hosts', 'Hosts LAN'),
                ('device_info', 'Información de dispositivos'),
                ('device_cache', 'Cache de dispositivos')
            ]
            
            total_deleted = 0
            
            for table_name, description in tables_to_clean:
                try:
                    # Contar registros antes
                    count_before = db.session.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
                    
                    if count_before > 0:
                        # Limpiar tabla
                        db.session.execute(text(f"DELETE FROM {table_name}"))
                        
                        # Reset AUTO_INCREMENT
                        db.session.execute(text(f"ALTER TABLE {table_name} AUTO_INCREMENT = 1"))
                        
                        db.session.commit()
                        
                        print(f"✅ {description}: {count_before} registros eliminados")
                        total_deleted += count_before
                    else:
                        print(f"ℹ️ {description}: ya está vacía")
                        
                except Exception as e:
                    print(f"⚠️ Error limpiando {table_name}: {e}")
                    db.session.rollback()
                    continue
            
            print(f"\n🎉 Limpieza completada: {total_deleted} registros eliminados en total")
            
    except Exception as e:
        print(f"❌ Error durante la limpieza: {e}")
        return False
    
    return True

def reset_users():
    """Resetear usuarios a valores por defecto"""
    print("👥 Reseteando usuarios por defecto...")
    
    try:
        with app.app_context():
            # Limpiar usuarios existentes
            User.query.delete()
            db.session.commit()
            
            # Crear usuarios por defecto
            default_users = [
                {
                    'username': 'admin',
                    'password': 'admin123',
                    'role': 'noc'
                },
                {
                    'username': 'informatica', 
                    'password': 'info123',
                    'role': 'informatica'
                },
                {
                    'username': 'callcenter',
                    'password': 'call123', 
                    'role': 'callcenter'
                }
            ]
            
            for user_data in default_users:
                user = User(
                    username=user_data['username'],
                    role=user_data['role']
                )
                user.set_password(user_data['password'])
                db.session.add(user)
            
            db.session.commit()
            
            print("✅ Usuarios por defecto creados:")
            print("   • admin/admin123 (NOC - Superadmin)")
            print("   • informatica/info123 (Informática - Admin)")
            print("   • callcenter/call123 (Call Center - Operador)")
            
    except Exception as e:
        print(f"❌ Error creando usuarios: {e}")
        return False
    
    return True

def verify_database_connection():
    """Verificar conexión a la base de datos"""
    print("🔍 Verificando conexión a la base de datos...")
    
    try:
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            print("✅ Conexión a MySQL exitosa")
            return True
    except Exception as e:
        print(f"❌ Error de conexión a MySQL: {e}")
        print("💡 Verifica que XAMPP esté ejecutándose y la configuración de BD sea correcta")
        return False

def show_table_status():
    """Mostrar estado actual de las tablas"""
    print("\n📊 Estado actual de las tablas:")
    print("-" * 50)
    
    try:
        with app.app_context():
            tables_info = [
                ('users', 'Usuarios del sistema'),
                ('device_contracts', 'Contratos de dispositivos'),
                ('wifi_passwords', 'Contraseñas WiFi'), 
                ('change_history', 'Historial de cambios'),
                ('csv_import_history', 'Historial CSV'),
                ('device_info', 'Info de dispositivos'),
                ('lan_hosts', 'Hosts LAN'),
                ('device_cache', 'Cache de dispositivos')
            ]
            
            for table_name, description in tables_info:
                try:
                    count = db.session.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
                    print(f"{description:25}: {count:6} registros")
                except Exception as e:
                    print(f"{description:25}: ERROR - {e}")
                    
    except Exception as e:
        print(f"❌ Error obteniendo estado de tablas: {e}")

def main():
    """Función principal del script"""
    print("🚀 GenieACS WiFi Manager - Limpieza de Base de Datos")
    print("=" * 60)
    print(f"⏰ Fecha/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("")
    
    # Verificar conexión
    if not verify_database_connection():
        print("❌ No se puede continuar sin conexión a la base de datos")
        exit(1)
    
    # Mostrar estado actual
    show_table_status()
    
    print("\n⚠️  ATENCIÓN: Esta acción eliminará TODOS los datos de:")
    print("   • Contratos de dispositivos")
    print("   • Contraseñas WiFi") 
    print("   • Historial de cambios")
    print("   • Historial de importaciones CSV")
    print("   • Cache de dispositivos")
    print("   • Información de dispositivos")
    print("   • Hosts LAN")
    print("")
    print("✅ Los usuarios del sistema se resetearán a valores por defecto")
    print("")
    
    # Confirmar acción
    confirm = input("¿Estás seguro de que quieres continuar? (escribe 'LIMPIAR' para confirmar): ")
    
    if confirm != 'LIMPIAR':
        print("❌ Operación cancelada por el usuario")
        exit(0)
    
    print("\n🧹 Iniciando limpieza de la base de datos...")
    print("-" * 40)
    
    # Limpiar todas las tablas
    if not clean_all_tables():
        print("❌ Error durante la limpieza de tablas")
        exit(1)
    
    # Resetear usuarios
    if not reset_users():
        print("❌ Error durante el reseteo de usuarios") 
        exit(1)
    
    print("\n📊 Estado final de las tablas:")
    print("-" * 40)
    show_table_status()
    
    print("\n🎉 ¡Limpieza completada exitosamente!")
    print("")
    print("📋 Próximos pasos:")
    print("1. Coloca tu CSV unificado en la carpeta 'data/' con nombre 'unified_data.csv'")
    print("2. El formato debe ser: mac_address,contract_number,customer_name,ssid_2_4ghz,password_2_4ghz,ssid_5ghz,password_5ghz") 
    print("3. Ejecuta: python app.py")
    print("4. El CSV se procesará automáticamente al iniciar la aplicación")
    print("")
    print("🌐 Accede a la aplicación en: http://localhost:5000")
    print("👤 Usuario: admin | Contraseña: admin123")
    print("")

if __name__ == '__main__':
    main()