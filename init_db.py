#!/usr/bin/env python3
"""
Script de inicialización de la base de datos MySQL - CORREGIDO PARA SQLALCHEMY 2.x
Ejecutar este script después de configurar las credenciales en config_db.py
"""

import sys
import logging
from flask import Flask
from sqlalchemy import text, inspect
from config_db import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS, SQLALCHEMY_ENGINE_OPTIONS
from models import db, User, DeviceContract, WifiPassword, ChangeHistory, DeviceCache
from db_services import DatabaseService

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Crear aplicación Flask para inicialización"""
    app = Flask(__name__)
    
    # Configurar base de datos
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = SQLALCHEMY_ENGINE_OPTIONS
    
    # Inicializar extensiones
    db.init_app(app)
    
    return app

def test_connection():
    """Probar conexión a MySQL usando SQLAlchemy 2.x"""
    try:
        app = create_app()
        with app.app_context():
            # SQLAlchemy 2.x: usar db.session.execute(text()) en lugar de engine.execute()
            result = db.session.execute(text('SELECT 1 as test'))
            test_value = result.scalar()
            if test_value == 1:
                logger.info("✅ Conexión MySQL exitosa")
                return True
            else:
                logger.error("❌ Conexión fallida: resultado inesperado")
                return False
    except Exception as e:
        logger.error(f"❌ Error de conexión: {e}")
        return False

def init_database():
    """Inicializar base de datos completa"""
    try:
        logger.info("🔧 Iniciando configuración de base de datos MySQL...")
        
        # Crear aplicación Flask
        app = create_app()
        
        with app.app_context():
            # Probar conexión primero
            logger.info("🔗 Probando conexión inicial...")
            try:
                db.session.execute(text('SELECT 1'))
                logger.info("✅ Conexión inicial exitosa")
            except Exception as e:
                logger.error(f"❌ Error de conexión inicial: {e}")
                raise
            
            logger.info("📋 Creando tablas en MySQL...")
            
            # Crear todas las tablas - SQLAlchemy 2.x compatible
            db.create_all()
            
            # Verificar que las tablas se crearon
            logger.info("🔍 Verificando tablas creadas...")
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            logger.info("✅ Tablas creadas exitosamente:")
            logger.info(" • users - Gestión de usuarios del sistema")
            logger.info(" • device_contracts - Contratos de dispositivos")
            logger.info(" • wifi_passwords - Contraseñas WiFi actuales")
            logger.info(" • change_history - Historial de cambios")
            
            # Verificar tablas requeridas
            required_tables = ['users', 'device_contracts', 'wifi_passwords', 'change_history']
            missing_tables = [table for table in required_tables if table not in tables]
            
            if missing_tables:
                logger.error(f"❌ Tablas faltantes: {missing_tables}")
                return False
            
            # Verificar si device_cache está presente (opcional)
            if 'device_cache' in tables:
                logger.info(" • device_cache - Cache de dispositivos (opcional)")
            
            # Crear usuarios por defecto
            logger.info("👥 Creando usuarios por defecto...")
            DatabaseService.create_default_users()
            
            # Verificar conexión final y contar usuarios
            logger.info("🔍 Verificación final...")
            try:
                user_count = User.query.count()
                logger.info(f"✅ Conexión final exitosa. Usuarios en base: {user_count}")
            except Exception as e:
                logger.error(f"❌ Error en verificación final: {e}")
                raise
            
            # Probar algunas operaciones básicas
            logger.info("🧪 Probando operaciones básicas...")
            try:
                # Probar consulta simple
                admin_user = User.query.filter_by(username='admin').first()
                if admin_user:
                    logger.info(f"✅ Usuario admin encontrado con rol: {admin_user.role}")
                else:
                    logger.warning("⚠️ Usuario admin no encontrado")
                
                # Probar inserción de datos de prueba (opcional)
                test_result = db.session.execute(text("SELECT COUNT(*) as count FROM users"))
                count = test_result.scalar()
                logger.info(f"✅ Total usuarios en base: {count}")
                
            except Exception as e:
                logger.error(f"❌ Error en pruebas básicas: {e}")
                raise
            
            logger.info("🎉 ¡Base de datos MySQL inicializada correctamente!")
            logger.info("")
            logger.info("👥 Usuarios creados:")
            logger.info(" • admin / admin123 (NOC - Superadmin)")
            logger.info(" • informatica / info123 (Informática - Admin)")
            logger.info(" • callcenter / call123 (Call Center - Operador)")
            logger.info("")
            logger.info("🚀 Tu aplicación está lista para usar MySQL con XAMPP")
            logger.info("💡 Puedes ejecutar: python app.py")
            
    except Exception as e:
        logger.error(f"❌ ERROR DE INICIALIZACIÓN: {e}")
        logger.error("💡 Verifica que:")
        logger.error(" • XAMPP esté ejecutándose")
        logger.error(" • MySQL esté iniciado en XAMPP")
        logger.error(" • Las credenciales en config_db.py sean correctas")
        logger.error(" • La base de datos exista en phpMyAdmin")
        logger.error(" • El usuario MySQL tenga permisos para crear tablas")
        return False
    
    return True

def show_database_info():
    """Mostrar información de la base de datos"""
    try:
        app = create_app()
        with app.app_context():
            logger.info("📊 INFORMACIÓN DE LA BASE DE DATOS:")
            logger.info("=" * 50)
            
            # Información de conexión
            logger.info(f"🔗 URI: {SQLALCHEMY_DATABASE_URI}")
            
            # Tablas existentes
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"📋 Tablas ({len(tables)}): {', '.join(tables)}")
            
            # Información de usuarios
            try:
                user_count = User.query.count()
                users = User.query.all()
                logger.info(f"👥 Usuarios ({user_count}):")
                for user in users:
                    status = "✅ Activo" if user.is_active else "❌ Inactivo"
                    last_login = user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "Nunca"
                    logger.info(f"   • {user.username} ({user.role}) - {status} - Último login: {last_login}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo usuarios: {e}")
            
            # Información de contratos
            try:
                contract_count = DeviceContract.query.count()
                logger.info(f"📄 Contratos de dispositivos: {contract_count}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo contratos: {e}")
            
            # Información de contraseñas WiFi
            try:
                password_count = WifiPassword.query.count()
                logger.info(f"🔐 Contraseñas WiFi almacenadas: {password_count}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo contraseñas: {e}")
            
            # Información de historial
            try:
                history_count = ChangeHistory.query.count()
                logger.info(f"📜 Registros de historial: {history_count}")
            except Exception as e:
                logger.error(f"❌ Error obteniendo historial: {e}")
                
    except Exception as e:
        logger.error(f"❌ Error mostrando información de BD: {e}")

def reset_database():
    """Resetear completamente la base de datos"""
    try:
        logger.info("⚠️ RESETEANDO BASE DE DATOS...")
        app = create_app()
        with app.app_context():
            # Eliminar todas las tablas
            db.drop_all()
            logger.info("🗑️ Tablas eliminadas")
            
            # Crear nuevamente
            db.create_all()
            logger.info("📋 Tablas recreadas")
            
            # Crear usuarios por defecto
            DatabaseService.create_default_users()
            logger.info("👥 Usuarios por defecto recreados")
            
            logger.info("✅ Base de datos reseteada exitosamente")
            
    except Exception as e:
        logger.error(f"❌ Error reseteando base de datos: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 INICIALIZACIÓN DE BASE DE DATOS MYSQL")
    print("=" * 60)
    
    # Manejar argumentos de línea de comandos
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--test":
            print("🧪 Modo de prueba - Solo verificar conexión")
            if test_connection():
                print("✅ Conexión MySQL funcionando correctamente")
                sys.exit(0)
            else:
                print("❌ Problema de conexión")
                sys.exit(1)
                
        elif command == "--info":
            print("📊 Mostrando información de la base de datos")
            show_database_info()
            sys.exit(0)
            
        elif command == "--reset":
            print("⚠️ MODO RESET - Eliminará TODOS los datos")
            confirm = input("¿Estás seguro? Escribe 'RESET' para confirmar: ").strip()
            if confirm == "RESET":
                if reset_database():
                    print("✅ Base de datos reseteada exitosamente")
                    sys.exit(0)
                else:
                    print("❌ Error reseteando base de datos")
                    sys.exit(1)  
            else:
                print("❌ Reset cancelado")
                sys.exit(1)
                
        else:
            print("❌ Comando no reconocido")
            print("Comandos disponibles:")
            print("  --test    : Solo probar conexión")
            print("  --info    : Mostrar información de BD")
            print("  --reset   : Resetear completamente la BD")
            sys.exit(1)
    
    # Modo normal - inicialización completa
    print("⚠️ Este script va a:")
    print(" • Crear todas las tablas en MySQL")
    print(" • Crear usuarios por defecto")
    print(" • Sobreescribir datos existentes si los hay")
    print("")
    
    # Probar conexión primero
    print("🔗 Probando conexión a MySQL...")
    if not test_connection():
        print("❌ No se puede conectar a MySQL")
        print("💡 Verifica que XAMPP esté ejecutándose y revisa config_db.py")
        sys.exit(1)
    
    # Confirmar antes de proceder
    confirm = input("¿Continuar con la inicialización? (s/N): ").lower().strip()
    if confirm not in ['s', 'si', 'sí', 'y', 'yes']:
        print("❌ Operación cancelada")
        sys.exit(1)
    
    # Ejecutar inicialización
    if init_database():
        print("")
        print("✅ ¡Inicialización completada exitosamente!")
        print("🎯 Siguiente paso: python app.py")
        sys.exit(0)
    else:
        print("❌ Inicialización falló")
        sys.exit(1)