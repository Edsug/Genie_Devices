#!/usr/bin/env python3
"""
Script de inicialización de la base de datos MySQL
Ejecutar este script después de configurar las credenciales en config_db.py
"""

import sys
import logging
from flask import Flask
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

def init_database():
    """Inicializar base de datos completa"""
    try:
        logger.info("🔧 Iniciando configuración de base de datos MySQL...")

        # Crear aplicación Flask
        app = create_app()

        with app.app_context():
            logger.info("📋 Creando tablas en MySQL...")

            # Crear todas las tablas
            db.create_all()

            logger.info("✅ Tablas creadas exitosamente:")
            logger.info("   • users - Gestión de usuarios del sistema")
            logger.info("   • device_contracts - Contratos de dispositivos")
            logger.info("   • wifi_passwords - Contraseñas WiFi actuales")
            logger.info("   • change_history - Historial de cambios")
            logger.info("   • device_cache - Cache de dispositivos (opcional)")

            # Crear usuarios por defecto
            logger.info("👥 Creando usuarios por defecto...")
            DatabaseService.create_default_users()

            # Verificar conexión
            logger.info("🔍 Verificando conexión...")
            user_count = User.query.count()
            logger.info(f"✅ Conexión exitosa. Usuarios en base: {user_count}")

            logger.info("🎉 ¡Base de datos MySQL inicializada correctamente!")
            logger.info("")
            logger.info("👥 Usuarios creados:")
            logger.info("   • admin / admin123 (NOC - Superadmin)")
            logger.info("   • informatica / info123 (Informática - Admin)")
            logger.info("   • callcenter / call123 (Call Center - Operador)")
            logger.info("")
            logger.info("🚀 Tu aplicación está lista para usar MySQL con XAMPP")

    except Exception as e:
        logger.error(f"❌ Error inicializando base de datos: {e}")
        logger.error("💡 Verifica que:")
        logger.error("   • XAMPP esté ejecutándose")
        logger.error("   • MySQL esté iniciado en XAMPP")
        logger.error("   • Las credenciales en config_db.py sean correctas")
        logger.error("   • La base de datos exista en phpMyAdmin")
        return False

    return True

from sqlalchemy import text

def test_connection():
    try:
        app = create_app()
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            logger.info("✅ Conexión MySQL exitosa")
            return True
    except Exception as e:
        logger.error(f"❌ Error de conexión: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("🔧 INICIALIZACIÓN DE BASE DE DATOS MYSQL")
    print("=" * 60)

    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("🧪 Modo de prueba - Solo verificar conexión")
        if test_connection():
            print("✅ Conexión MySQL funcionando correctamente")
            sys.exit(0)
        else:
            print("❌ Problema de conexión")
            sys.exit(1)

    # Confirmar antes de proceder
    print("⚠️  Este script va a:")
    print("   • Crear todas las tablas en MySQL")
    print("   • Crear usuarios por defecto")
    print("   • Sobreescribir datos existentes si los hay")
    print("")

    confirm = input("¿Continuar? (s/N): ").lower().strip()
    if confirm not in ['s', 'si', 'sí', 'y', 'yes']:
        print("❌ Operación cancelada")
        sys.exit(1)

    if init_database():
        print("✅ ¡Inicialización completada exitosamente!")
        sys.exit(0)
    else:
        print("❌ Inicialización falló")
        sys.exit(1)
