#!/usr/bin/env python3
"""
Script de migración de base de datos para GenieACS WiFi Manager
Ejecuta este script para arreglar los problemas de la base de datos
"""

import sqlite3
import os
import sys
from datetime import datetime

DB_NAME = 'genieacs_data.db'

def check_database_exists():
    """Verificar si la base de datos existe"""
    return os.path.exists(DB_NAME)

def backup_database():
    """Crear respaldo de la base de datos existente"""
    if check_database_exists():
        backup_name = f'genieacs_data_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        try:
            import shutil
            shutil.copy2(DB_NAME, backup_name)
            print(f"✅ Respaldo creado: {backup_name}")
            return True
        except Exception as e:
            print(f"❌ Error creando respaldo: {e}")
            return False
    return True

def migrate_database():
    """Ejecutar migración de base de datos"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        print("🔍 Verificando estructura de la base de datos...")
        
        # Verificar si la tabla change_history existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='change_history'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("📊 Creando tabla change_history...")
            cursor.execute('''
                CREATE TABLE change_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_number TEXT NOT NULL,
                    product_class TEXT,
                    band TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    ssid TEXT,
                    user_id INTEGER,
                    username TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            print("✅ Tabla change_history creada")
        else:
            print("📋 Tabla change_history ya existe, verificando columnas...")
            
            # Verificar columnas existentes
            cursor.execute("PRAGMA table_info(change_history)")
            columns = [column[1] for column in cursor.fetchall()]
            print(f"📋 Columnas encontradas: {columns}")
            
            # Agregar columnas faltantes
            if 'username' not in columns:
                print("➕ Agregando columna 'username'...")
                cursor.execute('ALTER TABLE change_history ADD COLUMN username TEXT')
                print("✅ Columna 'username' agregada")
            else:
                print("✅ Columna 'username' ya existe")
            
            if 'user_id' not in columns:
                print("➕ Agregando columna 'user_id'...")
                cursor.execute('ALTER TABLE change_history ADD COLUMN user_id INTEGER')
                print("✅ Columna 'user_id' agregada")
            else:
                print("✅ Columna 'user_id' ya existe")
        
        # Verificar tabla users
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        users_table_exists = cursor.fetchone()
        
        if not users_table_exists:
            print("👥 Creando tabla users...")
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'operator',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # Crear usuario admin por defecto
            import hashlib
            admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
            cursor.execute('''
                INSERT INTO users (username, password, role)
                VALUES ('admin', ?, 'admin')
            ''', (admin_password,))
            print("✅ Tabla users creada con usuario admin por defecto")
        
        # Verificar tabla wifi_passwords
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wifi_passwords'")
        wifi_table_exists = cursor.fetchone()
        
        if not wifi_table_exists:
            print("📶 Creando tabla wifi_passwords...")
            cursor.execute('''
                CREATE TABLE wifi_passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_number TEXT NOT NULL,
                    band TEXT NOT NULL,
                    ssid TEXT NOT NULL,
                    password TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(serial_number, band)
                )
            ''')
            print("✅ Tabla wifi_passwords creada")
        
        # Verificar tabla device_cache
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_cache'")
        cache_table_exists = cursor.fetchone()
        
        if not cache_table_exists:
            print("💾 Creando tabla device_cache...")
            cursor.execute('''
                CREATE TABLE device_cache (
                    serial_number TEXT PRIMARY KEY,
                    product_class TEXT,
                    software_version TEXT,
                    hardware_version TEXT,
                    ip TEXT,
                    mac TEXT,
                    last_inform TEXT,
                    tags TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print("✅ Tabla device_cache creada")
        
        conn.commit()
        conn.close()
        
        print("✅ Migración completada exitosamente")
        return True
        
    except Exception as e:
        print(f"❌ Error durante la migración: {e}")
        return False

def verify_migration():
    """Verificar que la migración fue exitosa"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Verificar change_history
        cursor.execute("PRAGMA table_info(change_history)")
        columns = [column[1] for column in cursor.fetchall()]
        
        required_columns = ['id', 'serial_number', 'product_class', 'band', 'change_type', 
                          'old_value', 'new_value', 'ssid', 'user_id', 'username', 'timestamp']
        
        missing_columns = [col for col in required_columns if col not in columns]
        
        if missing_columns:
            print(f"❌ Faltan columnas: {missing_columns}")
            return False
        
        # Verificar que se puede hacer query con username
        cursor.execute("SELECT COUNT(*) FROM change_history WHERE username IS NOT NULL OR username IS NULL")
        count = cursor.fetchone()[0]
        print(f"✅ Tabla change_history funcional: {count} registros")
        
        # Verificar usuarios
        cursor.execute("SELECT username FROM users WHERE role = 'admin'")
        admin = cursor.fetchone()
        if admin:
            print(f"✅ Usuario admin encontrado: {admin[0]}")
        else:
            print("❌ Usuario admin no encontrado")
            return False
        
        conn.close()
        print("✅ Verificación completada - Base de datos lista")
        return True
        
    except Exception as e:
        print(f"❌ Error en verificación: {e}")
        return False

def main():
    print("🚀 Iniciando migración de base de datos GenieACS WiFi Manager")
    print("=" * 60)
    
    # Crear respaldo
    if not backup_database():
        print("❌ No se pudo crear respaldo. ¿Continuar? (s/N)")
        response = input().lower()
        if response != 's':
            print("❌ Migración cancelada")
            sys.exit(1)
    
    # Ejecutar migración
    if not migrate_database():
        print("❌ Migración fallida")
        sys.exit(1)
    
    # Verificar migración
    if not verify_migration():
        print("❌ Verificación fallida")
        sys.exit(1)
    
    print("=" * 60)
    print("🎉 MIGRACIÓN COMPLETADA EXITOSAMENTE")
    print("")
    print("📋 Siguiente pasos:")
    print("1. Reemplaza el archivo app.py con el nuevo app-corregido.py")
    print("2. Reemplaza el archivo script.js con el nuevo script-completo.js") 
    print("3. Reemplaza el archivo index.html con el nuevo index-completo.html")
    print("4. Reinicia el servidor Flask")
    print("")
    print("🔐 Login: admin / admin123")

if __name__ == "__main__":
    main()