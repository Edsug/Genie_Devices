# manage_db.py - VERSIÓN FINAL Y ROBUSTA

import os
import sys
from sqlalchemy import text

# Añadir la ruta del proyecto
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
    from db_services import DatabaseService
    # Importar explícitamente los modelos para asegurar que SQLAlchemy los "vea"
    from models import User, Device, CustomerInfo, WifiNetwork, ChangeHistory, CSVImportHistory
except ImportError as e:
    print(f"❌ Error importando módulos: {e}")
    print("💡 Revisa que 'app.py' y 'models.py' estén en la misma carpeta y los modelos estén definidos.")
    exit(1)

def reset_database():
    """¡ACCIÓN DESTRUCTIVA! Borra todas las tablas y las crea de nuevo."""
    with app.app_context():
        print("\n⚠️ ¡ATENCIÓN! Esta acción borrará TODAS las tablas y datos existentes.")
        confirm = input("Escribe 'RESET DB' para continuar: ")
        if confirm != 'RESET DB':
            print("❌ Operación cancelada.")
            return

        print("\n🔥 Reseteando la base de datos por completo...")
        try:
            print("  - Desactivando restricciones de Foreign Key...")
            db.session.execute(text('SET FOREIGN_KEY_CHECKS=0;'))
            print("  - Borrando todas las tablas existentes...")
            db.drop_all()
            print("  - Reactivando restricciones de Foreign Key...")
            db.session.execute(text('SET FOREIGN_KEY_CHECKS=1;'))
            db.session.commit()
            print("  - Creando nuevas tablas desde models.py...")
            db.create_all()
            print("  - Creando usuarios por defecto...")
            DatabaseService.create_default_users()
            db.session.commit()
            print("\n✅ ¡Base de datos reseteada y reinicializada con éxito!")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Ocurrió un error durante el reseteo: {e}")

if __name__ == '__main__':
    reset_database()
