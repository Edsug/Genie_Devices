# csv_processor.py - VERSIÓN FINAL, COMPLETA Y ROBUSTA

import pandas as pd
import hashlib
import logging
from flask import jsonify

# Asumimos que estas funciones y clases están disponibles desde tus otros archivos
from db_services import DatabaseService
from models import db, CSVImportHistory
from models import encrypt_data # Importar la función de cifrado

# Configurar logging
logger = logging.getLogger(__name__)

def calculate_file_hash(file_stream):
    """Calcula el hash SHA-256 de un archivo de forma segura para la memoria."""
    hash_sha256 = hashlib.sha256()
    # Leer el archivo en bloques para no agotar la memoria con archivos grandes
    for chunk in iter(lambda: file_stream.read(4096), b""):
        hash_sha256.update(chunk)
    # Devolver el cursor al inicio del archivo para que pandas pueda leerlo
    file_stream.seek(0)
    return hash_sha256.hexdigest()

def normalize_mac(mac):
    """Normaliza una dirección MAC a un formato estándar (XX:XX:XX:XX:XX:XX)."""
    if not isinstance(mac, str):
        return None
    
    mac = mac.strip().upper().replace("-", "").replace(":", "").replace(" ", "")
    if len(mac) != 12:
        return None # Formato inválido
    
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))

class CSVProcessor:
    def __init__(self, file_stream, filename, user_id):
        self.file_stream = file_stream
        self.filename = filename
        self.user_id = user_id
        # Inicializar estadísticas
        self.stats = {
            'processed': 0,
            'updated': 0,
            'no_change': 0,
            'failed': 0
        }
        self.file_hash = calculate_file_hash(self.file_stream)

    def process(self):
        """
        Procesa el archivo CSV, valida, actualiza la base de datos y registra el historial.
        """
        # 1. Verificar si el hash del archivo ya existe en la base de datos
        if DatabaseService.check_csv_hash_exists(self.file_hash):
            message = "Este archivo CSV ya ha sido procesado anteriormente. No se realizaron cambios."
            logger.warning(message)
            return jsonify({'success': False, 'message': message}), 409

        try:
            # Usar 'dtype=str' para evitar que pandas interprete incorrectamente los datos
            df = pd.read_csv(self.file_stream, dtype=str).fillna('')
            self.stats['processed'] = len(df)

            for index, row in df.iterrows():
                try:
                    mac_address_raw = row.get('mac_address')
                    mac_address_norm = normalize_mac(mac_address_raw)

                    if not mac_address_norm:
                        logger.warning(f"Fila {index+2}: MAC inválida o ausente ('{mac_address_raw}'), omitiendo.")
                        self.stats['failed'] += 1
                        continue

                    # Preparar los datos del cliente y de las redes WiFi del CSV
                    customer_data = {
                        'contract_number': row.get('contract_number'),
                        'customer_name': row.get('customer_name')
                    }
                    wifi_data = [
                        {
                            'band': '2.4GHz',
                            'ssid': row.get('ssid_2_4ghz'),
                            # ¡Importante! Cifrar la contraseña antes de guardarla
                            'password': encrypt_data(row.get('password_2_4ghz')) if row.get('password_2_4ghz') else None
                        },
                        {
                            'band': '5GHz',
                            'ssid': row.get('ssid_5ghz'),
                            'password': encrypt_data(row.get('password_5ghz')) if row.get('password_5ghz') else None
                        }
                    ]
                    
                    # Llamar al método del servicio que contiene la lógica de actualización
                    result = DatabaseService.update_device_from_csv(
                        mac_address=mac_address_norm,
                        customer_data=customer_data,
                        wifi_networks_data=wifi_data,
                        user_id=self.user_id
                    )

                    # Actualizar estadísticas según el resultado
                    if result == 'updated':
                        self.stats['updated'] += 1
                    elif result == 'no_change':
                        self.stats['no_change'] += 1
                    else: # 'failed'
                        self.stats['failed'] += 1

                except Exception as row_error:
                    logger.error(f"Fila {index+2}: Error procesando la fila: {row_error}")
                    self.stats['failed'] += 1
            
            # 3. Registrar el resultado final de la importación
            status = 'Completed with errors' if self.stats['failed'] > 0 else 'Completed'
            DatabaseService.log_csv_import(
                filename=self.filename, user_id=self.user_id, file_hash=self.file_hash,
                stats=self.stats, status=status
            )
            message = "Procesamiento de CSV completado."
            logger.info(f"{message} - Estadísticas: {self.stats}")
            return jsonify({'success': True, 'message': message, 'stats': self.stats}), 200

        except Exception as e:
            # 4. Registrar el fallo catastrófico si el archivo no se puede leer
            error_message = f"Error fatal al leer el archivo CSV: {e}"
            logger.error(error_message)
            self.stats['failed'] = self.stats.get('processed', len(df) if 'df' in locals() else 0)
            DatabaseService.log_csv_import(
                filename=self.filename, user_id=self.user_id, file_hash=self.file_hash,
                stats=self.stats, status='Failed', error_message=error_message
            )
            return jsonify({'success': False, 'message': error_message}), 500

