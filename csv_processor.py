import pandas as pd
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict
from models import db, CSVImportHistory
from db_services import DatabaseService
import time

logger = logging.getLogger(__name__)

def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.strip().upper().replace('-', ':').replace(' ', '')
    if len(mac) == 12 and ':' not in mac:
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    return mac

class CSVProcessor:
    """Procesador CSV optimizado para configuración masiva de dispositivos"""

    def __init__(self):
        self.GENIEACS_URL = "http://192.168.0.237:7557"
        self.GENIEACS_USERNAME = "admin"
        self.GENIEACS_PASSWORD = "admin"
        self._unconfigured_cache = None
        self._cache_expiry = None

    def get_file_hash(self, file_path: str) -> str:
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculando hash: {e}")
            return ""

    def is_file_already_processed(self, file_hash: str) -> bool:
        return CSVImportHistory.query.filter(
            (CSVImportHistory.file_hash == file_hash) &
            (CSVImportHistory.status == 'completed')
        ).first() is not None

    def get_unconfigured_devices_macs(self, force_refresh: bool = False) -> Dict[str, str]:
        if not force_refresh and self._unconfigured_cache and self._cache_expiry:
            if datetime.utcnow() < self._cache_expiry:
                logger.info(f"📦 Usando cache: {len(self._unconfigured_cache)} dispositivos no configurados")
                return self._unconfigured_cache
        try:
            logger.info("🔍 Obteniendo dispositivos NO configurados...")
            start_time = time.time()
            unconfigured_devices = DatabaseService.get_unconfigured_devices()
            mac_to_serial = {}
            for device in unconfigured_devices:
                if device['mac']:
                    normalized_mac = normalize_mac(device['mac'])
                    mac_to_serial[normalized_mac] = device['serial_number']
            self._unconfigured_cache = mac_to_serial
            self._cache_expiry = datetime.utcnow() + timedelta(minutes=5)
            processing_time = time.time() - start_time
            logger.info(f"✅ Dispositivos no configurados obtenidos: {len(mac_to_serial)} en {processing_time:.2f}s")
            return mac_to_serial
        except Exception as e:
            logger.error(f"Error obteniendo dispositivos no configurados: {e}")
            return self._unconfigured_cache or {}

    def process_csv_file(self, file_path: str, user_id: int, force_reimport: bool = False) -> Dict:
        start_time = datetime.utcnow()
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return {'success': False, 'message': 'Error calculando hash del archivo'}
        if not force_reimport and self.is_file_already_processed(file_hash):
            return {
                'success': False,
                'message': 'Este archivo ya fue procesado anteriormente',
                'code': 'ALREADY_PROCESSED'
            }
        import_record = CSVImportHistory(
            file_name=file_path.split('/')[-1],
            file_type='unified_csv',
            file_hash=file_hash,
            user_id=user_id,
            status='processing'
        )
        db.session.add(import_record)
        db.session.commit()
        try:
            result = self._process_unified_csv_file(file_path, import_record.id, user_id)
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            import_record.records_processed = result.get('processed', 0)
            import_record.devices_matched = result.get('matched', 0)
            import_record.devices_configured = result.get('configured', 0)
            import_record.devices_updated = result.get('updated', 0)
            import_record.devices_skipped = result.get('skipped', 0)
            import_record.status = 'completed' if result['success'] else 'failed'
            import_record.error_message = result.get('error_message')
            import_record.processing_time = int(processing_time)
            db.session.commit()
            self._unconfigured_cache = None
            logger.info(f"CSV procesado: {result}")
            return result
        except Exception as e:
            import_record.status = 'failed'
            import_record.error_message = str(e)
            db.session.commit()
            logger.error(f"Error procesando CSV: {e}")
            return {
                'success': False,
                'message': f'Error procesando archivo: {str(e)}',
                'error': str(e)
            }

    def _process_unified_csv_file(self, file_path: str, import_id: int, user_id: int) -> Dict:
        try:
            df = pd.read_csv(file_path)
            required_columns = [
                'mac_address', 'contract_number', 'customer_name',
                'ssid_2_4ghz', 'password_2_4ghz', 'ssid_5ghz', 'password_5ghz'
            ]
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return {'success': False, 'message': f'Columnas faltantes: {", ".join(missing_columns)}'}

            logger.info(f"📊 Procesando {len(df)} registros del CSV unificado...")
            unconfigured_macs = self.get_unconfigured_devices_macs()
            if not unconfigured_macs:
                return {
                    'success': True,
                    'processed': len(df),
                    'matched': 0,
                    'configured': 0,
                    'updated': 0,
                    'skipped': len(df),
                    'message': 'No hay dispositivos no configurados disponibles'
                }
            logger.info(f"🎯 Dispositivos no configurados disponibles: {len(unconfigured_macs)}")
            processed = matched = configured = updated = skipped = 0

            for index, row in df.iterrows():
                try:
                    mac_raw = str(row['mac_address']).strip() if pd.notna(row['mac_address']) else ''
                    mac = normalize_mac(mac_raw)
                    contract = str(row['contract_number']).strip() if pd.notna(row['contract_number']) else ''
                    customer_name = str(row['customer_name']).strip() if pd.notna(row['customer_name']) else ''
                    ssid_24 = str(row['ssid_2_4ghz']).strip() if pd.notna(row['ssid_2_4ghz']) else ''
                    password_24 = str(row['password_2_4ghz']).strip() if pd.notna(row['password_2_4ghz']) else ''
                    ssid_5 = str(row['ssid_5ghz']).strip() if pd.notna(row['ssid_5ghz']) else ''
                    password_5 = str(row['password_5ghz']).strip() if pd.notna(row['password_5ghz']) else ''

                    if not mac or not contract:
                        skipped += 1
                        continue

                    if not self._is_valid_ssid(ssid_24) or not self._is_valid_password(password_24):
                        logger.warning(f"⚠️ Red 2.4GHz inválida para MAC {mac}")
                        skipped += 1
                        continue

                    if not self._is_valid_ssid(ssid_5) or not self._is_valid_password(password_5):
                        logger.warning(f"⚠️ Red 5GHz inválida para MAC {mac}")
                        skipped += 1
                        continue

                    processed += 1

                    if mac in unconfigured_macs:
                        matched += 1
                        success, message = DatabaseService.configure_device_from_csv(
                            mac, contract, customer_name, ssid_24, password_24, ssid_5, password_5, user_id
                        )
                        if success:
                            configured += 1
                            logger.info(f"✅ Configurado: {mac} - {contract} - {customer_name}")
                        else:
                            logger.warning(f"⚠️ Error configurando {mac}: {message}")
                            skipped += 1
                    else:
                        skipped += 1

                    if processed % 50 == 0:
                        db.session.commit()
                        progress = (processed / len(df) * 100)
                        logger.info(f"📈 Progreso: {processed}/{len(df)} ({progress:.1f}%) - Configurados: {configured}")

                except Exception as e:
                    logger.error(f"Error procesando fila {index}: {e}")
                    skipped += 1
                    continue

            db.session.commit()
            coverage_rate = (matched / len(unconfigured_macs) * 100) if unconfigured_macs else 0

            logger.info("=" * 60)
            logger.info("✅ PROCESAMIENTO CSV UNIFICADO COMPLETADO")
            logger.info(f"📊 Registros procesados: {processed}")
            logger.info(f"🎯 Dispositivos coincidentes: {matched}")
            logger.info(f"⚙️ Dispositivos configurados: {configured}")
            logger.info(f"📈 Tasa de configuración: {coverage_rate:.1f}%")
            logger.info("=" * 60)

            return {
                'success': True,
                'processed': processed,
                'matched': matched,
                'configured': configured,
                'updated': updated,
                'skipped': skipped,
                'coverage_percentage': round(coverage_rate, 2),
                'message': f'Procesado: {configured} dispositivos configurados de {matched} coincidencias por MAC'
            }
        except Exception as e:
            logger.error(f"Error en _process_unified_csv_file: {e}")
            return {'success': False, 'message': f'Error procesando CSV unificado: {str(e)}', 'error': str(e)}

    def _is_valid_ssid(self, ssid: str) -> bool:
        if not ssid or len(ssid.strip()) == 0:
            return False
        ssid = ssid.strip()
        invalid_patterns = ['**', '***', '....', '----', '____', 'default', 'hidden']
        ssid_lower = ssid.lower()
        for pattern in invalid_patterns:
            if pattern in ssid_lower:
                return False
        return 1 <= len(ssid) <= 32

    def _is_valid_password(self, password: str) -> bool:
        if not password:
            return False
        password = password.strip()
        return 8 <= len(password) <= 63

    def get_import_statistics(self, days: int = 30) -> Dict:
        try:
            since_date = datetime.utcnow() - timedelta(days=days)
            imports = CSVImportHistory.query.filter(
                CSVImportHistory.created_at >= since_date
            ).all()
            stats = {
                'total_imports': len(imports),
                'successful_imports': len([i for i in imports if i.status == 'completed']),
                'failed_imports': len([i for i in imports if i.status == 'failed']),
                'total_records_processed': sum(i.records_processed or 0 for i in imports),
                'total_devices_configured': sum(i.devices_configured or 0 for i in imports)
            }
            return stats
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}
