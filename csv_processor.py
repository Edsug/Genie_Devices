# csv_processor.py - Procesador de archivos CSV para automatización masiva con estadísticas mejoradas

import pandas as pd
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from models import db, DeviceContract, WifiPassword, DeviceInfo, CSVImportHistory
from sqlalchemy import and_, func, text
import requests
import json
from urllib.parse import unquote

logger = logging.getLogger(__name__)

class CSVProcessor:
    """Procesador principal para archivos CSV de ONUs con estadísticas avanzadas"""

    def __init__(self):
        self.supported_file_types = {
            'info1060': self._process_info1060_file,
            'matched_items': self._process_matched_items_file
        }
        
        # Configuración GenieACS para obtener dispositivos activos
        self.GENIEACS_URL = "http://192.168.0.237:7557"
        self.GENIEACS_USERNAME = "admin"
        self.GENIEACS_PASSWORD = "admin"

    def get_file_hash(self, file_path: str) -> str:
        """Calcular hash SHA256 del archivo para evitar duplicados"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculando hash del archivo: {e}")
            return ""

    def is_file_already_processed(self, file_hash: str, file_type: str) -> bool:
        """Verificar si el archivo ya fue procesado anteriormente"""
        return CSVImportHistory.query.filter(
            and_(
                CSVImportHistory.file_hash == file_hash,
                CSVImportHistory.file_type == file_type,
                CSVImportHistory.status == 'completed'
            )
        ).first() is not None

    def get_active_devices_from_genieacs(self) -> List[Dict]:
        """Obtener dispositivos activos desde GenieACS para estadísticas"""
        try:
            url = f"{self.GENIEACS_URL}/devices"
            response = requests.get(url, auth=(self.GENIEACS_USERNAME, self.GENIEACS_PASSWORD), timeout=10)
            response.raise_for_status()
            devices = response.json()
            
            active_devices = []
            for device in devices:
                try:
                    serial_number = unquote(device.get("_id", ""))
                    if serial_number:
                        # Extraer MAC address
                        mac_address = self._extract_mac_from_device(device)
                        active_devices.append({
                            'serial_number': serial_number,
                            'mac_address': mac_address
                        })
                except Exception as e:
                    logger.warning(f"Error procesando dispositivo GenieACS: {e}")
                    continue
            
            logger.info(f"📊 Dispositivos activos en GenieACS: {len(active_devices)}")
            return active_devices
            
        except Exception as e:
            logger.error(f"Error obteniendo dispositivos desde GenieACS: {e}")
            return []

    def _extract_mac_from_device(self, device: Dict) -> str:
        """Extraer MAC address del dispositivo GenieACS"""
        try:
            igw = device.get('InternetGatewayDevice', {})
            
            # Intentar diferentes ubicaciones del MAC
            wan_paths = [
                ['WANDevice', '1', 'WANConnectionDevice', '1', 'WANIPConnection', '1', 'MACAddress'],
                ['WANDevice', '1', 'WANConnectionDevice', '2', 'WANIPConnection', '1', 'MACAddress'],
                ['WANDevice', '1', 'WANConnectionDevice', '3', 'WANIPConnection', '1', 'MACAddress']
            ]
            
            for path in wan_paths:
                current = igw
                for key in path:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    else:
                        break
                else:
                    if isinstance(current, dict) and '_value' in current:
                        return str(current['_value']).upper()
            
            return ""
        except Exception as e:
            logger.error(f"Error extrayendo MAC: {e}")
            return ""

    def process_csv_file(self, file_path: str, file_type: str, user_id: int) -> Dict:
        """Procesar archivo CSV según su tipo con estadísticas mejoradas"""
        start_time = datetime.utcnow()
        
        # Calcular hash del archivo
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return {'success': False, 'message': 'Error calculando hash del archivo'}

        # Verificar si ya fue procesado
        if self.is_file_already_processed(file_hash, file_type):
            return {
                'success': False,
                'message': 'Este archivo ya fue procesado anteriormente',
                'code': 'ALREADY_PROCESSED'
            }

        # Crear registro en historial
        import_record = CSVImportHistory(
            file_name=file_path.split('/')[-1],
            file_type=file_type,
            file_hash=file_hash,
            user_id=user_id,
            status='processing'
        )
        db.session.add(import_record)
        db.session.commit()

        try:
            # Procesar según tipo de archivo
            if file_type not in self.supported_file_types:
                raise ValueError(f"Tipo de archivo no soportado: {file_type}")

            result = self.supported_file_types[file_type](file_path, import_record.id)

            # Actualizar registro con resultados
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            import_record.records_processed = result.get('processed', 0)
            import_record.records_imported = result.get('imported', 0)
            import_record.records_updated = result.get('updated', 0)
            import_record.records_skipped = result.get('skipped', 0)
            import_record.status = 'completed' if result['success'] else 'failed'
            import_record.error_message = result.get('error_message')
            import_record.processing_time = int(processing_time)
            db.session.commit()

            # Si es archivo de contratos, calcular estadísticas de cobertura
            if file_type == 'matched_items' and result['success']:
                coverage_stats = self._calculate_coverage_statistics()
                result['coverage_stats'] = coverage_stats
                logger.info(f"📊 Estadísticas de cobertura: {coverage_stats}")

            logger.info(f"Archivo {file_type} procesado: {result}")
            return result

        except Exception as e:
            # Marcar como fallido
            import_record.status = 'failed'
            import_record.error_message = str(e)
            db.session.commit()
            
            logger.error(f"Error procesando archivo {file_type}: {e}")
            return {
                'success': False,
                'message': f'Error procesando archivo: {str(e)}',
                'error': str(e)
            }

    def _calculate_coverage_statistics(self) -> Dict:
        """Calcular estadísticas de cobertura de contratos vs dispositivos activos"""
        try:
            # Obtener dispositivos activos de GenieACS
            active_devices = self.get_active_devices_from_genieacs()
            active_count = len(active_devices)
            
            if active_count == 0:
                logger.warning("No se encontraron dispositivos activos en GenieACS")
                return {
                    'active_devices': 0,
                    'devices_with_contract': 0,
                    'coverage_percentage': 0.0,
                    'message': 'No se pudieron obtener dispositivos activos de GenieACS'
                }

            # Obtener dispositivos con contrato en la BD
            devices_with_contract = db.session.query(func.count(DeviceContract.serial_number)).scalar() or 0
            
            # Calcular dispositivos activos que tienen contrato
            active_serials = [d['serial_number'] for d in active_devices if d['serial_number']]
            covered_devices = db.session.query(func.count(DeviceContract.serial_number)).filter(
                DeviceContract.serial_number.in_(active_serials)
            ).scalar() or 0
            
            # Calcular porcentaje de cobertura
            coverage_percentage = (covered_devices / active_count * 100) if active_count > 0 else 0.0
            
            stats = {
                'active_devices': active_count,
                'devices_with_contract': covered_devices,
                'coverage_percentage': round(coverage_percentage, 2),
                'message': f'{covered_devices}/{active_count} dispositivos activos tienen información de contrato'
            }
            
            # Log estadísticas en consola con formato bonito
            logger.info("=" * 60)
            logger.info("📊 ESTADÍSTICAS DE COBERTURA DE CONTRATOS")
            logger.info("=" * 60)
            logger.info(f"📡 Dispositivos activos en GenieACS: {active_count}")
            logger.info(f"📄 Dispositivos con contrato: {covered_devices}")
            logger.info(f"📈 Cobertura actual: {coverage_percentage:.1f}%")
            logger.info("=" * 60)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error calculando estadísticas de cobertura: {e}")
            return {
                'active_devices': 0,
                'devices_with_contract': 0,
                'coverage_percentage': 0.0,
                'error': str(e)
            }

    def _process_info1060_file(self, file_path: str, import_id: int) -> Dict:
        """
        Procesar archivo info1060_F6600R.CSV
        Formato esperado: ssid_2_4ghz,password_2_4ghz,ssid_5ghz,password_5ghz,serial_number
        """
        try:
            # Leer CSV
            df = pd.read_csv(file_path)
            required_columns = ['ssid_2_4ghz', 'password_2_4ghz', 'ssid_5ghz', 'password_5ghz', 'serial_number']

            # Verificar columnas requeridas
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return {
                    'success': False,
                    'message': f'Columnas faltantes: {", ".join(missing_columns)}'
                }

            processed = 0
            imported = 0
            updated = 0
            skipped = 0
            
            logger.info(f"📊 Procesando {len(df)} registros del archivo info1060")

            for index, row in df.iterrows():
                try:
                    serial = str(row['serial_number']).strip()
                    if not serial:
                        skipped += 1
                        continue

                    processed += 1

                    # Procesar red 2.4GHz
                    ssid_24 = str(row['ssid_2_4ghz']).strip() if pd.notna(row['ssid_2_4ghz']) else ''
                    password_24 = str(row['password_2_4ghz']).strip() if pd.notna(row['password_2_4ghz']) else ''

                    if ssid_24 and self._is_valid_ssid(ssid_24):
                        result = self._store_wifi_password(serial, '2.4GHz', ssid_24, password_24)
                        if result == 'imported':
                            imported += 1
                        elif result == 'updated':
                            updated += 1

                    # Procesar red 5GHz
                    ssid_5 = str(row['ssid_5ghz']).strip() if pd.notna(row['ssid_5ghz']) else ''
                    password_5 = str(row['password_5ghz']).strip() if pd.notna(row['password_5ghz']) else ''

                    if ssid_5 and self._is_valid_ssid(ssid_5):
                        result = self._store_wifi_password(serial, '5GHz', ssid_5, password_5)
                        if result == 'imported':
                            imported += 1
                        elif result == 'updated':
                            updated += 1

                    # Commit cada 100 registros para evitar transacciones muy largas
                    if processed % 100 == 0:
                        db.session.commit()
                        logger.info(f"📊 Procesados {processed}/{len(df)} registros info1060 ({(processed/len(df)*100):.1f}%)")

                except Exception as e:
                    logger.error(f"Error procesando fila {index}: {e}")
                    skipped += 1
                    continue

            # Commit final
            db.session.commit()

            return {
                'success': True,
                'processed': processed,
                'imported': imported,
                'updated': updated,
                'skipped': skipped,
                'message': f'Procesado correctamente: {imported} nuevos, {updated} actualizados, {skipped} omitidos'
            }

        except Exception as e:
            logger.error(f"Error en _process_info1060_file: {e}")
            return {
                'success': False,
                'message': f'Error procesando archivo info1060: {str(e)}',
                'error': str(e)
            }

    def _process_matched_items_file(self, file_path: str, import_id: int) -> Dict:
        """
        Procesar archivo matched_items.csv
        Formato esperado: mac_address,contract_number,customer_name
        """
        try:
            # Leer CSV
            df = pd.read_csv(file_path)
            required_columns = ['mac_address', 'contract_number', 'customer_name']

            # Verificar columnas mínimas requeridas
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return {
                    'success': False,
                    'message': f'Columnas faltantes: {", ".join(missing_columns)}'
                }

            processed = 0
            imported = 0
            updated = 0
            skipped = 0
            
            logger.info(f"📊 Procesando {len(df)} registros del archivo matched_items")
            logger.info("🔍 Buscando coincidencias con dispositivos activos...")

            # Obtener dispositivos activos para mostrar progreso
            active_devices = self.get_active_devices_from_genieacs()
            active_macs = {d['mac_address']: d['serial_number'] for d in active_devices if d['mac_address']}
            logger.info(f"📡 Dispositivos activos con MAC: {len(active_macs)}")

            matches_found = 0
            
            for index, row in df.iterrows():
                try:
                    mac = str(row['mac_address']).strip().upper() if pd.notna(row['mac_address']) else ''
                    contract = str(row['contract_number']).strip() if pd.notna(row['contract_number']) else ''
                    customer_name = str(row['customer_name']).strip() if pd.notna(row['customer_name']) else ''

                    if not mac or not contract:
                        skipped += 1
                        continue

                    processed += 1

                    # Buscar dispositivo por MAC en dispositivos activos
                    device_serial = active_macs.get(mac)
                    
                    if device_serial:
                        matches_found += 1
                        # Dispositivo encontrado, actualizar contrato
                        result = self._store_contract_info(device_serial, contract, customer_name)
                        if result == 'imported':
                            imported += 1
                        elif result == 'updated':
                            updated += 1
                            
                        # Log progreso cada vez que se encuentra una coincidencia
                        if matches_found % 10 == 0:
                            coverage_so_far = (matches_found / len(active_devices) * 100) if len(active_devices) > 0 else 0
                            logger.info(f"✅ Coincidencias encontradas: {matches_found} ({coverage_so_far:.1f}% cobertura)")
                    else:
                        # Si no se encuentra el dispositivo, guardar información para futuro uso
                        self._store_device_info_by_mac(mac, contract, customer_name, row)
                        imported += 1

                    # Commit cada 100 registros
                    if processed % 100 == 0:
                        db.session.commit()
                        progress_percentage = (processed / len(df) * 100)
                        logger.info(f"📊 Procesados {processed}/{len(df)} registros ({progress_percentage:.1f}%) - Coincidencias: {matches_found}")

                except Exception as e:
                    logger.error(f"Error procesando fila {index}: {e}")
                    skipped += 1
                    continue

            # Commit final
            db.session.commit()

            # Estadísticas finales
            final_coverage = (matches_found / len(active_devices) * 100) if len(active_devices) > 0 else 0
            logger.info("=" * 60)
            logger.info("✅ PROCESAMIENTO COMPLETADO")
            logger.info(f"📊 Registros procesados: {processed}")
            logger.info(f"🎯 Coincidencias encontradas: {matches_found}")
            logger.info(f"📈 Cobertura alcanzada: {final_coverage:.1f}%")
            logger.info("=" * 60)

            return {
                'success': True,
                'processed': processed,
                'imported': imported,
                'updated': updated,
                'skipped': skipped,
                'matches_found': matches_found,
                'coverage_percentage': round(final_coverage, 2),
                'message': f'Procesado correctamente: {imported} nuevos, {updated} actualizados. Coincidencias: {matches_found} ({final_coverage:.1f}% cobertura)'
            }

        except Exception as e:
            logger.error(f"Error en _process_matched_items_file: {e}")
            return {
                'success': False,
                'message': f'Error procesando archivo matched_items: {str(e)}',
                'error': str(e)
            }

    def _store_wifi_password(self, serial: str, band: str, ssid: str, password: str) -> str:
        """Almacenar contraseña WiFi, retorna 'imported', 'updated' o 'skipped'"""
        try:
            # Buscar si ya existe
            existing = WifiPassword.query.filter(
                and_(WifiPassword.serial_number == serial, WifiPassword.band == band)
            ).first()

            if existing:
                # Verificar si necesita actualización
                if existing.ssid != ssid or existing.password != password:
                    existing.ssid = ssid
                    existing.password = password
                    existing.updated_at = datetime.utcnow()
                    return 'updated'
                return 'skipped'
            else:
                # Crear nuevo registro
                wifi_pwd = WifiPassword(
                    serial_number=serial,
                    band=band,
                    ssid=ssid,
                    password=password
                )
                db.session.add(wifi_pwd)
                return 'imported'

        except Exception as e:
            logger.error(f"Error almacenando WiFi password para {serial}: {e}")
            return 'skipped'

    def _store_contract_info(self, serial: str, contract: str, customer_name: str) -> str:
        """Almacenar información de contrato, retorna 'imported', 'updated' o 'skipped'"""
        try:
            from db_services import DatabaseService
            success, message = DatabaseService.store_contract_with_customer_info(serial, contract, customer_name)
            return 'imported' if success else 'skipped'
        except Exception as e:
            logger.error(f"Error almacenando contrato para {serial}: {e}")
            return 'skipped'

    def _store_device_info_by_mac(self, mac: str, contract: str, customer_name: str, row):
        """Almacenar info del dispositivo por MAC cuando no se encuentra el serial"""
        try:
            ns = str(row.get('ns', '')).strip() if pd.notna(row.get('ns', '')) else ''
            model = str(row.get('model', '')).strip() if pd.notna(row.get('model', '')) else ''

            # Crear registro temporal con MAC como identificador
            temp_serial = f"MAC_{mac}"
            
            # Guardar información del dispositivo
            device_info = DeviceInfo.query.filter_by(device_serial=temp_serial).first()
            if device_info:
                device_info.mac_address = mac
                device_info.ns = ns if ns else device_info.ns
                device_info.model = model if model else device_info.model
                device_info.updated_at = datetime.utcnow()
            else:
                device_info = DeviceInfo(
                    device_serial=temp_serial,
                    mac_address=mac,
                    ns=ns,
                    model=model
                )
                db.session.add(device_info)

            # También guardar contrato temporal
            self._store_contract_info(temp_serial, contract, customer_name)

        except Exception as e:
            logger.error(f"Error almacenando info por MAC {mac}: {e}")

    def _is_valid_ssid(self, ssid: str) -> bool:
        """Validar que el SSID sea válido"""
        if not ssid or len(ssid.strip()) == 0:
            return False

        # Filtrar SSIDs obviamente inválidos
        invalid_patterns = [
            '**', '***', '....', '----', '____',
            'hidden', 'oculto', 'default'
        ]

        ssid_lower = ssid.lower().strip()
        for pattern in invalid_patterns:
            if pattern in ssid_lower:
                return False

        return len(ssid.strip()) >= 1 and len(ssid.strip()) <= 32

    def get_import_statistics(self, days: int = 30) -> Dict:
        """Obtener estadísticas de importaciones recientes"""
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
                'total_records_imported': sum(i.records_imported or 0 for i in imports),
                'by_file_type': {},
                'coverage_stats': self._calculate_coverage_statistics()
            }

            # Estadísticas por tipo de archivo
            for file_type in ['info1060', 'matched_items']:
                type_imports = [i for i in imports if i.file_type == file_type]
                stats['by_file_type'][file_type] = {
                    'count': len(type_imports),
                    'records_processed': sum(i.records_processed or 0 for i in type_imports),
                    'records_imported': sum(i.records_imported or 0 for i in type_imports)
                }

            return stats

        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}