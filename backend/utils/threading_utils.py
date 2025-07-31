# backend/threading_utils.py

import pandas as pd
import logging
from datetime import datetime
from pathlib import Path
from io import StringIO
from typing import List, Dict, Optional
from dataclasses import asdict

from utils.config_utils import (
    DeviceInfo, DeviceMetadata, ProcessingResult, ProcessingSession,
    DEFAULT_TIMEOUT, DEFAULT_RETRY_ATTEMPTS, DEVICE_STATUS
)

logger = logging.getLogger(__name__)

def get_csv_separator_from_content(content: str) -> str:
    """Determine CSV separator from content."""
    first_line = content.split('\n')[0] if content else ""
    
    # Count occurrences of common separators
    comma_count = first_line.count(',')
    semicolon_count = first_line.count(';')
    tab_count = first_line.count('\t')
    
    # Return the most common separator
    if comma_count >= semicolon_count and comma_count >= tab_count:
        return ','
    elif semicolon_count >= tab_count:
        return ';'
    else:
        return '\t'

def validate_csv_columns(df: pd.DataFrame) -> tuple[List[str], List[str], Dict[str, str]]:
    """Validate CSV columns and create column mapping."""
    errors = []
    warnings = []
    
    # Required columns mapping (case-insensitive)
    required_columns = {
        'IP MGMT': ['ip_mgmt', 'ip', 'ip_address', 'management_ip'],
        'NAMA SW': ['nama_sw', 'hostname', 'device_name', 'name'],
        'SN': ['sn', 'serial_number', 'serial'],
        'MODEL SW': ['model_sw', 'model', 'device_model']
    }
    
    column_mapping = {}
    df_columns_lower = [col.lower() for col in df.columns]
    
    for required_col, possible_names in required_columns.items():
        found = False
        for possible_name in possible_names:
            if possible_name.lower() in df_columns_lower:
                # Find the actual column name (with original case)
                actual_col = df.columns[df_columns_lower.index(possible_name.lower())]
                column_mapping[required_col] = actual_col
                found = True
                break
        
        if not found:
            errors.append(f"Required column '{required_col}' not found. Expected one of: {', '.join(possible_names)}")
    
    return errors, warnings, column_mapping

def process_single_device_with_retry(device_info: DeviceInfo, metadata: DeviceMetadata, 
                                   session: ProcessingSession, device_manager, 
                                   selected_commands: List[str] = None) -> ProcessingResult:
    """Process a single device with retry mechanism using APIs."""
    retry_count = 0
    max_retries = DEFAULT_RETRY_ATTEMPTS
    
    while retry_count < max_retries:
        if session.is_stopped:
            return ProcessingResult(
                ip_mgmt=metadata.ip_mgmt,
                nama_sw=metadata.nama_sw,
                sn=metadata.sn,
                model_sw=metadata.model_sw,
                status="Stopped",
                connection_status=DEVICE_STATUS["STOPPED"],
                retry_count=retry_count,
                last_attempt=datetime.now().isoformat(),
                error="Processing stopped by user"
            )
        
        start_time = datetime.now()
        
        try:
            connection_status = DEVICE_STATUS["CONNECTING"] if retry_count == 0 else DEVICE_STATUS["RETRYING"]
            
            device_data, error, final_status, detected_type, api_endpoint, api_response_time = device_manager.connect_and_collect_data(
                device_info, metadata.model_sw, retry_count, session, selected_commands
            )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            if error is None:
                return ProcessingResult(
                    ip_mgmt=metadata.ip_mgmt,
                    nama_sw=metadata.nama_sw,
                    sn=metadata.sn,
                    model_sw=metadata.model_sw,
                    status="Success",
                    data=device_data,
                    processing_time=processing_time,
                    retry_count=retry_count,
                    last_attempt=datetime.now().isoformat(),
                    connection_status=DEVICE_STATUS["SUCCESS"],
                    detected_device_type=detected_type,
                    api_endpoint=api_endpoint,
                    api_status="Connected",
                    api_response_time=api_response_time
                )
            else:
                retry_count += 1
                if retry_count < max_retries:
                    logger.info(f"Retrying {device_info.host} via API (attempt {retry_count + 1}/{max_retries}) after error: {error}")
                else:
                    logger.error(f"Failed to process {device_info.host} after {max_retries} attempts via API: {error}")
                    return ProcessingResult(
                        ip_mgmt=metadata.ip_mgmt,
                        nama_sw=metadata.nama_sw,
                        sn=metadata.sn,
                        model_sw=metadata.model_sw,
                        status="Failed",
                        error=str(error),
                        processing_time=processing_time,
                        retry_count=retry_count,
                        last_attempt=datetime.now().isoformat(),
                        connection_status=DEVICE_STATUS["FAILED"],
                        api_status="Failed"
                    )
        
        except Exception as e:
            processing_time = (datetime.now() - start_time).total_seconds()
            retry_count += 1
            if retry_count < max_retries:
                logger.info(f"Exception during processing {device_info.host}, retrying (attempt {retry_count + 1}/{max_retries}): {e}")
            else:
                logger.error(f"Exception during processing {device_info.host} after {max_retries} attempts: {e}")
                return ProcessingResult(
                    ip_mgmt=metadata.ip_mgmt,
                    nama_sw=metadata.nama_sw,
                    sn=metadata.sn,
                    model_sw=metadata.model_sw,
                    status="Failed",
                    error=str(e),
                    processing_time=processing_time,
                    retry_count=retry_count,
                    last_attempt=datetime.now().isoformat(),
                    connection_status=DEVICE_STATUS["FAILED"]
                )
    
    return ProcessingResult(
        ip_mgmt=metadata.ip_mgmt,
        nama_sw=metadata.nama_sw,
        sn=metadata.sn,
        model_sw=metadata.model_sw,
        status="Failed",
        error="Max retries exceeded",
        retry_count=max_retries,
        last_attempt=datetime.now().isoformat(),
        connection_status=DEVICE_STATUS["FAILED"]
    )

def process_devices_worker(username: str, password: str, file_content: str, session_id: str, 
                         selected_commands: List[str], retry_failed_only: bool,
                         device_manager, data_processor, processing_sessions) -> Dict:
    """Worker function for processing devices in a separate thread."""
    try:
        session = processing_sessions[session_id]
        session.start_time = datetime.now()
        
        logger.info(f"Starting API-based threaded processing for session {session_id}")
        
        if retry_failed_only:
            logger.info("Retrying failed devices only")
        
        separator = get_csv_separator_from_content(file_content)
        csv_io = StringIO(file_content)
        df = pd.read_csv(csv_io, sep=separator)
        df.columns = [col.strip() for col in df.columns]

        errors, warnings, column_mapping = validate_csv_columns(df)
        
        if errors:
            error_message = "CSV validation failed:\n" + "\n".join(errors)
            if warnings:
                error_message += "\n\nWarnings:\n" + "\n".join(warnings[:5])
                if len(warnings) > 5:
                    error_message += f"\n... and {len(warnings) - 5} more warnings"
            
            raise ValueError(error_message)

        session.total_devices = len(df)
        logger.info(f"Processing {len(df)} devices from CSV file using vendor APIs")

        results = []
        
        for idx, row in df.iterrows():
            if session.is_stopped:
                logger.info("API processing stopped by user")
                break
                
            device_info = DeviceInfo(
                host=str(row[column_mapping['IP MGMT']]).strip(),
                username=username,
                password=password,
                conn_timeout=DEFAULT_TIMEOUT,
                protocol="https",
                port=None
            )
            
            # Handle optional columns with defaults
            def get_optional_value(column_name, default="N/A"):
                if column_mapping.get(column_name):
                    val = str(row[column_mapping[column_name]]).strip()
                    return val if val not in ['', 'nan', 'NaN'] else default
                return default
            
            metadata = DeviceMetadata(
                ip_mgmt=device_info.host,
                nama_sw=get_optional_value('NAMA SW'),
                sn=get_optional_value('SN'),
                model_sw=get_optional_value('MODEL SW')
            )
            
            result = process_single_device_with_retry(device_info, metadata, session, device_manager, selected_commands)
            results.append(result)
            
            session.completed += 1
            if result.status == "Success":
                session.successful += 1
            else:
                session.failed += 1
        
        session.end_time = datetime.now()
        output_filename = data_processor.save_results(results, session_id)
        session.output_file = output_filename
        
        return {
            "status": "success" if not session.is_stopped else "stopped",
            "message": f"Processing complete: {session.successful} successful, {session.failed} failed",
            "data": [asdict(result) for result in results],
            "session_id": session_id,
            "output_file": Path(output_filename).name
        }
        
    except Exception as e:
        logger.error(f"Error in threaded processing: {e}")
        session = processing_sessions.get(session_id)
        if session:
            session.end_time = datetime.now()
        
        return {
            "status": "error",
            "message": str(e),
            "session_id": session_id
        }

def retry_failed_devices_worker(username: str, password: str, failed_devices: List[Dict], 
                              session_id: str, device_manager, data_processor, 
                              processing_sessions) -> Dict:
    """Worker function for retrying failed devices."""
    try:
        session = processing_sessions[session_id]
        session.start_time = datetime.now()
        
        logger.info(f"Starting retry processing for {len(failed_devices)} failed devices")
        
        results = []
        
        for device_data in failed_devices:
            if session.is_stopped:
                break
                
            device_info = DeviceInfo(
                host=device_data.get('ip_mgmt', ''),
                username=username,
                password=password,
                conn_timeout=DEFAULT_TIMEOUT,
                protocol="https",
                port=None
            )
            
            metadata = DeviceMetadata(
                ip_mgmt=device_data.get('ip_mgmt', ''),
                nama_sw=device_data.get('nama_sw', ''),
                sn=device_data.get('sn', ''),
                model_sw=device_data.get('model_sw', '')
            )
            
            result = process_single_device_with_retry(device_info, metadata, session, device_manager)
            results.append(result)
            
            session.completed += 1
            if result.status == "Success":
                session.successful += 1
            else:
                session.failed += 1
        
        session.end_time = datetime.now()
        output_filename = data_processor.save_results(results, session_id)
        session.output_file = output_filename
        
        return {
            "status": "success" if not session.is_stopped else "stopped",
            "message": f"Retry complete: {session.successful} successful, {session.failed} failed",
            "data": [asdict(result) for result in results],
            "session_id": session_id,
            "output_file": Path(output_filename).name
        }
        
    except Exception as e:
        logger.error(f"Error in retry processing: {e}")
        session = processing_sessions.get(session_id)
        if session:
            session.end_time = datetime.now()
        
        return {
            "status": "error",
            "message": str(e),
            "session_id": session_id
        }