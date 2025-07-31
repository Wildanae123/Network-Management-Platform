# backend/config_utils.py

import os
import json
import yaml
import time
import queue
import socket
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Constants
DEFAULT_TIMEOUT = 30
MAX_WORKERS = 10
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
LOGS_DIR = DEFAULT_OUTPUT_DIR
SUPPORTED_FILE_TYPES = ("CSV Files (*.csv)",)
SUPPORTED_EXPORT_TYPES = ("JSON Files (*.json)",)
EXCEL_ENGINE = "openpyxl"

# API endpoint configurations for different vendors
API_ENDPOINTS = {
    'arista_eos': {
        'endpoint': '/command-api',
        'default_protocol': 'https',
        'content_type': 'application/json-rpc',
        'api_type': 'json-rpc'
    },
    'cisco_nxos': {
        'endpoint': '/ins',
        'default_protocol': 'https',
        'content_type': 'application/json',
        'api_type': 'rest'
    },
    'cisco_xe': {
        'endpoint': '/restconf/data',
        'default_protocol': 'https',
        'content_type': 'application/yang-data+json',
        'api_type': 'restconf'
    }
}

# Vendor detection mapping based on Model SW
VENDOR_DETECTION_MAP = {
    'cisco_ios': ['ISR', 'C1100', 'C1000', 'C2900', 'C3900', 'CAT', 'WS-C', 'C9200', 'C9300', 'C9400', 'C9500', 'C3850', 'C3750'],
    'cisco_nxos': ['N9K', 'N7K', 'N5K', 'N3K', 'N2K', 'Nexus'],
    'cisco_xe': ['ASR', 'CSR', 'ISR4', 'C8000'],
    'cisco_xr': ['ASR9', 'NCS', 'CRS'],
    'arista_eos': ['DCS', 'CCS', 'Arista'],
}

# Device Status Constants
DEVICE_STATUS = {
    "PENDING": "pending",
    "CONNECTING": "connecting", 
    "SUCCESS": "success",
    "FAILED": "failed",
    "RETRYING": "retrying",
    "STOPPED": "stopped"
}

@dataclass
class DeviceInfo:
    """Data class for device information."""
    host: str
    device_type: str = "autodetect"
    username: str = ""
    password: str = ""
    conn_timeout: int = DEFAULT_TIMEOUT
    protocol: str = "https"
    port: int = None

@dataclass
class DeviceMetadata:
    """Data class for device metadata."""
    ip_mgmt: str
    nama_sw: str
    sn: str
    model_sw: str

@dataclass
class ProcessingResult:
    """Data class for processing results."""
    ip_mgmt: str
    nama_sw: str
    sn: str
    model_sw: str
    status: str
    data: Optional[Dict] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None
    retry_count: int = 0
    last_attempt: Optional[str] = None
    connection_status: str = DEVICE_STATUS["PENDING"]
    detected_device_type: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_status: Optional[str] = None
    api_response_time: Optional[float] = None

@dataclass
class ProcessingSession:
    """Data class for tracking processing sessions."""
    session_id: str
    total_devices: int
    completed: int = 0
    successful: int = 0
    failed: int = 0
    retrying: int = 0
    is_stopped: bool = False
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    output_file: Optional[str] = None

@dataclass
class ComparisonResult:
    """Data class for comparison results."""
    ip_mgmt: str
    hostname: str
    first_snapshot: Dict
    second_snapshot: Dict
    compare_result: Dict
    overall_status: str = "no_changes"
    command_results: Optional[Dict] = None

# Global session storage and log queue
processing_sessions = {}
current_session_id = [None]
log_queue = queue.Queue(maxsize=1000)

def get_next_log_number():
    """Get the next log file number for today."""
    today = datetime.now().strftime("%Y%m%d")
    log_pattern = f"network_fetcher_{today}_*.log"
    log_files = list(Path(DEFAULT_OUTPUT_DIR).glob(log_pattern))
    
    if not log_files:
        return 1
    
    numbers = []
    for log_file in log_files:
        try:
            # Extract number from filename like "network_fetcher_20250104_001.log"
            parts = log_file.stem.split('_')
            if len(parts) >= 3:
                number = int(parts[-1])
                numbers.append(number)
        except (ValueError, IndexError):
            continue
    
    return max(numbers, default=0) + 1

class StreamingLogHandler(logging.Handler):
    """Log handler for real-time streaming."""
    
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
        self.logs = []
        self.max_logs = 1000
    
    def emit(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': self.format(record),
            'module': record.module
        }
        
        # Add to memory storage
        self.logs.append(log_entry)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        # Add to streaming queue
        try:
            if not self.log_queue.full():
                self.log_queue.put_nowait(log_entry)
        except queue.Full:
            pass
    
    def get_logs(self):
        return self.logs
    
    def clear_logs(self):
        self.logs = []

def setup_logging():
    """Setup logging configuration with streaming support."""
    # Ensure output directory exists
    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    
    # Create streaming log handler
    streaming_handler = StreamingLogHandler(log_queue)
    streaming_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    
    # Update logging configuration with date and number
    log_number = get_next_log_number()
    log_filename = f"network_fetcher_{datetime.now().strftime('%Y%m%d')}_{log_number:03d}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(DEFAULT_OUTPUT_DIR, log_filename)),
            logging.StreamHandler(),
            streaming_handler
        ]
    )
    
    return streaming_handler, log_filename

def create_processing_session(session_id: str, total_devices: int) -> ProcessingSession:
    """Create a new processing session."""
    session = ProcessingSession(
        session_id=session_id,
        total_devices=total_devices,
        start_time=datetime.now()
    )
    processing_sessions[session_id] = session
    current_session_id[0] = session_id
    return session

def get_processing_session(session_id: str) -> Optional[ProcessingSession]:
    """Get processing session by ID."""
    return processing_sessions.get(session_id)

def update_session_stats(session_id: str, successful: int = 0, failed: int = 0, completed: int = 0):
    """Update session statistics."""
    session = processing_sessions.get(session_id)
    if session:
        session.successful += successful
        session.failed += failed
        session.completed += completed

def finalize_session(session_id: str, output_file: str = None):
    """Finalize processing session."""
    session = processing_sessions.get(session_id)
    if session:
        session.end_time = datetime.now()
        session.output_file = output_file

def validate_csv_file(file_content: str) -> tuple[bool, str, List[DeviceMetadata]]:
    """Validate CSV file content and extract device metadata."""
    try:
        lines = file_content.strip().split('\n')
        if not lines:
            return False, "File is empty", []
        
        headers = [h.strip().lower() for h in lines[0].split(',')]
        required_headers = ['ip_mgmt', 'nama_sw', 'sn', 'model_sw']
        
        missing_headers = [h for h in required_headers if h not in headers]
        if missing_headers:
            return False, f"Missing required headers: {', '.join(missing_headers)}", []
        
        devices = []
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                continue
                
            values = [v.strip() for v in line.split(',')]
            if len(values) != len(headers):
                return False, f"Row {i} has incorrect number of columns", []
            
            row_data = dict(zip(headers, values))
            device = DeviceMetadata(
                ip_mgmt=row_data['ip_mgmt'],
                nama_sw=row_data['nama_sw'],
                sn=row_data['sn'],
                model_sw=row_data['model_sw']
            )
            devices.append(device)
        
        return True, f"Valid CSV with {len(devices)} devices", devices
        
    except Exception as e:
        return False, f"Error parsing CSV: {str(e)}", []

def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    return {
        'version': '2.2.0',
        'supported_vendors': list(API_ENDPOINTS.keys()),
        'max_concurrent_devices': MAX_WORKERS,
        'default_timeout': DEFAULT_TIMEOUT,
        'output_directory': DEFAULT_OUTPUT_DIR,
        'supported_file_types': list(SUPPORTED_FILE_TYPES),
        'supported_export_types': list(SUPPORTED_EXPORT_TYPES)
    }

def cleanup_old_sessions(max_age_hours: int = 24):
    """Clean up old processing sessions."""
    cutoff_time = datetime.now() - datetime.timedelta(hours=max_age_hours)
    sessions_to_remove = []
    
    for session_id, session in processing_sessions.items():
        if session.end_time and session.end_time < cutoff_time:
            sessions_to_remove.append(session_id)
    
    for session_id in sessions_to_remove:
        del processing_sessions[session_id]

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['csv']

def get_csv_separator_from_content(file_content: str):
    """Detects the separator of a CSV file from content string."""
    try:
        header = file_content.split('\n')[0]
        separators = {',': header.count(','), ';': header.count(';'), '\t': header.count('\t'), '|': header.count('|')}
        separator = max(separators.items(), key=lambda x: x[1])[0]
        return separator
    except Exception:
        return ','

def validate_ip_address(ip_str):
    """Validate IP address format."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    return True

def validate_csv_columns(df):
    """Validate CSV columns - IP MGMT required, others optional."""
    errors = []
    warnings = []
    
    # Only IP MGMT is required
    required_columns = {
        'IP MGMT': ['ip mgmt', 'ip_mgmt', 'ip', 'management ip', 'mgmt_ip', 'device_ip'],
    }
    
    # Optional columns
    optional_columns = {
        'Nama SW': ['nama sw', 'nama_sw', 'name', 'hostname', 'device_name', 'switch_name'],
        'SN': ['sn', 'serial', 'serial_number', 'serial number', 'serial_no'],
        'Model SW': ['model sw', 'model_sw', 'model', 'device_model', 'switch_model']
    }
    
    if df.empty:
        errors.append("CSV file is empty. Please provide a file with device information.")
        return errors, warnings, {}
    
    column_mapping = {}
    df_cols_lower = {col.lower(): col for col in df.columns}
    
    # Check required columns
    for req_col, aliases in required_columns.items():
        found = False
        for alias in [req_col.lower()] + aliases:
            if alias in df_cols_lower:
                column_mapping[req_col] = df_cols_lower[alias]
                found = True
                break
        
        if not found:
            errors.append(f"Missing required column '{req_col}'. Acceptable column names: {', '.join([req_col] + [a.upper() for a in aliases])}")
    
    # Check optional columns
    for opt_col, aliases in optional_columns.items():
        found = False
        for alias in [opt_col.lower()] + aliases:
            if alias in df_cols_lower:
                column_mapping[opt_col] = df_cols_lower[alias]
                found = True
                break
        
        if not found:
            # Use placeholder for missing optional columns
            column_mapping[opt_col] = None
            warnings.append(f"Optional column '{opt_col}' not found. Will use 'N/A' as default value.")
    
    # Validate data rows
    if not errors:
        for idx, row in df.iterrows():
            row_num = idx + 2
            
            # Validate required IP MGMT
            ip_val = str(row[column_mapping['IP MGMT']]).strip()
            if not ip_val or ip_val.lower() in ['nan', 'none', 'null', '']:
                errors.append(f"Row {row_num}: Missing IP address (required)")
            elif not validate_ip_address(ip_val):
                errors.append(f"Row {row_num}: Invalid IP address format '{ip_val}'")
    
    return errors, warnings, column_mapping

def detect_vendors_from_data(data):
    """Detect vendors from device data."""
    vendor_stats = {}
    for result in data:
        if result.get('status') == 'Success' and result.get('detected_device_type'):
            device_type = result['detected_device_type']
            vendor_stats[device_type] = vendor_stats.get(device_type, 0) + 1
    return vendor_stats

def detect_device_type_by_model_static(model_sw: str) -> str:
    """Static device type detection by model string."""
    model_upper = model_sw.upper()
    
    for device_type, patterns in VENDOR_DETECTION_MAP.items():
        for pattern in patterns:
            if pattern.upper() in model_upper:
                return device_type
    
    return "arista_eos"