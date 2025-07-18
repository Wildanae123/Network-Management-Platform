# backend/server.py

import os
import json
import threading
import concurrent.futures
import yaml
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import difflib
import logging
import time
import uuid
import requests
import webbrowser
import threading
import tempfile
import io
import base64
import sys
import queue
import socket
import subprocess
import getpass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, send_file, send_from_directory, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from collections import defaultdict
from utils.ssl_utils import setup_arista_connection
from app.core.config_manager import ConfigManager

# Setup SSL and jsonrpclib
Server = setup_arista_connection()

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
    'juniper_junos': ['EX', 'QFX', 'MX', 'SRX', 'ACX'],
    'hp_procurve': ['ProCurve', 'Aruba', 'HP'],
    'dell_force10': ['S4048', 'S5048', 'S6010', 'Z9100'],
    'huawei': ['S5700', 'S6700', 'S7700', 'S9700', 'CE'],
    'fortinet': ['FGT', 'FortiGate'],
}

# Configure logging with real-time streaming
os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)

# Helper function for log numbering
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

# Global log queue for real-time streaming
log_queue = queue.Queue(maxsize=1000)

class StreamingLogHandler(logging.Handler):
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
logger = logging.getLogger(__name__)

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

class APIClientBase:
    """Base class for vendor API clients."""
    
    def __init__(self, host: str, username: str, password: str, timeout: int = DEFAULT_TIMEOUT, protocol: str = "https", port: int = None):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.protocol = protocol
        self.port = port
        
        # Create session with SSL verification disabled
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False

        # Additional SSL configuration
        self.session.headers.update({
            'User-Agent': 'NetworkDataApp/2.2.0'
        })
        
        # Configure adapter for SSL bypass
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def _get_base_url(self, endpoint: str) -> str:
        """Get the base URL for API calls."""
        return f"{self.protocol}://{self.host}{endpoint}"
    
    def test_connection(self) -> tuple[bool, str]:
        """Test API connectivity."""
        raise NotImplementedError("Subclasses must implement test_connection")
    
    def execute_commands(self, commands: List[str]) -> tuple[Dict, Optional[str]]:
        """Execute a list of commands via API."""
        raise NotImplementedError("Subclasses must implement execute_commands")

class AristaEAPIClient(APIClientBase):
    """Arista eAPI client using JSON-RPC."""
    
    def __init__(self, host: str, username: str, password: str, timeout: int = DEFAULT_TIMEOUT, protocol: str = "https", port: int = None):
        super().__init__(host, username, password, timeout, protocol, port)
        self.endpoint = API_ENDPOINTS['arista_eos']['endpoint']
        
        # Use default HTTPS without explicit port
        self.server_url = f"{self.protocol}://{self.username}:{self.password}@{self.host}{self.endpoint}"
        self.switch = None
        
        # Set global SSL bypass
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context
        
        # Set global socket timeout
        socket.setdefaulttimeout(self.timeout)
        
        logger.debug(f"Initialized Arista eAPI client for {self.host} using {self.protocol}")
    
    def _get_server_connection(self):
        """Get or create JSON-RPC server connection."""
        if self.switch is None:
            try:
                # Create server proxy with SSL bypass
                self.switch = ServerProxy(
                    self.server_url,
                    verbose=False
                )
                
                logger.debug(f"Created JSON-RPC server connection for {self.host}")

            except Exception as e:
                logger.error(f"Failed to create JSON-RPC server connection for {self.host}: {e}")
                raise
        return self.switch

    def test_connection(self) -> tuple[bool, str]:
        """Test eAPI connectivity with show version."""
        try:
            logger.debug(f"Testing eAPI connection to {self.host}")
            switch = self._get_server_connection()
            
            # Test with show version command
            result = switch.runCmds(version=1, cmds=['show version'], format='json')
            
            if result and len(result) > 0:
                version_info = result[0]
                device_model = version_info.get('modelName', 'Unknown')
                hostname = version_info.get('hostname', 'Unknown')
                logger.info(f"eAPI connection successful to {self.host} - {device_model} ({hostname})")
                return True, f"eAPI connection successful - {device_model}"
            else:
                error_msg = "eAPI test failed: No response from device"
                logger.warning(f"{error_msg} for {self.host}")
                return False, error_msg
                
        except Exception as e:
            error_msg_original = str(e).lower()
            
            # Error handling with specific messages
            if "authentication failed" in error_msg_original or "unauthorized" in error_msg_original:
                error_msg = "eAPI Authentication failed: Check username and password"
            elif "connection refused" in error_msg_original:
                error_msg = "eAPI Connection refused: Check if eAPI is enabled on device. Run: (config)# management api http-commands; (config-mgmt-api-http-cmds)# no shutdown"
            elif "timeout" in error_msg_original or "timed out" in error_msg_original:
                error_msg = f"eAPI Connection timeout after {self.timeout}s: Check network connectivity"
            elif "ssl" in error_msg_original or "certificate" in error_msg_original:
                error_msg = "eAPI SSL/Certificate error: Device HTTPS configuration issue"
            elif "name or service not known" in error_msg_original or "no address associated" in error_msg_original:
                error_msg = "eAPI DNS resolution failed: Check IP address or hostname"
            elif "no route to host" in error_msg_original:
                error_msg = "eAPI No route to host: Check network routing and firewall"
            else:
                error_msg = f"eAPI connection failed: {str(e)}"
            
            logger.error(f"{error_msg} for {self.host}")
            return False, error_msg
    
    def execute_commands(self, commands: List[str]) -> tuple[Dict, Optional[str]]:
        """Execute commands via Arista eAPI using jsonrpclib with error handling."""
        try:
            switch = self._get_server_connection()
            logger.debug(f"Executing {len(commands)} commands via eAPI on {self.host}: {commands}")
            
            # Execute commands using jsonrpclib
            start_time = time.time()
            result = switch.runCmds(version=1, cmds=commands, format='json')
            execution_time = time.time() - start_time
            
            if result and isinstance(result, list):
                # Transform result into command-output mapping
                output = {}
                for i, cmd in enumerate(commands):
                    if i < len(result):
                        output[cmd] = result[i]
                    else:
                        output[cmd] = {"error": "No result returned for this command"}
                
                logger.debug(f"Successfully executed {len(commands)} commands via eAPI on {self.host} in {execution_time:.2f}s")
                return output, None
            else:
                error_msg = "Invalid eAPI response format"
                logger.error(f"{error_msg} for {self.host}")
                return {}, error_msg
                
        except Exception as e:
            error_msg_original = str(e).lower()
            
            # Error handling for command execution
            if "authentication failed" in error_msg_original:
                error_msg = "eAPI Authentication failed during command execution"
            elif "connection refused" in error_msg_original:
                error_msg = "eAPI Connection lost during command execution"
            elif "timeout" in error_msg_original:
                error_msg = f"eAPI Command execution timeout after {self.timeout}s"
            elif "invalid command" in error_msg_original or "cli command" in error_msg_original:
                error_msg = f"eAPI Invalid command in list: {commands}"
            else:
                error_msg = f"eAPI execution error: {str(e)}"
            
            logger.error(f"{error_msg} for {self.host}")
            return {}, error_msg


class NetworkDeviceAPIManager:
    """Network device manager using vendor APIs instead of SSH."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
    
    def detect_device_type_by_model(self, model_sw: str) -> str:
        """Detect device type based on model string."""
        model_upper = model_sw.upper()
        
        for device_type, patterns in VENDOR_DETECTION_MAP.items():
            for pattern in patterns:
                if pattern.upper() in model_upper:
                    logger.info(f"Detected device type '{device_type}' for model '{model_sw}'")
                    return device_type
        
        logger.warning(f"Could not detect device type for model '{model_sw}', defaulting to arista_eos")
        return "arista_eos"
    
    def create_api_client(self, device_info: DeviceInfo) -> APIClientBase:
        """Create appropriate API client based on device type."""
        if device_info.device_type == "arista_eos":
            return AristaEAPIClient(
                device_info.host, 
                device_info.username, 
                device_info.password,
                device_info.conn_timeout,
                device_info.protocol,
                device_info.port
            )
        else:
            logger.warning(f"Unsupported device type '{device_info.device_type}', defaulting to Arista eAPI")
            return AristaEAPIClient(
                device_info.host, 
                device_info.username, 
                device_info.password,
                device_info.conn_timeout,
                device_info.protocol,
                device_info.port
            )
    
    def connect_and_collect_data(self, device_info: DeviceInfo, model_sw: str = None, retry_count: int = 0, session: ProcessingSession = None, selected_commands: List[str] = None):
        """Connect to device via API and collect data with error handling."""
        collected_data = {}
        start_time = datetime.now()
        detected_device_type = None
        api_endpoint = None
        api_response_time = None
        
        try:
            # Device type detection
            if model_sw and device_info.device_type == "autodetect":
                detected_type = self.detect_device_type_by_model(model_sw)
                device_info.device_type = detected_type
            elif device_info.device_type == "autodetect":
                device_info.device_type = "arista_eos"
            
            detected_device_type = device_info.device_type
            
            logger.info(f"Connecting to device: {device_info.host} via {detected_device_type} API (attempt {retry_count + 1})")
            
            # Create API client
            api_client = self.create_api_client(device_info)
            api_endpoint = f"{device_info.protocol}://{device_info.host}{api_client.endpoint}"
            
            # Test connection with error handling
            api_test_start = time.time()
            connection_ok, connection_msg = api_client.test_connection()
            api_response_time = time.time() - api_test_start
            
            if not connection_ok:
                error_msg = f"API connection test failed: {connection_msg}"
                logger.error(error_msg)
                return None, error_msg, DEVICE_STATUS["FAILED"], detected_device_type, api_endpoint, api_response_time
            
            logger.info(f"Successfully connected to {device_info.host} via {detected_device_type} API (response time: {api_response_time:.2f}s)")
            
            # Get commands configuration
            commands_by_category = self.config_manager.get_commands_for_device(detected_device_type)
            
            if not commands_by_category:
                error_msg = f"Device type '{detected_device_type}' not supported in API configuration"
                logger.warning(error_msg)
                return None, error_msg, DEVICE_STATUS["FAILED"], detected_device_type, api_endpoint, api_response_time
            
            # Filter commands if specific commands are selected
            if selected_commands:
                filtered_commands = {}
                for category in selected_commands:
                    if category in commands_by_category:
                        filtered_commands[category] = commands_by_category[category]
                commands_by_category = filtered_commands
                logger.debug(f"Filtered to selected command categories: {list(filtered_commands.keys())}")
            
            # Execute commands by category
            for category, commands in commands_by_category.items():
                logger.debug(f"Processing category '{category}' with {len(commands)} commands via API")
                
                if session and session.is_stopped:
                    return None, "Processing stopped by user", DEVICE_STATUS["STOPPED"], detected_device_type, api_endpoint, api_response_time
                
                try:
                    category_results, category_error = api_client.execute_commands(commands)
                    
                    if category_error:
                        logger.warning(f"API error in category '{category}': {category_error}")
                        collected_data[category] = {"error": category_error}
                    else:
                        collected_data[category] = category_results
                        logger.debug(f"Category '{category}' executed successfully via API")
                        
                except Exception as cmd_error:
                    error_msg = f"Category '{category}' failed via API: {str(cmd_error)}"
                    logger.warning(f"{error_msg} on {device_info.host}")
                    collected_data[category] = {"error": error_msg}
            
            processing_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"API data collection completed for {device_info.host} in {processing_time:.2f}s")
            
            return collected_data, None, DEVICE_STATUS["SUCCESS"], detected_device_type, api_endpoint, api_response_time
            
        except Exception as e:
            error_msg = f"Unexpected API error for {device_info.host}: {str(e)}"
            logger.error(error_msg)
            return None, error_msg, DEVICE_STATUS["FAILED"], detected_device_type, api_endpoint, api_response_time

class DataProcessor:
    """Data processor with enhanced filtering and comparison capabilities."""
    
    def __init__(self, output_dir: str = DEFAULT_OUTPUT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def save_results(self, results, session_id: str = None, selected_commands: List[str] = None):
        """Save processing results to JSON file with timestamp-based naming."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Simple timestamp-only filename
        filename = f"data_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        try:
            # Add metadata to the results
            output_data = {
                "metadata": {
                    "timestamp": timestamp,
                    "session_id": session_id,
                    "selected_commands": selected_commands,
                    "total_devices": len(results),
                    "successful_devices": len([r for r in results if r.status == "Success"]),
                    "failed_devices": len([r for r in results if r.status == "Failed"]),
                    "connection_method": "API"
                },
                "results": [asdict(result) for result in results]
            }
            
            with open(filepath, "w", encoding='utf-8') as f:
                json.dump(output_data, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Results saved to {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            raise
    
    def load_results(self, filepath: str):
        """Load results from JSON file."""
        try:
            with open(filepath, "r", encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading results from {filepath}: {e}")
            raise
    
    def export_to_excel_enhanced(self, results: List[Dict], filepath: str, export_type: str = "detailed"):
        """Enhanced Excel export with better organization."""
        try:
            if export_type == "detailed":
                # Create multiple sheets for different data types
                with pd.ExcelWriter(filepath, engine=EXCEL_ENGINE) as writer:
                    # Summary sheet
                    summary_data = []
                    for result in results:
                        summary_data.append({
                            "IP Address": result.get("ip_mgmt", "N/A"),
                            "Hostname": result.get("nama_sw", "N/A"),
                            "Model": result.get("model_sw", "N/A"),
                            "Serial Number": result.get("sn", "N/A"),
                            "Status": result.get("status", "N/A"),
                            "Processing Time (s)": result.get("processing_time", "N/A"),
                            "Connection Status": result.get("connection_status", "N/A"),
                            "API Endpoint": result.get("api_endpoint", "N/A"),
                            "API Response Time (s)": result.get("api_response_time", "N/A"),
                            "Error": result.get("error", "N/A")
                        })
                    
                    df_summary = pd.DataFrame(summary_data)
                    df_summary.to_excel(writer, sheet_name='Summary', index=False)
                    
                    # Command data sheets
                    if results:
                        command_categories = set()
                        for result in results:
                            if result.get("data") and result.get("status") == "Success":
                                command_categories.update(result["data"].keys())
                        
                        for category in command_categories:
                            category_data = []
                            for result in results:
                                if result.get("data") and category in result["data"]:
                                    data = result["data"][category]
                                    if isinstance(data, dict):
                                        # Flatten nested data
                                        flattened = self._flatten_dict(data, result.get("ip_mgmt", "N/A"), result.get("nama_sw", "N/A"))
                                        category_data.extend(flattened)
                                    else:
                                        category_data.append({
                                            "IP Address": result.get("ip_mgmt", "N/A"),
                                            "Hostname": result.get("nama_sw", "N/A"),
                                            "Data": str(data)
                                        })
                            
                            if category_data:
                                df_category = pd.DataFrame(category_data)
                                sheet_name = category.replace('_', ' ').title()[:31]  # Excel sheet name limit
                                df_category.to_excel(writer, sheet_name=sheet_name, index=False)
            
            else:
                # Simple export
                df = pd.DataFrame(results)
                df.to_excel(filepath, index=False, engine=EXCEL_ENGINE)

            logger.info(f"Enhanced data exported to Excel: {filepath}")

        except Exception as e:
            logger.error(f"Error exporting to Excel: {e}")
            raise

    def _flatten_dict(self, data: Dict, ip_address: str, hostname: str = "N/A", parent_key: str = '', sep: str = '.') -> List[Dict]:
        """Flatten nested dictionary for Excel export."""
        items = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{parent_key}{sep}{key}" if parent_key else key
                
                if isinstance(value, dict):
                    items.extend(self._flatten_dict(value, ip_address, hostname, new_key, sep))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            items.extend(self._flatten_dict(item, ip_address, hostname, f"{new_key}[{i}]", sep))
                        else:
                            items.append({
                                "IP Address": ip_address,
                                "Hostname": hostname,
                                "Field": f"{new_key}[{i}]",
                                "Value": str(item)
                            })
                else:
                    items.append({
                        "IP Address": ip_address,
                        "Hostname": hostname,
                        "Field": new_key,
                        "Value": str(value)
                    })
        
        return items

    def export_to_excel_comparison(self, comparison_results: List[Dict], filepath: str):
        """Export enhanced comparison results to Excel."""
        try:
            with pd.ExcelWriter(filepath, engine=EXCEL_ENGINE) as writer:
                # Summary sheet
                summary_data = []
                detailed_data = []
                
                for result in comparison_results:
                    # Handle both dict and ComparisonResult objects
                    if isinstance(result, dict):
                        ip_mgmt = result.get('ip_mgmt', 'Unknown')
                        hostname = result.get('hostname', 'Unknown')
                        overall_status = result.get('overall_status', 'unknown')
                        command_results = result.get('command_results', {})
                    else:
                        ip_mgmt = result.ip_mgmt
                        hostname = result.hostname
                        overall_status = result.overall_status
                        command_results = result.command_results or {}

                    # Summary row
                    summary_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Overall Status": overall_status,
                        "Total Commands": len(command_results),
                        "Changed Commands": len([r for r in command_results.values() if r.get("status") == "changed"]),
                        "Unchanged Commands": len([r for r in command_results.values() if r.get("status") == "no_changes"]),
                        "Error Commands": len([r for r in command_results.values() if r.get("status") == "error"])
                    })

                    # Detailed rows for each command
                    for command, cmd_result in command_results.items():
                        detailed_data.append({
                            "IP Address": ip_mgmt,
                            "Hostname": hostname,
                            "Command": command.replace('_', ' ').title(),
                            "Status": cmd_result.get("status", "unknown"),
                            "Summary": cmd_result.get("summary", "No summary available"),
                            "Added Items": len(cmd_result.get("added", [])),
                            "Removed Items": len(cmd_result.get("removed", [])),
                            "Modified Items": len(cmd_result.get("modified", [])),
                            "Details": "; ".join(cmd_result.get("details", [])) if cmd_result.get("details") else "No changes"
                        })

                # Create sheets
                if summary_data:
                    df_summary = pd.DataFrame(summary_data)
                    df_summary.to_excel(writer, sheet_name='Summary', index=False)

                if detailed_data:
                    df_detailed = pd.DataFrame(detailed_data)
                    df_detailed.to_excel(writer, sheet_name='Detailed Changes', index=False)

                # Create individual sheets for each command type
                command_types = set()
                for result in comparison_results:
                    command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
                    command_types.update(command_results.keys())

                for command_type in command_types:
                    command_data = []
                    for result in comparison_results:
                        if isinstance(result, dict):
                            ip_mgmt = result.get('ip_mgmt', 'Unknown')
                            hostname = result.get('hostname', 'Unknown')
                            command_results = result.get('command_results', {})
                        else:
                            ip_mgmt = result.ip_mgmt
                            hostname = result.hostname
                            command_results = result.command_results or {}

                        if command_type in command_results:
                            cmd_result = command_results[command_type]
                            
                            # Add changes details
                            for change_type in ['added', 'removed', 'modified']:
                                changes = cmd_result.get(change_type, [])
                                for change in changes:
                                    command_data.append({
                                        "IP Address": ip_mgmt,
                                        "Hostname": hostname,
                                        "Change Type": change_type.title(),
                                        "Description": change.get('description', str(change)),
                                        "Details": str(change)
                                    })

                    if command_data:
                        df_command = pd.DataFrame(command_data)
                        sheet_name = command_type.replace('_', ' ').title()[:31]
                        df_command.to_excel(writer, sheet_name=sheet_name, index=False)

            logger.info(f"Enhanced comparison data exported to Excel: {filepath}")

        except Exception as e:
            logger.error(f"Error exporting comparison to Excel: {e}")
            raise

    def _compare_command_data(self, first_data: Dict, second_data: Dict, command_category: str) -> Dict:
        """Enhanced comparison with detailed changes."""
        try:
            differences = {
                "status": "no_changes",
                "summary": "",
                "details": [],
                "added": [],
                "removed": [],
                "modified": [],
                "statistics": {}
            }
            
            if command_category == "mac_address_table":
                differences = self._compare_mac_table_enhanced(first_data, second_data)
            elif command_category == "ip_arp":
                differences = self._compare_arp_table_enhanced(first_data, second_data)
            elif command_category == "interfaces_status":
                differences = self._compare_interfaces_enhanced(first_data, second_data)
            elif command_category == "mlag_interfaces":
                differences = self._compare_mlag_enhanced(first_data, second_data)
            else:
                # Generic comparison with detailed diff
                differences = self._generic_comparison(first_data, second_data, command_category)
            
            return differences
            
        except Exception as e:
            logger.error(f"Error comparing command data: {e}")
            return {
                "status": "error",
                "summary": f"Error during comparison: {str(e)}",
                "details": [],
                "added": [],
                "removed": [],
                "modified": [],
                "statistics": {"error": str(e)}
            }

    def _compare_mac_table_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced MAC table comparison."""
        differences = {
            "status": "no_changes",
            "summary": "",
            "details": [],
            "added": [],
            "removed": [],
            "modified": [],
            "statistics": {}
        }
        
        try:
            first_cmd = first_data.get('show mac address-table', {})
            second_cmd = second_data.get('show mac address-table', {})
            
            if not first_cmd or not second_cmd:
                differences["status"] = "error"
                differences["summary"] = "MAC table data missing"
                return differences
            
            first_entries = first_cmd.get('unicastTable', {}).get('tableEntries', [])
            second_entries = second_cmd.get('unicastTable', {}).get('tableEntries', [])
            
            # Create detailed mappings
            first_macs = {entry['macAddress']: entry for entry in first_entries}
            second_macs = {entry['macAddress']: entry for entry in second_entries}
            
            added_macs = set(second_macs.keys()) - set(first_macs.keys())
            removed_macs = set(first_macs.keys()) - set(second_macs.keys())
            
            # Check for modifications in existing MACs
            modified_macs = []
            for mac in set(first_macs.keys()) & set(second_macs.keys()):
                if first_macs[mac] != second_macs[mac]:
                    modified_macs.append({
                        'mac': mac,
                        'before': first_macs[mac],
                        'after': second_macs[mac]
                    })
            
            # Compile results
            if added_macs:
                for mac in added_macs:
                    entry = second_macs[mac]
                    differences["added"].append({
                        'type': 'mac_entry',
                        'mac': mac,
                        'vlan': entry.get('vlanId'),
                        'interface': entry.get('interface'),
                        'description': f"MAC {mac} added on VLAN {entry.get('vlanId')} interface {entry.get('interface')}"
                    })
            
            if removed_macs:
                for mac in removed_macs:
                    entry = first_macs[mac]
                    differences["removed"].append({
                        'type': 'mac_entry',
                        'mac': mac,
                        'vlan': entry.get('vlanId'),
                        'interface': entry.get('interface'),
                        'description': f"MAC {mac} removed from VLAN {entry.get('vlanId')} interface {entry.get('interface')}"
                    })
            
            if modified_macs:
                for mod in modified_macs:
                    differences["modified"].append({
                        'type': 'mac_entry',
                        'mac': mod['mac'],
                        'changes': mod,
                        'description': f"MAC {mod['mac']} modified"
                    })
            
            # Statistics
            differences["statistics"] = {
                'total_before': len(first_entries),
                'total_after': len(second_entries),
                'added_count': len(added_macs),
                'removed_count': len(removed_macs),
                'modified_count': len(modified_macs)
            }
            
            if added_macs or removed_macs or modified_macs:
                differences["status"] = "changed"
                differences["summary"] = f"MAC table changes: {len(added_macs)} added, {len(removed_macs)} removed, {len(modified_macs)} modified"
                
                # Compile details
                differences["details"] = []
                differences["details"].extend([item['description'] for item in differences["added"]])
                differences["details"].extend([item['description'] for item in differences["removed"]])
                differences["details"].extend([item['description'] for item in differences["modified"]])
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing MAC tables: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

    def _compare_arp_table_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced ARP table comparison."""
        differences = {
            "status": "no_changes",
            "summary": "",
            "details": [],
            "added": [],
            "removed": [],
            "modified": [],
            "statistics": {}
        }
        
        try:
            first_cmd = first_data.get('show ip arp', {})
            second_cmd = second_data.get('show ip arp', {})
            
            if not first_cmd or not second_cmd:
                differences["status"] = "error"
                differences["summary"] = "ARP table data missing"
                return differences
            
            first_entries = first_cmd.get('ipV4Neighbors', [])
            second_entries = second_cmd.get('ipV4Neighbors', [])
            
            first_ips = {entry['address']: entry for entry in first_entries}
            second_ips = {entry['address']: entry for entry in second_entries}
            
            added_ips = set(second_ips.keys()) - set(first_ips.keys())
            removed_ips = set(first_ips.keys()) - set(second_ips.keys())
            
            # Check for modifications
            modified_ips = []
            for ip in set(first_ips.keys()) & set(second_ips.keys()):
                if first_ips[ip] != second_ips[ip]:
                    modified_ips.append({
                        'ip': ip,
                        'before': first_ips[ip],
                        'after': second_ips[ip]
                    })
            
            # Compile results
            if added_ips:
                for ip in added_ips:
                    entry = second_ips[ip]
                    differences["added"].append({
                        'type': 'arp_entry',
                        'ip': ip,
                        'mac': entry.get('hwAddress'),
                        'interface': entry.get('interface'),
                        'description': f"ARP {ip} added with MAC {entry.get('hwAddress')} on {entry.get('interface')}"
                    })
            
            if removed_ips:
                for ip in removed_ips:
                    entry = first_ips[ip]
                    differences["removed"].append({
                        'type': 'arp_entry',
                        'ip': ip,
                        'mac': entry.get('hwAddress'),
                        'interface': entry.get('interface'),
                        'description': f"ARP {ip} removed with MAC {entry.get('hwAddress')} from {entry.get('interface')}"
                    })
            
            if modified_ips:
                for mod in modified_ips:
                    differences["modified"].append({
                        'type': 'arp_entry',
                        'ip': mod['ip'],
                        'changes': mod,
                        'description': f"ARP {mod['ip']} modified"
                    })
            
            # Statistics
            differences["statistics"] = {
                'total_before': len(first_entries),
                'total_after': len(second_entries),
                'added_count': len(added_ips),
                'removed_count': len(removed_ips),
                'modified_count': len(modified_ips)
            }
            
            if added_ips or removed_ips or modified_ips:
                differences["status"] = "changed"
                differences["summary"] = f"ARP table changes: {len(added_ips)} added, {len(removed_ips)} removed, {len(modified_ips)} modified"
                
                # Compile details
                differences["details"] = []
                differences["details"].extend([item['description'] for item in differences["added"]])
                differences["details"].extend([item['description'] for item in differences["removed"]])
                differences["details"].extend([item['description'] for item in differences["modified"]])
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing ARP tables: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

    def _compare_interfaces_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced interface status comparison."""
        differences = {
            "status": "no_changes",
            "summary": "",
            "details": [],
            "added": [],
            "removed": [],
            "modified": [],
            "statistics": {}
        }
        
        try:
            first_cmd = first_data.get('show interfaces status', {})
            second_cmd = second_data.get('show interfaces status', {})
            
            if not first_cmd or not second_cmd:
                differences["status"] = "error"
                differences["summary"] = "Interface status data missing"
                return differences
            
            first_intfs = first_cmd.get('interfaceStatuses', {})
            second_intfs = second_cmd.get('interfaceStatuses', {})
            
            all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
            added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
            
            status_changes = []
            
            for intf_name in all_interfaces:
                first_status = first_intfs.get(intf_name, {}).get('linkStatus')
                second_status = second_intfs.get(intf_name, {}).get('linkStatus')
                
                if intf_name in added_interfaces:
                    differences["added"].append({
                        'type': 'interface',
                        'interface': intf_name,
                        'status': second_status,
                        'description': f"Interface {intf_name} added with status {second_status}"
                    })
                elif intf_name in removed_interfaces:
                    differences["removed"].append({
                        'type': 'interface',
                        'interface': intf_name,
                        'status': first_status,
                        'description': f"Interface {intf_name} removed (was {first_status})"
                    })
                elif first_status != second_status:
                    differences["modified"].append({
                        'type': 'interface',
                        'interface': intf_name,
                        'before': first_status,
                        'after': second_status,
                        'description': f"Interface {intf_name}: {first_status} -> {second_status}"
                    })
                    status_changes.append(f"Interface {intf_name}: {first_status} -> {second_status}")
            
            # Statistics
            differences["statistics"] = {
                'total_before': len(first_intfs),
                'total_after': len(second_intfs),
                'added_count': len(added_interfaces),
                'removed_count': len(removed_interfaces),
                'modified_count': len(status_changes)
            }
            
            if added_interfaces or removed_interfaces or status_changes:
                differences["status"] = "changed"
                differences["summary"] = f"Interface changes: {len(added_interfaces)} added, {len(removed_interfaces)} removed, {len(status_changes)} status changes"
                
                # Compile details
                differences["details"] = []
                differences["details"].extend([item['description'] for item in differences["added"]])
                differences["details"].extend([item['description'] for item in differences["removed"]])
                differences["details"].extend([item['description'] for item in differences["modified"]])
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing interfaces: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

    def _compare_mlag_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced MLAG interfaces comparison."""
        differences = {
            "status": "no_changes",
            "summary": "",
            "details": [],
            "added": [],
            "removed": [],
            "modified": [],
            "statistics": {}
        }
        
        try:
            first_cmd = first_data.get('show mlag interfaces detail', {})
            second_cmd = second_data.get('show mlag interfaces detail', {})
            
            if not first_cmd or not second_cmd:
                differences["status"] = "error"
                differences["summary"] = "MLAG interface data missing"
                return differences
            
            first_intfs = first_cmd.get('interfaces', {})
            second_intfs = second_cmd.get('interfaces', {})
            
            all_mlags = set(first_intfs.keys()) | set(second_intfs.keys())
            added_mlags = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_mlags = set(first_intfs.keys()) - set(second_intfs.keys())
            
            mlag_changes = []
            
            for mlag_id in all_mlags:
                first_status = first_intfs.get(mlag_id, {}).get('status')
                second_status = second_intfs.get(mlag_id, {}).get('status')
                
                if mlag_id in added_mlags:
                    differences["added"].append({
                        'type': 'mlag_interface',
                        'mlag_id': mlag_id,
                        'status': second_status,
                        'description': f"MLAG {mlag_id} added with status {second_status}"
                    })
                elif mlag_id in removed_mlags:
                    differences["removed"].append({
                        'type': 'mlag_interface',
                        'mlag_id': mlag_id,
                        'status': first_status,
                        'description': f"MLAG {mlag_id} removed (was {first_status})"
                    })
                elif first_status != second_status:
                    differences["modified"].append({
                        'type': 'mlag_interface',
                        'mlag_id': mlag_id,
                        'before': first_status,
                        'after': second_status,
                        'description': f"MLAG {mlag_id}: {first_status} -> {second_status}"
                    })
                    mlag_changes.append(f"MLAG {mlag_id}: {first_status} -> {second_status}")
            
            # Statistics
            differences["statistics"] = {
                'total_before': len(first_intfs),
                'total_after': len(second_intfs),
                'added_count': len(added_mlags),
                'removed_count': len(removed_mlags),
                'modified_count': len(mlag_changes)
            }
            
            if added_mlags or removed_mlags or mlag_changes:
                differences["status"] = "changed"
                differences["summary"] = f"MLAG changes: {len(added_mlags)} added, {len(removed_mlags)} removed, {len(mlag_changes)} status changes"
                
                # Compile details
                differences["details"] = []
                differences["details"].extend([item['description'] for item in differences["added"]])
                differences["details"].extend([item['description'] for item in differences["removed"]])
                differences["details"].extend([item['description'] for item in differences["modified"]])
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing MLAG: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

    def _generic_comparison(self, first_data: Dict, second_data: Dict, command_category: str) -> Dict:
        """Generic comparison for unknown command types."""
        differences = {
            "status": "no_changes",
            "summary": "",
            "details": [],
            "added": [],
            "removed": [],
            "modified": [],
            "statistics": {}
        }
        
        try:
            if first_data != second_data:
                differences["status"] = "changed"
                differences["summary"] = f"{command_category} data has changed between snapshots"
                differences["details"] = ["Generic data comparison shows differences"]
                differences["modified"].append({
                    'type': 'generic_change',
                    'command': command_category,
                    'description': f"Changes detected in {command_category}"
                })
                differences["statistics"] = {
                    'comparison_type': 'generic',
                    'changed': True
                }
            else:
                differences["statistics"] = {
                    'comparison_type': 'generic',
                    'changed': False
                }
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error in generic comparison: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

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
            
            # Check optional columns
            for opt_col in optional_columns.keys():
                if column_mapping[opt_col]:
                    val = str(row[column_mapping[opt_col]]).strip()
                    if not val or val.lower() in ['nan', 'none', 'null', '']:
                        warnings.append(f"Row {row_num}: Missing {opt_col} - will use 'N/A'")
    
    return errors, warnings, column_mapping

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

def get_csv_separator(file_path: str):
    """Detects the separator of a CSV file by checking the header."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            header = f.readline()
            separators = {',': header.count(','), ';': header.count(';'), '\t': header.count('\t'), '|': header.count('|')}
            separator = max(separators.items(), key=lambda x: x[1])[0]
            logger.info(f"Detected CSV separator: '{separator}'")
            return separator
    except Exception as e:
        logger.warning(f"Could not detect separator for {file_path}, defaulting to comma. Error: {e}")
        return ','

def process_single_device_with_retry(device_info: DeviceInfo, metadata: DeviceMetadata, session: ProcessingSession, device_manager: NetworkDeviceAPIManager, selected_commands: List[str] = None):
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
                    time.sleep(2)
                    continue
                else:
                    return ProcessingResult(
                        ip_mgmt=metadata.ip_mgmt,
                        nama_sw=metadata.nama_sw,
                        sn=metadata.sn,
                        model_sw=metadata.model_sw,
                        status="Failed",
                        error=error,
                        processing_time=processing_time,
                        retry_count=retry_count,
                        last_attempt=datetime.now().isoformat(),
                        connection_status=DEVICE_STATUS["FAILED"],
                        detected_device_type=detected_type,
                        api_endpoint=api_endpoint,
                        api_status="Failed",
                        api_response_time=api_response_time
                    )
                    
        except Exception as e:
            retry_count += 1
            if retry_count >= max_retries:
                processing_time = (datetime.now() - start_time).total_seconds()
                return ProcessingResult(
                    ip_mgmt=metadata.ip_mgmt,
                    nama_sw=metadata.nama_sw,
                    sn=metadata.sn,
                    model_sw=metadata.model_sw,
                    status="Failed",
                    error=f"Unexpected error: {str(e)}",
                    processing_time=processing_time,
                    retry_count=retry_count,
                    last_attempt=datetime.now().isoformat(),
                    connection_status=DEVICE_STATUS["FAILED"],
                    api_status="Error"
                )
            else:
                logger.info(f"Retrying {device_info.host} due to exception (attempt {retry_count + 1}/{max_retries}): {str(e)}")
                time.sleep(2)
                continue

def threaded_process_devices(username: str, password: str, file_path: str, session_id: str, selected_commands: List[str] = None, retry_failed_only: bool = False):
    """Threaded processing with retry mechanism and progress tracking using APIs."""
    try:
        session = processing_sessions[session_id]
        session.start_time = datetime.now()
        
        logger.info(f"Starting API-based threaded processing for session {session_id}")
        
        if retry_failed_only:
            logger.info("Retrying failed devices only")
        
        separator = get_csv_separator(file_path)
        df = pd.read_csv(file_path, sep=separator)
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
                if column_mapping[column_name]:
                    val = str(row[column_mapping[column_name]]).strip()
                    return val if val and val.lower() not in ['nan', 'none', 'null', ''] else default
                return default
            
            metadata = DeviceMetadata(
                ip_mgmt=str(row[column_mapping['IP MGMT']]).strip(),
                nama_sw=get_optional_value('Nama SW'),
                sn=get_optional_value('SN'),
                model_sw=get_optional_value('Model SW')
            )
            
            result = process_single_device_with_retry(device_info, metadata, session, device_manager, selected_commands)
            results.append(result)
            
            session.completed += 1
            if result.status == "Success":
                session.successful += 1
            else:
                session.failed += 1
            
            logger.info(f"API Progress: {session.completed}/{session.total_devices} - {metadata.ip_mgmt}: {result.status}")
        
        session.end_time = datetime.now()
        output_filename = data_processor.save_results(results, session_id, selected_commands)
        session.output_file = output_filename
        
        response = {
            "status": "success" if not session.is_stopped else "stopped",
            "message": f"API processing complete: {session.successful} successful, {session.failed} failed. Results saved to {Path(output_filename).name}",
            "data": [asdict(result) for result in results],
            "session_id": session_id,
            "output_file": Path(output_filename).name,
            "summary": {
                "total": session.total_devices,
                "successful": session.successful,
                "failed": session.failed,
                "completed": session.completed,
                "duration": (session.end_time - session.start_time).total_seconds() if session.end_time else 0,
                "connection_method": "Vendor APIs"
            }
        }
        
        processing_sessions[session_id] = session
        processing_sessions[f"{session_id}_results"] = response
        
        logger.info(f"API processing completed for session {session_id}: {len(results)} devices processed")
        
    except Exception as e:
        logger.error(f"Error in API threaded processing: {e}", exc_info=True)
        session.end_time = datetime.now()
        response = {
            "status": "error",
            "message": f"API processing failed: {str(e)}",
            "session_id": session_id
        }
        processing_sessions[f"{session_id}_results"] = response

def threaded_retry_failed_devices(username: str, password: str, failed_devices: List[Dict], session_id: str):
    """Retry processing for failed devices only."""
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
        
        response = {
            "status": "success" if not session.is_stopped else "stopped",
            "message": f"Retry complete: {session.successful} successful, {session.failed} failed",
            "data": [asdict(result) for result in results],
            "session_id": session_id,
            "output_file": Path(output_filename).name
        }
        
        processing_sessions[f"{session_id}_results"] = response
        
    except Exception as e:
        logger.error(f"Error in retry processing: {e}")
        response = {
            "status": "error",
            "message": f"Retry processing failed: {str(e)}",
            "session_id": session_id
        }
        processing_sessions[f"{session_id}_results"] = response

# Helper Functions
def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['csv']

# Create Flask app with proper configuration for packaging
if getattr(sys, 'frozen', False):
    # If running as PyInstaller bundle
    template_folder = os.path.join(sys._MEIPASS, '../frontend/dist')
    static_folder = os.path.join(sys._MEIPASS, '../frontend/dist')
    app = Flask(__name__, static_folder=static_folder, template_folder=template_folder)
else:
    # If running in development
    app = Flask(__name__, static_folder='../frontend/dist', static_url_path='')

CORS(app, origins=["http://localhost:5173", "http://127.0.0.1:5173"])

# Configure file upload
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global variables
config_manager = ConfigManager()
device_manager = NetworkDeviceAPIManager(config_manager)
data_processor = DataProcessor()
processing_sessions = {}
current_session_id = None

# Flask API Routes

@app.route('/')
def serve_react_app():
    """Serve the React application."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_react_routes(path):
    """Serve React routes - catch all for React Router."""
    if path.startswith('api/'):
        return jsonify({"error": "API endpoint not found"}), 404
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/system_info', methods=['GET'])
def get_system_info():
    """Get system information with dynamic API endpoint details."""
    try:
        supported_devices = config_manager.get_supported_device_types()
        
        api_info = {}
        for device_type in supported_devices:
            if device_type in API_ENDPOINTS:
                endpoint_config = API_ENDPOINTS[device_type]
                api_info[device_type] = {
                    "endpoint": endpoint_config["endpoint"],
                    "protocol": endpoint_config["default_protocol"],
                    "api_type": endpoint_config["api_type"],
                    "content_type": endpoint_config["content_type"]
                }
        
        return jsonify({
            "status": "success",
            "data": {
                "supported_devices": supported_devices,
                "api_endpoints": api_info,
                "comparison_commands": config_manager.get_comparison_commands(),
                "max_workers": MAX_WORKERS,
                "default_timeout": DEFAULT_TIMEOUT,
                "default_retry_attempts": DEFAULT_RETRY_ATTEMPTS,
                "output_directory": str(data_processor.output_dir),
                "version": "2.2.0-DEV",
                "connection_method": "Vendor APIs",
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get system info: {str(e)}"
        }), 500

@app.route('/api/comparison_commands', methods=['GET'])
def get_comparison_commands():
    """Get available comparison commands dynamically."""
    try:
        return jsonify({
            "status": "success",
            "data": config_manager.get_comparison_commands()
        })
    except Exception as e:
        logger.error(f"Error getting comparison commands: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get comparison commands: {str(e)}"
        }), 500

@app.route('/api/logs/stream')
def stream_logs():
    """Stream logs using Server-Sent Events."""
    def event_stream():
        while True:
            try:
                # Get log from queue with timeout
                log_entry = log_queue.get(timeout=30)
                yield f"data: {json.dumps(log_entry)}\n\n"
            except queue.Empty:
                # Send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now().isoformat()})}\n\n"
            except Exception as e:
                logger.error(f"Error in log stream: {e}")
                break
    
    return Response(event_stream(), mimetype="text/plain")

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear all logs from memory."""
    try:
        streaming_handler.clear_logs()
        logger.info("System logs cleared by user")
        return jsonify({
            "status": "success",
            "message": "Logs cleared successfully"
        })
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error clearing logs: {str(e)}"
        }), 500

@app.route('/api/output_files/<filename>', methods=['DELETE'])
def delete_output_file(filename):
    """Delete a specific output file."""
    try:
        filepath = os.path.join(data_processor.output_dir, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            os.remove(filepath)
            logger.info(f"Output file deleted: {filename}")
            return jsonify({
                "status": "success",
                "message": f"File {filename} deleted successfully"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "File not found"
            }), 404
    except Exception as e:
        logger.error(f"Error deleting file {filename}: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error deleting file: {str(e)}"
        }), 500

@app.route('/api/upload_csv', methods=['POST'])
def upload_csv():
    """Handle CSV file upload for web interface."""
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "No file selected"}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            try:
                separator = get_csv_separator(filepath)
                df = pd.read_csv(filepath, sep=separator)
                df.columns = [col.strip() for col in df.columns]
                
                errors, warnings, column_mapping = validate_csv_columns(df)
                
                if errors:
                    os.remove(filepath)
                    error_message = "CSV validation failed:\n" + "\n".join(errors)
                    if warnings:
                        error_message += f"\n\nWarnings: {len(warnings)} issues found"
                    return jsonify({
                        "status": "error",
                        "message": error_message,
                        "errors": errors,
                        "warnings": warnings[:10]
                    }), 400
                
                device_count = len(df)
                
                return jsonify({
                    "status": "success",
                    "message": f"File uploaded successfully. {device_count} devices found.",
                    "filepath": filepath,
                    "device_count": device_count,
                    "warnings": warnings[:10] if warnings else []
                })
                
            except Exception as e:
                if os.path.exists(filepath):
                    os.remove(filepath)
                return jsonify({
                    "status": "error",
                    "message": f"Error reading CSV: {str(e)}"
                }), 400
        
        return jsonify({"status": "error", "message": "Invalid file type. Only CSV files are allowed."}), 400
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/process_devices', methods=['POST'])
def process_devices_from_file():
    """Start device processing with uploaded file."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        filepath = data.get('filepath', '')
        selected_commands = data.get('selected_commands', [])
        retry_failed_only = data.get('retry_failed_only', False)
        
        if not username or not password:
            return jsonify({
                "status": "error",
                "message": "Username and password are required for API authentication"
            }), 400
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({
                "status": "error",
                "message": "No valid file found. Please upload a CSV file first."
            }), 400
        
        try:
            separator = get_csv_separator(filepath)
            full_df = pd.read_csv(filepath, sep=separator)
            device_count = len(full_df)
            
            if device_count == 0:
                return jsonify({"status": "error", "message": "The CSV file is empty."}), 400
                
        except Exception as e:
            logger.error(f"Error reading CSV file: {e}")
            return jsonify({
                "status": "error",
                "message": f"Error reading CSV file: {str(e)}"
            }), 400
        
        session_id = str(uuid.uuid4())
        session = ProcessingSession(
            session_id=session_id,
            total_devices=device_count
        )
        
        processing_sessions[session_id] = session
        global current_session_id
        current_session_id = session_id
        
        thread = threading.Thread(
            target=threaded_process_devices,
            args=(username, password, filepath, session_id, selected_commands, retry_failed_only)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "status": "loading",
            "message": f"API processing started for {device_count} devices with selected commands: {selected_commands}",
            "session_id": session_id,
            "total_devices": device_count,
            "selected_commands": selected_commands
        })
        
    except Exception as e:
        logger.error(f"Error starting API process: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error starting API process: {str(e)}"
        }), 500

@app.route('/api/processing_status/<session_id>', methods=['GET'])
def get_processing_status(session_id):
    """Get real-time processing status with progress."""
    try:
        if f"{session_id}_results" in processing_sessions:
            results = processing_sessions[f"{session_id}_results"]
            if session_id in processing_sessions:
                del processing_sessions[session_id]
            del processing_sessions[f"{session_id}_results"]
            return jsonify(results)
        
        if session_id in processing_sessions:
            session = processing_sessions[session_id]
            progress_percentage = (session.completed / session.total_devices * 100) if session.total_devices > 0 else 0
            
            return jsonify({
                "status": "processing",
                "message": f"Processing... {session.completed}/{session.total_devices} devices completed",
                "progress": {
                    "total": session.total_devices,
                    "completed": session.completed,
                    "successful": session.successful,
                    "failed": session.failed,
                    "percentage": round(progress_percentage, 1)
                },
                "session_id": session_id
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Session not found"
            }), 404
            
    except Exception as e:
        logger.error(f"Error getting processing status: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error getting status: {str(e)}"
        }), 500

@app.route('/api/compare_files', methods=['POST'])
def compare_files():
    """Compare two files across all available commands."""
    try:
        data = request.get_json()
        first_file = data.get('first_file')
        second_file = data.get('second_file')
        export_excel = data.get('export_excel', False)
        
        if not all([first_file, second_file]):
            return jsonify({
                "status": "error",
                "message": "Missing required parameters: first_file, second_file"
            }), 400
        
        # Get full file paths
        first_file_path = os.path.join(data_processor.output_dir, first_file)
        second_file_path = os.path.join(data_processor.output_dir, second_file)
        
        if not os.path.exists(first_file_path) or not os.path.exists(second_file_path):
            return jsonify({
                "status": "error",
                "message": "One or both files not found"
            }), 404
        
        # Load both files
        first_data = data_processor.load_results(first_file_path)
        second_data = data_processor.load_results(second_file_path)
        
        # Handle both old and new format with metadata
        if 'results' in first_data:
            first_data = first_data['results']
        if 'results' in second_data:
            second_data = second_data['results']
        
        # Get available commands for comparison
        available_commands = list(config_manager.get_comparison_commands().keys())
        
        # Create device mapping
        first_devices = {item["ip_mgmt"]: item for item in first_data}
        second_devices = {item["ip_mgmt"]: item for item in second_data}
        
        comparison_results = []
        
        # Compare devices that exist in both files
        for ip, first_device in first_devices.items():
            if ip in second_devices:
                second_device = second_devices[ip]
                
                device_result = {
                    "ip_mgmt": ip,
                    "hostname": first_device.get("nama_sw", "Unknown"),
                    "overall_status": "no_changes",
                    "command_results": {}
                }
                
                has_changes = False
                
                # Compare each available command
                for command_category in available_commands:
                    first_cmd_data = first_device.get("data", {}).get(command_category, {})
                    second_cmd_data = second_device.get("data", {}).get(command_category, {})
                    
                    # Compare the data for this command
                    compare_result = data_processor._compare_command_data(
                        first_cmd_data, second_cmd_data, command_category
                    )
                    
                    device_result["command_results"][command_category] = compare_result
                    
                    if compare_result["status"] != "no_changes":
                        has_changes = True
                
                device_result["overall_status"] = "changed" if has_changes else "no_changes"
                comparison_results.append(device_result)
        
        # Export to Excel with enhanced format
        excel_filename = None
        if export_excel and comparison_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            excel_filename = f"comparison_{timestamp}.xlsx"
            excel_path = os.path.join(data_processor.output_dir, excel_filename)
            
            data_processor.export_to_excel_comparison(comparison_results, excel_path)
        
        return jsonify({
            "status": "success",
            "data": comparison_results,
            "first_file": first_file,
            "second_file": second_file,
            "total_compared": len(comparison_results),
            "available_commands": available_commands,
            "excel_file": excel_filename
        })
        
    except Exception as e:
        logger.error(f"Error comparing files: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error comparing files: {str(e)}"
        }), 500

@app.route('/api/output_files', methods=['GET'])
def list_output_files():
    """List all output files."""
    try:
        files = []
        for file_path in data_processor.output_dir.glob("*.json"):
            stat = file_path.stat()
            files.append({
                "filename": file_path.name,
                "filepath": str(file_path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
        
        # Also include Excel files
        for file_path in data_processor.output_dir.glob("*.xlsx"):
            stat = file_path.stat()
            files.append({
                "filename": file_path.name,
                "filepath": str(file_path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
        
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        return jsonify({
            "status": "success",
            "data": files,
            "total": len(files)
        })
    except Exception as e:
        logger.error(f"Error listing output files: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error listing files: {str(e)}"
        }), 500

@app.route('/api/output_files/<filename>', methods=['GET'])
def download_output_file(filename):
    """Download a specific output file."""
    try:
        filepath = os.path.join(data_processor.output_dir, filename)
        if os.path.exists(filepath) and os.path.isfile(filepath):
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' if filename.endswith('.xlsx') else 'application/json'
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype=mimetype
            )
        else:
            return jsonify({
                "status": "error",
                "message": "File not found"
            }), 404
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error downloading file: {str(e)}"
        }), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get recent logs from memory."""
    try:
        logs = streaming_handler.get_logs()
        return jsonify({
            "status": "success",
            "data": logs,
            "total": len(logs)
        })
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error getting logs: {str(e)}"
        }), 500

@app.route('/api/stop_processing/<session_id>', methods=['POST'])
def stop_processing(session_id):
    """Stop processing for a specific session."""
    try:
        if session_id in processing_sessions:
            session = processing_sessions[session_id]
            session.is_stopped = True
            logger.info(f"API processing stopped for session {session_id}")
            
            return jsonify({
                "status": "success",
                "message": "API processing stop requested"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Session not found"
            }), 404
            
    except Exception as e:
        logger.error(f"Error stopping API processing: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error stopping API processing: {str(e)}"
        }), 500

@app.route('/api/generate_comparison_chart', methods=['POST'])
def generate_comparison_chart():
    """Generate chart data specifically for comparison results."""
    try:
        data = request.get_json()
        comparison_data = data.get('comparison_data', [])
        chart_type = data.get('chart_type', 'summary')
        
        if not comparison_data:
            return jsonify({
                "status": "error",
                "message": "No comparison data provided"
            }), 400
        
        chart_result = generate_comparison_chart_data(comparison_data, chart_type)
        
        if chart_result is None:
            return jsonify({
                "status": "error", 
                "message": "Failed to generate chart data"
            }), 500
        
        return jsonify({
            "status": "success",
            "data": chart_result
        })
        
    except Exception as e:
        logger.error(f"Error generating comparison chart: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error generating comparison chart: {str(e)}"
        }), 500

def generate_comparison_chart_data(comparison_data, chart_type='summary'):
    """Generate chart data for comparison results."""
    try:
        if chart_type == 'summary':
            return generate_comparison_summary_chart(comparison_data)
        elif chart_type == 'by_command':
            return generate_comparison_by_command_chart(comparison_data)
        elif chart_type == 'by_device':
            return generate_comparison_by_device_chart(comparison_data)
        else:
            return generate_comparison_summary_chart(comparison_data)
            
    except Exception as e:
        logger.error(f"Error in generate_comparison_chart_data: {e}")
        return None

def generate_comparison_summary_chart(comparison_data):
    """Generate summary chart showing overall comparison statistics."""
    try:
        # Count overall status
        status_counts = {'no_changes': 0, 'changed': 0, 'error': 0}
        device_count = len(comparison_data)
        
        for device in comparison_data:
            overall_status = device.get('overall_status', 'error')
            if overall_status in status_counts:
                status_counts[overall_status] += 1
            else:
                status_counts['error'] += 1
        
        # Create pie chart for overall status
        labels = []
        values = []
        colors = []
        
        color_map = {
            'no_changes': '#52c41a',  # Green
            'changed': '#faad14',     # Orange  
            'error': '#f5222d'        # Red
        }
        
        label_map = {
            'no_changes': 'No Changes',
            'changed': 'Changed',
            'error': 'Errors'
        }
        
        for status, count in status_counts.items():
            if count > 0:
                labels.append(f"{label_map[status]} ({count})")
                values.append(count)
                colors.append(color_map[status])
        
        # If no data, create a simple message
        if not values:
            labels = ['No Data']
            values = [1]
            colors = ['#cccccc']
        
        pie_chart = {
            'data': [{
                'values': values,
                'labels': labels,
                'type': 'pie',
                'marker': {'colors': colors},
                'textinfo': 'label+percent',
                'textposition': 'outside'
            }],
            'layout': {
                'title': {
                    'text': f'Comparison Summary - {device_count} Devices',
                    'x': 0.5,
                    'font': {'size': 16, 'family': 'Arial, sans-serif'}
                },
                'showlegend': True,
                'legend': {
                    'orientation': 'h',
                    'yanchor': 'bottom', 
                    'y': -0.2,
                    'xanchor': 'center',
                    'x': 0.5
                },
                'margin': {'t': 60, 'b': 80, 'l': 20, 'r': 20},
                'height': 400
            }
        }
        
        return pie_chart
        
    except Exception as e:
        logger.error(f"Error generating comparison summary chart: {e}")
        return None

def generate_comparison_by_command_chart(comparison_data):
    """Generate chart showing comparison results by command category."""
    try:
        command_stats = {}
        
        # Collect statistics for each command
        for device in comparison_data:
            command_results = device.get('command_results', {})
            for command, result in command_results.items():
                if command not in command_stats:
                    command_stats[command] = {'no_changes': 0, 'changed': 0, 'error': 0}
                
                status = result.get('status', 'error')
                if status in command_stats[command]:
                    command_stats[command][status] += 1
                else:
                    command_stats[command]['error'] += 1
        
        if not command_stats:
            # No command data available
            return {
                'data': [{
                    'x': ['No Data'],
                    'y': [1],
                    'type': 'bar',
                    'marker': {'color': '#cccccc'}
                }],
                'layout': {
                    'title': 'No Command Data Available',
                    'height': 400
                }
            }
        
        # Create stacked bar chart
        commands = list(command_stats.keys())
        no_changes = [command_stats[cmd]['no_changes'] for cmd in commands]
        changed = [command_stats[cmd]['changed'] for cmd in commands]
        errors = [command_stats[cmd]['error'] for cmd in commands]
        
        bar_chart = {
            'data': [
                {
                    'x': commands,
                    'y': no_changes,
                    'name': 'No Changes',
                    'type': 'bar',
                    'marker': {'color': '#52c41a'}
                },
                {
                    'x': commands,
                    'y': changed,
                    'name': 'Changed',
                    'type': 'bar',
                    'marker': {'color': '#faad14'}
                },
                {
                    'x': commands,
                    'y': errors,
                    'name': 'Errors',
                    'type': 'bar',
                    'marker': {'color': '#f5222d'}
                }
            ],
            'layout': {
                'title': {
                    'text': 'Comparison Results by Command',
                    'x': 0.5,
                    'font': {'size': 16}
                },
                'barmode': 'stack',
                'xaxis': {
                    'title': 'Commands',
                    'tickangle': -45
                },
                'yaxis': {
                    'title': 'Number of Devices'
                },
                'legend': {
                    'orientation': 'h',
                    'yanchor': 'bottom',
                    'y': 1.02,
                    'xanchor': 'center',
                    'x': 0.5
                },
                'margin': {'t': 80, 'b': 100, 'l': 60, 'r': 40},
                'height': 400
            }
        }
        
        return bar_chart
        
    except Exception as e:
        logger.error(f"Error generating command comparison chart: {e}")
        return None

def generate_comparison_by_device_chart(comparison_data):
    """Generate chart showing devices with changes."""
    try:
        # Get devices that have changes
        changed_devices = []
        unchanged_devices = []
        error_devices = []
        
        for device in comparison_data:
            device_name = f"{device.get('hostname', 'Unknown')} ({device.get('ip_mgmt', 'N/A')})"
            overall_status = device.get('overall_status', 'error')
            
            if overall_status == 'changed':
                # Count number of changed commands
                command_results = device.get('command_results', {})
                changed_count = sum(1 for result in command_results.values() 
                                  if result.get('status') == 'changed')
                changed_devices.append({'name': device_name, 'changes': changed_count})
            elif overall_status == 'no_changes':
                unchanged_devices.append(device_name)
            else:
                error_devices.append(device_name)
        
        # Create chart based on what data we have
        if changed_devices:
            changed_devices.sort(key=lambda x: x['changes'], reverse=True)
            device_names = [d['name'][:30] + '...' if len(d['name']) > 30 else d['name'] 
                           for d in changed_devices[:10]]  # Top 10, truncate long names
            change_counts = [d['changes'] for d in changed_devices[:10]]
            
            device_chart = {
                'data': [{
                    'x': change_counts,
                    'y': device_names,
                    'type': 'bar',
                    'orientation': 'h',
                    'marker': {'color': '#faad14'},
                    'text': change_counts,
                    'textposition': 'auto'
                }],
                'layout': {
                    'title': {
                        'text': f'Top Devices with Changes (Total: {len(changed_devices)})',
                        'x': 0.5,
                        'font': {'size': 16}
                    },
                    'xaxis': {
                        'title': 'Number of Changed Commands'
                    },
                    'yaxis': {
                        'title': 'Devices'
                    },
                    'margin': {'t': 60, 'b': 40, 'l': 200, 'r': 40},
                    'height': 400
                }
            }
        else:
            # No changes found, show distribution
            categories = []
            counts = []
            colors = []
            
            if unchanged_devices:
                categories.append('No Changes')
                counts.append(len(unchanged_devices))
                colors.append('#52c41a')
            
            if error_devices:
                categories.append('Errors')
                counts.append(len(error_devices))
                colors.append('#f5222d')
            
            if not categories:
                categories = ['No Data']
                counts = [1]
                colors = ['#cccccc']
            
            device_chart = {
                'data': [{
                    'x': counts,
                    'y': categories,
                    'type': 'bar',
                    'orientation': 'h',
                    'marker': {'color': colors}
                }],
                'layout': {
                    'title': {
                        'text': 'Device Status Distribution',
                        'x': 0.5,
                        'font': {'size': 16}
                    },
                    'xaxis': {'title': 'Number of Devices'},
                    'yaxis': {'title': 'Status'},
                    'margin': {'t': 60, 'b': 40, 'l': 100, 'r': 40},
                    'height': 400
                }
            }
        
        return device_chart
        
    except Exception as e:
        logger.error(f"Error generating device comparison chart: {e}")
        return None

@app.route('/api/retry_failed', methods=['POST'])
def retry_failed_devices():
    """Retry only failed devices from previous results."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        previous_results = data.get('results', [])
        
        if not username or not password:
            return jsonify({
                "status": "error",
                "message": "Username and password are required"
            }), 400
        
        # Filter only failed devices
        failed_devices = [r for r in previous_results if r.get('status') == 'Failed']
        
        if not failed_devices:
            return jsonify({
                "status": "info",
                "message": "No failed devices to retry"
            })
        
        # Create a session for retry
        session_id = str(uuid.uuid4())
        session = ProcessingSession(
            session_id=session_id,
            total_devices=len(failed_devices)
        )
        
        processing_sessions[session_id] = session
        
        # Start retry processing in background thread
        thread = threading.Thread(
            target=threaded_retry_failed_devices,
            args=(username, password, failed_devices, session_id)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "status": "loading",
            "message": f"Retrying {len(failed_devices)} failed devices",
            "session_id": session_id,
            "total_devices": len(failed_devices)
        })
        
    except Exception as e:
        logger.error(f"Error retrying failed devices: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error retrying devices: {str(e)}"
        }), 500

@app.route('/api/filter_results', methods=['POST'])
def filter_results():
    """Filter results based on criteria."""
    try:
        data = request.get_json()
        results = data.get('results', [])
        filter_type = data.get('filter_type', 'all')
        filter_value = data.get('filter_value', '')
        
        if filter_type == 'all' or not filter_value:
            return jsonify({
                "status": "success",
                "data": results
            })
        
        filtered = []
        for result in results:
            if filter_type == 'status' and result.get('status') == filter_value:
                filtered.append(result)
            elif filter_type == 'model_sw' and filter_value.lower() in result.get('model_sw', '').lower():
                filtered.append(result)
            elif filter_type == 'connection_status' and result.get('connection_status') == filter_value:
                filtered.append(result)
        
        return jsonify({
            "status": "success",
            "data": filtered
        })
        
    except Exception as e:
        logger.error(f"Error filtering results: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error filtering results: {str(e)}"
        }), 500

@app.route('/api/compare_snapshots', methods=['POST'])
def compare_snapshots():
    """Compare specific command between two snapshots."""
    try:
        data = request.get_json()
        first_file = data.get('first_file')
        second_file = data.get('second_file')
        command_category = data.get('command_category')
        
        if not all([first_file, second_file, command_category]):
            return jsonify({
                "status": "error",
                "message": "Missing required parameters"
            }), 400
        
        # Load and compare specific command
        first_path = os.path.join(data_processor.output_dir, first_file)
        second_path = os.path.join(data_processor.output_dir, second_file)
        
        if not os.path.exists(first_path) or not os.path.exists(second_path):
            return jsonify({
                "status": "error", 
                "message": "One or both files not found"
            }), 404
        
        first_data = data_processor.load_results(first_path)
        second_data = data_processor.load_results(second_path)
        
        # Handle metadata wrapper
        if 'results' in first_data:
            first_data = first_data['results']
        if 'results' in second_data:
            second_data = second_data['results']
        
        # Perform comparison for specific command
        comparison_results = []
        first_devices = {item["ip_mgmt"]: item for item in first_data}
        second_devices = {item["ip_mgmt"]: item for item in second_data}
        
        for ip, first_device in first_devices.items():
            if ip in second_devices:
                second_device = second_devices[ip]
                
                first_cmd_data = first_device.get("data", {}).get(command_category, {})
                second_cmd_data = second_device.get("data", {}).get(command_category, {})
                
                compare_result = data_processor._compare_command_data(
                    first_cmd_data, second_cmd_data, command_category
                )
                
                comparison_results.append({
                    "ip_mgmt": ip,
                    "hostname": first_device.get("nama_sw", "Unknown"),
                    "compare_result": compare_result
                })
        
        # Export to Excel
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_filename = f"snapshot_comparison_{command_category}_{timestamp}.xlsx"
        excel_path = os.path.join(data_processor.output_dir, excel_filename)
        
        excel_data = []
        for result in comparison_results:
            excel_data.append({
                "IP": result["ip_mgmt"],
                "Hostname": result["hostname"],
                "Status": result["compare_result"]["status"],
                "Summary": result["compare_result"]["summary"],
                "Details": "; ".join(result["compare_result"]["details"]) if result["compare_result"]["details"] else ""
            })
        
        df = pd.DataFrame(excel_data)
        df.to_excel(excel_path, index=False, engine=EXCEL_ENGINE)
        
        return jsonify({
            "status": "success",
            "data": comparison_results,
            "total_compared": len(comparison_results),
            "excel_file": excel_filename
        })
        
    except Exception as e:
        logger.error(f"Error comparing snapshots: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error comparing snapshots: {str(e)}"
        }), 500

@app.route('/api/export_excel', methods=['POST'])
def export_excel():
    """Export results to Excel file with enhanced format."""
    try:
        data = request.get_json()
        results = data.get('data', [])
        export_type = data.get('export_type', 'detailed')
        
        if not results:
            return jsonify({
                "status": "error",
                "message": "No data to export"
            }), 400
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_data_export_{timestamp}.xlsx"
        filepath = os.path.join(data_processor.output_dir, filename)
        
        # Use enhanced export
        data_processor.export_to_excel_enhanced(results, filepath, export_type)
        
        # Return file for download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        logger.error(f"Error exporting to Excel: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error exporting to Excel: {str(e)}"
        }), 500

@app.route('/api/generate_chart', methods=['POST'])
def generate_chart():
    """Generate chart data for visualization."""
    try:
        data = request.get_json()
        results = data.get('data', [])
        filter_by = data.get('filter_by', 'model_sw')
        
        if not results:
            return jsonify({
                "status": "error",
                "message": "No data provided"
            }), 400
        
        # Count occurrences
        counts = {}
        for result in results:
            key = result.get(filter_by, 'Unknown')
            counts[key] = counts.get(key, 0) + 1
        
        # Create chart data
        chart_data = {
            "data": [{
                "x": list(counts.keys()),
                "y": list(counts.values()),
                "type": "bar",
                "marker": {"color": "#1f77b4"}
            }],
            "layout": {
                "title": f"Device Distribution by {filter_by.replace('_', ' ').title()}",
                "xaxis": {"title": filter_by.replace('_', ' ').title()},
                "yaxis": {"title": "Count"},
                "height": 400
            }
        }
        
        return jsonify({
            "status": "success",
            "data": chart_data
        })
        
    except Exception as e:
        logger.error(f"Error generating chart: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error generating chart: {str(e)}"
        }), 500

@app.route('/api/progress_chart/<session_id>', methods=['GET'])
def get_progress_chart(session_id):
    """Get progress chart for active session."""
    try:
        if session_id not in processing_sessions:
            return jsonify({
                "status": "error",
                "message": "Session not found"
            }), 404
        
        session = processing_sessions[session_id]
        
        chart_data = {
            "data": [{
                "values": [session.successful, session.failed, session.total_devices - session.completed],
                "labels": ["Successful", "Failed", "Pending"],
                "type": "pie",
                "marker": {
                    "colors": ["#52c41a", "#f5222d", "#faad14"]
                }
            }],
            "layout": {
                "title": "Processing Progress",
                "height": 300
            }
        }
        
        return jsonify({
            "status": "success",
            "data": chart_data
        })
        
    except Exception as e:
        logger.error(f"Error generating progress chart: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error generating progress chart: {str(e)}"
        }), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.2.0-DEV",
        "connection_method": "APIs",
        "supported_apis": list(API_ENDPOINTS.keys()),
        "output_directory": str(data_processor.output_dir),
        "ssl_bypass": "Enabled",
        "jsonrpclib_version": "SSL bypass",
        "log_file": log_filename,
        "dynamic_commands": "Enabled"
    })

if __name__ == '__main__':
    # Start log streaming automatically
    logger.info("Starting Network Data App Production Server")
    logger.info(f"Log file: {log_filename}")
    logger.info(f"Output directory: {DEFAULT_OUTPUT_DIR}")
    logger.info(f"Upload directory: {UPLOAD_FOLDER}")
    logger.info(f"Supported API endpoints: {list(API_ENDPOINTS.keys())}")
    logger.info(f"Available comparison commands: {list(config_manager.get_comparison_commands().keys())}")
    logger.info("SSL bypass enabled for all API connections")
    logger.info("Error handling and retry mechanisms activated")
    logger.info("Dynamic command detection enabled")
    logger.info("Enhanced comparison and Excel export enabled")
    
    # Production server configuration
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        threaded=True
    )