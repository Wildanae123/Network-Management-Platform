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
import ssl
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
from jsonrpclib import ServerProxy

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
                logger.info(f"Selected commands received: {selected_commands}")
                logger.debug(f"Available command categories: {list(commands_by_category.keys())}")
                
                filtered_commands = {}
                for category_key in selected_commands:
                    # Handle both direct category names and prefixed category names
                    # e.g., "interfaces" or "arista_eos_interfaces"
                    category_name = category_key
                    if "_" in category_key:
                        # Extract category from format like "arista_eos_interfaces"
                        parts = category_key.split("_")
                        if len(parts) >= 3:  # device_vendor_category format
                            category_name = "_".join(parts[2:])  # Get everything after device_vendor
                        elif len(parts) == 2:  # vendor_category format
                            category_name = parts[1]
                    
                    logger.debug(f"Looking for category: '{category_name}' (from '{category_key}')")
                    
                    if category_name in commands_by_category:
                        filtered_commands[category_name] = commands_by_category[category_name]
                        logger.debug(f"Added category '{category_name}' with {len(commands_by_category[category_name])} commands")
                    else:
                        logger.warning(f"Category '{category_name}' not found in available categories: {list(commands_by_category.keys())}")
                
                if filtered_commands:
                    commands_by_category = filtered_commands
                    logger.info(f"Filtered to selected command categories: {list(filtered_commands.keys())}")
                else:
                    logger.warning(f"No valid categories found from selected commands: {selected_commands}")
                    logger.info("Using all available categories as fallback")
            else:
                logger.info("No command selection specified, using all available categories")
            
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
                    model_sw = result.get('model_sw', 'N/A') if isinstance(result, dict) else getattr(result, 'model_sw', 'N/A')
                    summary_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Model SW": model_sw,
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
                            "Model SW": model_sw,
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

                # Create comprehensive detailed analysis sheet combining detailed changes and interface specifics
                if detailed_data:
                    comprehensive_data = self._create_comprehensive_detailed_data(comparison_results, detailed_data)
                    if comprehensive_data:
                        df_comprehensive = pd.DataFrame(comprehensive_data)
                        df_comprehensive.to_excel(writer, sheet_name='Detailed Analysis', index=False)

                # Create individual sheets for non-interface command types
                command_types = set()
                for result in comparison_results:
                    command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
                    command_types.update(command_results.keys())

                for command_type in command_types:
                    if command_type == 'interfaces':
                        # Create dedicated interfaces sheet
                        self._create_interfaces_detailed_sheet(writer, comparison_results, command_type)
                    elif command_type == 'mac_address_table':
                        # Detailed MAC address table comparison
                        self._create_mac_table_detailed_sheet(writer, comparison_results, command_type)
                    elif command_type == 'ip_arp':
                        # Detailed ARP table comparison
                        self._create_arp_table_detailed_sheet(writer, comparison_results, command_type)
                    elif command_type == 'mlag_interfaces':
                        # Detailed MLAG interfaces comparison
                        self._create_mlag_interfaces_detailed_sheet(writer, comparison_results, command_type)
                    elif command_type == 'protocols':
                        # Detailed OSPF neighbor comparison
                        self._create_ospf_neighbor_detailed_sheet(writer, comparison_results, command_type)
                    elif command_type == 'mlag':
                        # Detailed MLAG config sanity comparison
                        self._create_mlag_config_detailed_sheet(writer, comparison_results, command_type)
                    else:
                        # Generic handling for other command types
                        self._create_generic_detailed_sheet(writer, comparison_results, command_type)

            logger.info(f"Enhanced comparison data exported to Excel: {filepath}")

        except Exception as e:
            logger.error(f"Error exporting comparison to Excel: {e}")
            raise

    def _create_interfaces_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed interfaces comparison sheet based on api_output.json structure."""
        interface_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            model_sw = result.get('model_sw', 'N/A') if isinstance(result, dict) else getattr(result, 'model_sw', 'N/A')
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process interface status data based on api_output.json structure
                for interface_name, interface_info in self._extract_interface_data_enhanced(cmd_result):
                    interface_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Model SW": model_sw,
                        "Interface": interface_name,
                        "Link Status First": interface_info.get('first', {}).get('linkStatus', 'N/A'),
                        "Link Status Second": interface_info.get('second', {}).get('linkStatus', 'N/A'),
                        "Description First": interface_info.get('first', {}).get('description', 'N/A'),
                        "Description Second": interface_info.get('second', {}).get('description', 'N/A'),
                        "Bandwidth First": interface_info.get('first', {}).get('bandwidth', 'N/A'),
                        "Bandwidth Second": interface_info.get('second', {}).get('bandwidth', 'N/A'),
                        "Duplex First": interface_info.get('first', {}).get('duplex', 'N/A'),
                        "Duplex Second": interface_info.get('second', {}).get('duplex', 'N/A'),
                        "Interface Type First": interface_info.get('first', {}).get('interfaceType', 'N/A'),
                        "Interface Type Second": interface_info.get('second', {}).get('interfaceType', 'N/A'),
                        "VLAN ID First": interface_info.get('first', {}).get('vlanInformation', {}).get('vlanId', 'N/A'),
                        "VLAN ID Second": interface_info.get('second', {}).get('vlanInformation', {}).get('vlanId', 'N/A'),
                        "Auto Negotiate First": interface_info.get('first', {}).get('autoNegotiateActive', 'N/A'),
                        "Auto Negotiate Second": interface_info.get('second', {}).get('autoNegotiateActive', 'N/A'),
                        "Line Protocol First": interface_info.get('first', {}).get('lineProtocolStatus', 'N/A'),
                        "Line Protocol Second": interface_info.get('second', {}).get('lineProtocolStatus', 'N/A'),
                        "MTU First": interface_info.get('first', {}).get('mtu', 'N/A'),
                        "MTU Second": interface_info.get('second', {}).get('mtu', 'N/A'),
                        "MAC Address First": interface_info.get('first', {}).get('physicalAddress', 'N/A'),
                        "MAC Address Second": interface_info.get('second', {}).get('physicalAddress', 'N/A'),
                        "In Octets First": interface_info.get('first', {}).get('interfaceCounters', {}).get('inOctets', 'N/A'),
                        "In Octets Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('inOctets', 'N/A'),
                        "Out Octets First": interface_info.get('first', {}).get('interfaceCounters', {}).get('outOctets', 'N/A'),
                        "Out Octets Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('outOctets', 'N/A'),
                        "In Packets First": interface_info.get('first', {}).get('interfaceCounters', {}).get('inTotalPkts', 'N/A'),
                        "In Packets Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('inTotalPkts', 'N/A'),
                        "Out Packets First": interface_info.get('first', {}).get('interfaceCounters', {}).get('outTotalPkts', 'N/A'),
                        "Out Packets Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('outTotalPkts', 'N/A'),
                        "In Errors First": interface_info.get('first', {}).get('interfaceCounters', {}).get('totalInErrors', 'N/A'),
                        "In Errors Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('totalInErrors', 'N/A'),
                        "Out Errors First": interface_info.get('first', {}).get('interfaceCounters', {}).get('totalOutErrors', 'N/A'),
                        "Out Errors Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('totalOutErrors', 'N/A'),
                        "Link Status Changes First": interface_info.get('first', {}).get('interfaceCounters', {}).get('linkStatusChanges', 'N/A'),
                        "Link Status Changes Second": interface_info.get('second', {}).get('interfaceCounters', {}).get('linkStatusChanges', 'N/A'),
                        "Change Status": interface_info.get('change_status', 'No Change')
                    })
        
        if interface_data:
            df_interfaces = pd.DataFrame(interface_data)
            df_interfaces.to_excel(writer, sheet_name='Interfaces Detail', index=False)

    def _extract_interface_data_enhanced(self, cmd_result):
        """Extract interface data for comparison with enhanced structure based on api_output.json."""
        interface_data = []
        
        # Get interface data from added, removed, and modified lists
        for added_intf in cmd_result.get('added', []):
            interface_data.append((added_intf.get('interface', 'Unknown'), {
                'first': {},
                'second': added_intf,
                'change_status': 'Added'
            }))
        
        for removed_intf in cmd_result.get('removed', []):
            interface_data.append((removed_intf.get('interface', 'Unknown'), {
                'first': removed_intf,
                'second': {},
                'change_status': 'Removed'
            }))
        
        for modified_intf in cmd_result.get('modified', []):
            interface_name = modified_intf.get('interface', 'Unknown')
            interface_data.append((interface_name, {
                'first': modified_intf.get('old_data', {}),
                'second': modified_intf.get('new_data', {}),
                'change_status': 'Modified'
            }))
        
        return interface_data

    def _extract_interface_data(self, cmd_result):
        """Extract interface data for comparison with proper change detection."""
        interface_data = []
        
        # Get interface data from added, removed, and modified lists
        for added_intf in cmd_result.get('added', []):
            interface_data.append((added_intf.get('interface', 'Unknown'), {
                'first': {},
                'second': added_intf,
                'change_status': 'Added'
            }))
        
        for removed_intf in cmd_result.get('removed', []):
            interface_data.append((removed_intf.get('interface', 'Unknown'), {
                'first': removed_intf,
                'second': {},
                'change_status': 'Removed'
            }))
        
        for modified_intf in cmd_result.get('modified', []):
            interface_data.append((modified_intf.get('interface', 'Unknown'), {
                'first': modified_intf.get('before', {}),
                'second': modified_intf.get('after', {}),
                'change_status': 'Modified'
            }))
        
        return interface_data

    def _create_mac_table_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed MAC address table comparison sheet."""
        mac_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            model_sw = result.get('model_sw', 'N/A') if isinstance(result, dict) else getattr(result, 'model_sw', 'N/A')
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process added MACs
                for mac_entry in cmd_result.get('added', []):
                    mac_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Model SW": model_sw,
                        "MAC Address": mac_entry.get('mac', 'N/A'),
                        "VLAN": mac_entry.get('vlan', 'N/A'),
                        "Interface": mac_entry.get('interface', 'N/A'),
                        "Type": mac_entry.get('type', 'N/A'),
                        "Status First": "Not Present",
                        "Status Second": "Present",
                        "Change Type": "Added"
                    })
                
                # Process removed MACs
                for mac_entry in cmd_result.get('removed', []):
                    mac_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Model SW": model_sw,
                        "MAC Address": mac_entry.get('mac', 'N/A'),
                        "VLAN": mac_entry.get('vlan', 'N/A'),
                        "Interface": mac_entry.get('interface', 'N/A'),
                        "Type": mac_entry.get('type', 'N/A'),
                        "Status First": "Present",
                        "Status Second": "Not Present",
                        "Change Type": "Removed"
                    })
                
                # Process modified MACs
                for mac_entry in cmd_result.get('modified', []):
                    changes = mac_entry.get('changes', {})
                    mac_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Model SW": model_sw,
                        "MAC Address": mac_entry.get('mac', 'N/A'),
                        "VLAN": changes.get('before', {}).get('vlanId', 'N/A'),
                        "Interface": changes.get('before', {}).get('interface', 'N/A'),
                        "Type": changes.get('before', {}).get('entryType', 'N/A'),
                        "Status First": "Present",
                        "Status Second": "Present (Modified)",
                        "Change Type": "Modified"
                    })
        
        if mac_data:
            df_mac = pd.DataFrame(mac_data)
            df_mac.to_excel(writer, sheet_name='MAC Table Detailed', index=False)

    def _create_arp_table_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed ARP table comparison sheet."""
        arp_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process added ARP entries
                for arp_entry in cmd_result.get('added', []):
                    arp_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "ARP IP": arp_entry.get('ip', 'N/A'),
                        "MAC Address": arp_entry.get('mac', 'N/A'),
                        "Interface": arp_entry.get('interface', 'N/A'),
                        "Age": arp_entry.get('age', 'N/A'),
                        "Status First": "Not Present",
                        "Status Second": "Present",
                        "Change Type": "Added"
                    })
                
                # Process removed ARP entries
                for arp_entry in cmd_result.get('removed', []):
                    arp_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "ARP IP": arp_entry.get('ip', 'N/A'),
                        "MAC Address": arp_entry.get('mac', 'N/A'),
                        "Interface": arp_entry.get('interface', 'N/A'),
                        "Age": arp_entry.get('age', 'N/A'),
                        "Status First": "Present",
                        "Status Second": "Not Present",
                        "Change Type": "Removed"
                    })
                
                # Process modified ARP entries
                for arp_entry in cmd_result.get('modified', []):
                    changes = arp_entry.get('changes', {})
                    arp_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "ARP IP": arp_entry.get('ip', 'N/A'),
                        "MAC Address": changes.get('before', {}).get('hwAddress', 'N/A'),
                        "Interface": changes.get('before', {}).get('interface', 'N/A'),
                        "Age": changes.get('before', {}).get('age', 'N/A'),
                        "Status First": "Present",
                        "Status Second": "Present (Modified)",
                        "Change Type": "Modified"
                    })
        
        if arp_data:
            df_arp = pd.DataFrame(arp_data)
            df_arp.to_excel(writer, sheet_name='ARP Table Detailed', index=False)

    def _create_mlag_interfaces_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed MLAG interfaces comparison sheet."""
        mlag_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process added MLAG interfaces
                for mlag_entry in cmd_result.get('added', []):
                    mlag_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "MLAG ID": mlag_entry.get('mlag_id', 'N/A'),
                        "Status First": "Not Present",
                        "Status Second": mlag_entry.get('status', 'N/A'),
                        "Local Interface": mlag_entry.get('local_interface', 'N/A'),
                        "Peer Interface": mlag_entry.get('peer_interface', 'N/A'),
                        "State": mlag_entry.get('state', 'N/A'),
                        "Change Type": "Added"
                    })
                
                # Process removed MLAG interfaces
                for mlag_entry in cmd_result.get('removed', []):
                    mlag_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "MLAG ID": mlag_entry.get('mlag_id', 'N/A'),
                        "Status First": mlag_entry.get('status', 'N/A'),
                        "Status Second": "Not Present",
                        "Local Interface": mlag_entry.get('local_interface', 'N/A'),
                        "Peer Interface": mlag_entry.get('peer_interface', 'N/A'),
                        "State": mlag_entry.get('state', 'N/A'),
                        "Change Type": "Removed"
                    })
                
                # Process modified MLAG interfaces
                for mlag_entry in cmd_result.get('modified', []):
                    mlag_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "MLAG ID": mlag_entry.get('mlag_id', 'N/A'),
                        "Status First": mlag_entry.get('before', 'N/A'),
                        "Status Second": mlag_entry.get('after', 'N/A'),
                        "Local Interface": mlag_entry.get('local_interface', 'N/A'),
                        "Peer Interface": mlag_entry.get('peer_interface', 'N/A'),
                        "State": mlag_entry.get('state', 'N/A'),
                        "Change Type": "Modified"
                    })
        
        if mlag_data:
            df_mlag = pd.DataFrame(mlag_data)
            df_mlag.to_excel(writer, sheet_name='MLAG Interfaces Detailed', index=False)

    def _create_ospf_neighbor_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed OSPF neighbor comparison sheet."""
        ospf_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process added OSPF neighbors
                for ospf_entry in cmd_result.get('added', []):
                    ospf_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Neighbor ID": ospf_entry.get('neighbor_id', 'N/A'),
                        "Neighbor IP": ospf_entry.get('neighbor_ip', 'N/A'),
                        "Interface": ospf_entry.get('interface', 'N/A'),
                        "State First": "Not Present",
                        "State Second": ospf_entry.get('state', 'N/A'),
                        "Priority": ospf_entry.get('priority', 'N/A'),
                        "Dead Time": ospf_entry.get('dead_time', 'N/A'),
                        "Area": ospf_entry.get('area', 'N/A'),
                        "Change Type": "Added"
                    })
                
                # Process removed OSPF neighbors
                for ospf_entry in cmd_result.get('removed', []):
                    ospf_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Neighbor ID": ospf_entry.get('neighbor_id', 'N/A'),
                        "Neighbor IP": ospf_entry.get('neighbor_ip', 'N/A'),
                        "Interface": ospf_entry.get('interface', 'N/A'),
                        "State First": ospf_entry.get('state', 'N/A'),
                        "State Second": "Not Present",
                        "Priority": ospf_entry.get('priority', 'N/A'),
                        "Dead Time": ospf_entry.get('dead_time', 'N/A'),
                        "Area": ospf_entry.get('area', 'N/A'),
                        "Change Type": "Removed"
                    })
                
                # Process modified OSPF neighbors
                for ospf_entry in cmd_result.get('modified', []):
                    ospf_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Neighbor ID": ospf_entry.get('neighbor_id', 'N/A'),
                        "Neighbor IP": ospf_entry.get('neighbor_ip', 'N/A'),
                        "Interface": ospf_entry.get('interface', 'N/A'),
                        "State First": ospf_entry.get('before', 'N/A'),
                        "State Second": ospf_entry.get('after', 'N/A'),
                        "Priority": ospf_entry.get('priority', 'N/A'),
                        "Dead Time": ospf_entry.get('dead_time', 'N/A'),
                        "Area": ospf_entry.get('area', 'N/A'),
                        "Change Type": "Modified"
                    })
        
        if ospf_data:
            df_ospf = pd.DataFrame(ospf_data)
            df_ospf.to_excel(writer, sheet_name='OSPF Neighbors Detailed', index=False)

    def _create_mlag_config_detailed_sheet(self, writer, comparison_results, command_type):
        """Create detailed MLAG config sanity comparison sheet."""
        mlag_config_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process configuration changes
                for config_entry in cmd_result.get('added', []) + cmd_result.get('removed', []) + cmd_result.get('modified', []):
                    change_type = "Added" if config_entry in cmd_result.get('added', []) else "Removed" if config_entry in cmd_result.get('removed', []) else "Modified"
                    
                    mlag_config_data.append({
                        "IP Address": ip_mgmt,
                        "Hostname": hostname,
                        "Configuration Item": config_entry.get('config_item', 'N/A'),
                        "Category": config_entry.get('category', 'N/A'),
                        "Value First": config_entry.get('before', 'N/A'),
                        "Value Second": config_entry.get('after', 'N/A'),
                        "Severity": config_entry.get('severity', 'N/A'),
                        "Recommendation": config_entry.get('recommendation', 'N/A'),
                        "Change Type": change_type
                    })
        
        if mlag_config_data:
            df_mlag_config = pd.DataFrame(mlag_config_data)
            df_mlag_config.to_excel(writer, sheet_name='MLAG Config Detailed', index=False)

    def _create_generic_detailed_sheet(self, writer, comparison_results, command_type):
        """Create generic detailed comparison sheet for other command types."""
        generic_data = []
        
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            if command_type in command_results:
                cmd_result = command_results[command_type]
                
                # Process all changes generically
                for change_type in ['added', 'removed', 'modified']:
                    changes = cmd_result.get(change_type, [])
                    for change in changes:
                        generic_data.append({
                            "IP Address": ip_mgmt,
                            "Hostname": hostname,
                            "Change Type": change_type.title(),
                            "Description": change.get('description', str(change)),
                            "Details": str(change)
                        })
        
        if generic_data:
            df_generic = pd.DataFrame(generic_data)
            sheet_name = command_type.replace('_', ' ').title()[:31]
            df_generic.to_excel(writer, sheet_name=sheet_name, index=False)

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
            elif command_category == "protocols":
                differences = self._compare_arp_table_enhanced(first_data, second_data)
            elif command_category == "interfaces_status" or command_category == "interfaces":
                differences = self._compare_interfaces_enhanced(first_data, second_data)
            elif command_category == "mlag":
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

    def _compare_mlag_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced MLAG comparison covering all MLAG commands."""
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
            # Check all MLAG-related commands
            mlag_commands = [
                'show mlag',
                'show mlag config-sanity',
                'show mlag interfaces detail',
                'show mlag detail'
            ]
            
            changes_found = False
            total_changes = 0
            
            # Compare each MLAG command
            for cmd in mlag_commands:
                first_cmd = first_data.get(cmd, {})
                second_cmd = second_data.get(cmd, {})
                
                if not first_cmd and not second_cmd:
                    continue  # Skip if both are missing
                
                if not first_cmd or not second_cmd:
                    differences["details"].append(f"Command '{cmd}' missing in one file")
                    changes_found = True
                    continue
                
                # Compare MLAG command data
                cmd_result = self._compare_mlag_command(first_cmd, second_cmd, cmd)
                if cmd_result["changes_count"] > 0:
                    changes_found = True
                    total_changes += cmd_result["changes_count"]
                    
                    # Merge results
                    differences["added"].extend(cmd_result["added"])
                    differences["removed"].extend(cmd_result["removed"])
                    differences["modified"].extend(cmd_result["modified"])
                    differences["details"].extend(cmd_result["details"])
            
            # Set final status
            if changes_found:
                differences["status"] = "changed"
                differences["summary"] = f"Found {total_changes} MLAG changes across {len([cmd for cmd in mlag_commands if first_data.get(cmd) or second_data.get(cmd)])} commands"
            else:
                differences["status"] = "no_changes"
                differences["summary"] = "No MLAG changes detected"
            
            differences["statistics"] = {
                "total_changes": total_changes,
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"])
            }
            
            return differences
            
        except Exception as e:
            logger.error(f"Error in MLAG comparison: {e}")
            differences["status"] = "error"
            differences["summary"] = f"Error during MLAG comparison: {str(e)}"
            return differences

    def _compare_mlag_command(self, first_cmd: Dict, second_cmd: Dict, command_name: str) -> Dict:
        """Compare MLAG data for a specific command and return detailed change information."""
        result = {
            "changes_count": 0,
            "added": [],
            "removed": [],
            "modified": [],
            "details": []
        }
        
        try:
            if command_name == 'show mlag interfaces detail':
                # Compare MLAG interfaces
                first_intfs = first_cmd.get('interfaces', {})
                second_intfs = second_cmd.get('interfaces', {})
                
                # Added interfaces
                for intf_id in set(second_intfs.keys()) - set(first_intfs.keys()):
                    intf_data = second_intfs[intf_id]
                    result["added"].append({
                        'type': 'mlag_interface',
                        'interface_id': intf_id,
                        'local_interface': intf_data.get('localInterface'),
                        'status': intf_data.get('status'),
                        'description': f"MLAG interface {intf_id} ({intf_data.get('localInterface')}) added"
                    })
                    result["changes_count"] += 1
                
                # Removed interfaces
                for intf_id in set(first_intfs.keys()) - set(second_intfs.keys()):
                    intf_data = first_intfs[intf_id]
                    result["removed"].append({
                        'type': 'mlag_interface',
                        'interface_id': intf_id,
                        'local_interface': intf_data.get('localInterface'),
                        'status': intf_data.get('status'),
                        'description': f"MLAG interface {intf_id} ({intf_data.get('localInterface')}) removed"
                    })
                    result["changes_count"] += 1
                
                # Modified interfaces
                for intf_id in set(first_intfs.keys()) & set(second_intfs.keys()):
                    first_intf = first_intfs[intf_id]
                    second_intf = second_intfs[intf_id]
                    
                    changes = []
                    # Check key attributes
                    for attr in ['localInterfaceStatus', 'peerInterfaceStatus', 'status', 'localInterfaceDescription']:
                        if first_intf.get(attr) != second_intf.get(attr):
                            changes.append(f"{attr}: {first_intf.get(attr)} → {second_intf.get(attr)}")
                    
                    # Check detail attributes
                    first_detail = first_intf.get('detail', {})
                    second_detail = second_intf.get('detail', {})
                    for attr in ['changeCount', 'lastChangeTime']:
                        if first_detail.get(attr) != second_detail.get(attr):
                            changes.append(f"detail.{attr}: {first_detail.get(attr)} → {second_detail.get(attr)}")
                    
                    if changes:
                        result["modified"].append({
                            'type': 'mlag_interface',
                            'interface_id': intf_id,
                            'local_interface': first_intf.get('localInterface'),
                            'changes': changes,
                            'before': first_intf,
                            'after': second_intf,
                            'description': f"MLAG interface {intf_id} modified: {', '.join(changes)}"
                        })
                        result["changes_count"] += 1
            
            elif command_name in ['show mlag', 'show mlag detail']:
                # Compare top-level MLAG state
                state_attrs = ['state', 'negStatus', 'peerLinkStatus', 'localIntfStatus', 'configSanity']
                port_attrs = ['mlagPorts']
                detail_attrs = ['mlagState', 'peerMlagState', 'stateChanges', 'failover', 'enabled'] if command_name == 'show mlag detail' else []
                
                changes = []
                
                # Check state attributes
                for attr in state_attrs:
                    if first_cmd.get(attr) != second_cmd.get(attr):
                        changes.append(f"{attr}: {first_cmd.get(attr)} → {second_cmd.get(attr)}")
                
                # Check port counts
                for attr in port_attrs:
                    first_ports = first_cmd.get(attr, {})
                    second_ports = second_cmd.get(attr, {})
                    for port_type in ['Disabled', 'Configured', 'Inactive', 'Active-partial', 'Active-full']:
                        if first_ports.get(port_type) != second_ports.get(port_type):
                            changes.append(f"ports.{port_type}: {first_ports.get(port_type)} → {second_ports.get(port_type)}")
                
                # Check detail attributes for show mlag detail
                if command_name == 'show mlag detail':
                    first_detail = first_cmd.get('detail', {})
                    second_detail = second_cmd.get('detail', {})
                    for attr in detail_attrs:
                        if first_detail.get(attr) != second_detail.get(attr):
                            changes.append(f"detail.{attr}: {first_detail.get(attr)} → {second_detail.get(attr)}")
                
                if changes:
                    result["modified"].append({
                        'type': 'mlag_state',
                        'command': command_name,
                        'changes': changes,
                        'before': first_cmd,
                        'after': second_cmd,
                        'description': f"MLAG state modified: {', '.join(changes)}"
                    })
                    result["changes_count"] += 1
            
            elif command_name == 'show mlag config-sanity':
                # Compare MLAG config sanity
                attrs = ['mlagActive', 'mlagConnected']
                changes = []
                
                for attr in attrs:
                    if first_cmd.get(attr) != second_cmd.get(attr):
                        changes.append(f"{attr}: {first_cmd.get(attr)} → {second_cmd.get(attr)}")
                
                if changes:
                    result["modified"].append({
                        'type': 'mlag_config_sanity',
                        'changes': changes,
                        'before': first_cmd,
                        'after': second_cmd,
                        'description': f"MLAG config sanity modified: {', '.join(changes)}"
                    })
                    result["changes_count"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Error comparing MLAG command {command_name}: {e}")
            result["details"].append(f"Error comparing {command_name}: {str(e)}")
            return result

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
            
            # Create detailed mappings based on IP address
            first_arps = {entry['address']: entry for entry in first_entries}
            second_arps = {entry['address']: entry for entry in second_entries}
            
            added_ips = set(second_arps.keys()) - set(first_arps.keys())
            removed_ips = set(first_arps.keys()) - set(second_arps.keys())
            
            changes_found = False
            total_changes = 0
            
            # Added ARP entries
            if added_ips:
                for ip in added_ips:
                    entry = second_arps[ip]
                    differences["added"].append({
                        'type': 'arp_entry',
                        'address': ip,
                        'hwAddress': entry.get('hwAddress'),
                        'interface': entry.get('interface'),
                        'age': entry.get('age'),
                        'description': f"ARP entry {ip} ({entry.get('hwAddress')}) added on {entry.get('interface')}"
                    })
                    total_changes += 1
                    changes_found = True
            
            # Removed ARP entries
            if removed_ips:
                for ip in removed_ips:
                    entry = first_arps[ip]
                    differences["removed"].append({
                        'type': 'arp_entry',
                        'address': ip,
                        'hwAddress': entry.get('hwAddress'),
                        'interface': entry.get('interface'),
                        'age': entry.get('age'),
                        'description': f"ARP entry {ip} ({entry.get('hwAddress')}) removed from {entry.get('interface')}"
                    })
                    total_changes += 1
                    changes_found = True
            
            # Modified ARP entries
            for ip in set(first_arps.keys()) & set(second_arps.keys()):
                first_entry = first_arps[ip]
                second_entry = second_arps[ip]
                
                changes = []
                # Check key attributes
                for attr in ['hwAddress', 'interface', 'age']:
                    if first_entry.get(attr) != second_entry.get(attr):
                        changes.append(f"{attr}: {first_entry.get(attr)} → {second_entry.get(attr)}")
                
                if changes:
                    differences["modified"].append({
                        'type': 'arp_entry',
                        'address': ip,
                        'changes': changes,
                        'before': first_entry,
                        'after': second_entry,
                        'description': f"ARP entry {ip} modified: {', '.join(changes)}"
                    })
                    total_changes += 1
                    changes_found = True
            
            # Compare summary statistics
            first_stats = {
                'totalEntries': first_cmd.get('totalEntries', 0),
                'staticEntries': first_cmd.get('staticEntries', 0),
                'dynamicEntries': first_cmd.get('dynamicEntries', 0),
                'notLearnedEntries': first_cmd.get('notLearnedEntries', 0)
            }
            second_stats = {
                'totalEntries': second_cmd.get('totalEntries', 0),
                'staticEntries': second_cmd.get('staticEntries', 0),
                'dynamicEntries': second_cmd.get('dynamicEntries', 0),
                'notLearnedEntries': second_cmd.get('notLearnedEntries', 0)
            }
            
            stats_changes = []
            for stat in first_stats:
                if first_stats[stat] != second_stats[stat]:
                    stats_changes.append(f"{stat}: {first_stats[stat]} → {second_stats[stat]}")
            
            if stats_changes:
                differences["modified"].append({
                    'type': 'arp_statistics',
                    'changes': stats_changes,
                    'before': first_stats,
                    'after': second_stats,
                    'description': f"ARP table statistics changed: {', '.join(stats_changes)}"
                })
                total_changes += 1
                changes_found = True
            
            # Set final status
            if changes_found:
                differences["status"] = "changed"
                differences["summary"] = f"Found {total_changes} ARP changes - {len(added_ips)} added, {len(removed_ips)} removed, {len([m for m in differences['modified'] if m['type'] == 'arp_entry'])} modified entries"
            else:
                differences["status"] = "no_changes"
                differences["summary"] = "No ARP table changes detected"
            
            differences["statistics"] = {
                "total_changes": total_changes,
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"]),
                "first_total_entries": first_stats['totalEntries'],
                "second_total_entries": second_stats['totalEntries']
            }
            
            return differences
            
        except Exception as e:
            logger.error(f"Error in ARP comparison: {e}")
            differences["status"] = "error"
            differences["summary"] = f"Error during ARP comparison: {str(e)}"
            return differences

    def _compare_interfaces_enhanced(self, first_data: Dict, second_data: Dict) -> Dict:
        """Enhanced interface comparison covering all interface commands."""
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
            # Check all interface-related commands
            interface_commands = [
                'show interfaces',
                'show interfaces status', 
                'show interfaces counters',
                'show interfaces description'
            ]
            
            changes_found = False
            total_changes = 0
            
            # Compare each interface command
            for cmd in interface_commands:
                first_cmd = first_data.get(cmd, {})
                second_cmd = second_data.get(cmd, {})
                
                if not first_cmd and not second_cmd:
                    continue  # Skip if both are missing
                
                if not first_cmd or not second_cmd:
                    differences["details"].append(f"Command '{cmd}' missing in one file")
                    changes_found = True
                    continue
                
                # Handle different data structures for each command
                if cmd == 'show interfaces status':
                    first_intfs = first_cmd.get('interfaceStatuses', {})
                    second_intfs = second_cmd.get('interfaceStatuses', {})
                elif cmd == 'show interfaces':
                    first_intfs = first_cmd.get('interfaces', {})
                    second_intfs = second_cmd.get('interfaces', {})
                elif cmd == 'show interfaces counters':
                    first_intfs = first_cmd.get('interfaces', {})
                    second_intfs = second_cmd.get('interfaces', {})
                elif cmd == 'show interfaces description':
                    first_intfs = first_cmd.get('interfaceDescriptions', {})
                    second_intfs = second_cmd.get('interfaceDescriptions', {})
                else:
                    continue
                
                # Compare interfaces for this command
                cmd_result = self._compare_interface_command(first_intfs, second_intfs, cmd)
                if cmd_result["changes_count"] > 0:
                    changes_found = True
                    total_changes += cmd_result["changes_count"]
                    
                    # Add command-specific details
                    differences["details"].append(f"Changes in '{cmd}': {cmd_result['changes_count']} interfaces affected")
                    differences["details"].extend(cmd_result["details"])
                    
                    # Aggregate changes from this command
                    differences["added"].extend(cmd_result["added"])
                    differences["removed"].extend(cmd_result["removed"])
                    differences["modified"].extend(cmd_result["modified"])
            
            if changes_found:
                differences["status"] = "changed"
                differences["summary"] = f"Interface changes detected across {total_changes} interfaces in multiple commands"
                
                # Add detailed statistics
                differences["statistics"] = {
                    "total_changes": total_changes,
                    "added_interfaces": len(differences["added"]),
                    "removed_interfaces": len(differences["removed"]),
                    "modified_interfaces": len(differences["modified"]),
                    "commands_with_changes": len([cmd for cmd in interface_commands 
                                                if self._command_has_changes(first_data.get(cmd, {}), second_data.get(cmd, {}))]),
                    "breakdown_by_command": self._get_command_breakdown(differences)
                }
                
                return differences
            
            # If no changes found in any command, fall back to original logic for compatibility
            first_cmd = first_data.get('show interfaces status', {})
            second_cmd = second_data.get('show interfaces status', {})
            
            if not first_cmd or not second_cmd:
                differences["status"] = "no_changes"
                differences["summary"] = "No interface data to compare"
                return differences
            
            first_intfs = first_cmd.get('interfaceStatuses', {})
            second_intfs = second_cmd.get('interfaceStatuses', {})
            
            all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
            added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
            
            status_changes = []
            
            for intf_name in all_interfaces:
                first_intf = first_intfs.get(intf_name, {})
                second_intf = second_intfs.get(intf_name, {})
                
                if intf_name in added_interfaces:
                    differences["added"].append({
                        'type': 'interface',
                        'interface': intf_name,
                        'linkStatus': second_intf.get('linkStatus'),
                        'description': second_intf.get('description'),
                        'bandwidth': second_intf.get('bandwidth'),
                        'duplex': second_intf.get('duplex'),
                        'interfaceType': second_intf.get('interfaceType'),
                        'vlanInformation': second_intf.get('vlanInformation'),
                        'autoNegotiateActive': second_intf.get('autoNegotiateActive'),
                        'lineProtocolStatus': second_intf.get('lineProtocolStatus'),
                        'description_text': f"Interface {intf_name} added with status {second_intf.get('linkStatus')}"
                    })
                elif intf_name in removed_interfaces:
                    differences["removed"].append({
                        'type': 'interface',
                        'interface': intf_name,
                        'linkStatus': first_intf.get('linkStatus'),
                        'description': first_intf.get('description'),
                        'bandwidth': first_intf.get('bandwidth'),
                        'duplex': first_intf.get('duplex'),
                        'interfaceType': first_intf.get('interfaceType'),
                        'vlanInformation': first_intf.get('vlanInformation'),
                        'autoNegotiateActive': first_intf.get('autoNegotiateActive'),
                        'lineProtocolStatus': first_intf.get('lineProtocolStatus'),
                        'description_text': f"Interface {intf_name} removed (was {first_intf.get('linkStatus')})"
                    })
                else:
                    # Check for detailed changes in interface attributes
                    changes_detected = []
                    
                    # Compare key interface attributes
                    attributes_to_compare = [
                        'linkStatus', 'description', 'bandwidth', 'duplex', 
                        'interfaceType', 'autoNegotiateActive', 'lineProtocolStatus'
                    ]
                    
                    interface_changed = False
                    change_details = {}
                    
                    for attr in attributes_to_compare:
                        first_val = first_intf.get(attr)
                        second_val = second_intf.get(attr)
                        if first_val != second_val:
                            interface_changed = True
                            change_details[attr] = {'before': first_val, 'after': second_val}
                            changes_detected.append(f"{attr}: {first_val} -> {second_val}")
                    
                    # Compare VLAN information if present
                    first_vlan = first_intf.get('vlanInformation', {})
                    second_vlan = second_intf.get('vlanInformation', {})
                    if first_vlan != second_vlan:
                        interface_changed = True
                        change_details['vlanInformation'] = {'before': first_vlan, 'after': second_vlan}
                        changes_detected.append(f"VLAN info changed")
                    
                    if interface_changed:
                        differences["modified"].append({
                            'type': 'interface',
                            'interface': intf_name,
                            'old_data': first_intf,
                            'new_data': second_intf,
                            'changes': change_details,
                            'description_text': f"Interface {intf_name}: {', '.join(changes_detected)}"
                        })
                        status_changes.append(f"Interface {intf_name}: {', '.join(changes_detected)}")
            
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
                differences["details"].extend([item['description_text'] for item in differences["added"]])
                differences["details"].extend([item['description_text'] for item in differences["removed"]])
                differences["details"].extend([item['description_text'] for item in differences["modified"]])
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing interfaces: {str(e)}"
            differences["statistics"] = {"error": str(e)}
        
        return differences

    def _compare_interface_command(self, first_intfs: Dict, second_intfs: Dict, command_name: str) -> Dict:
        """Compare interfaces for a specific command and return detailed change information."""
        result = {
            "changes_count": 0,
            "added": [],
            "removed": [],
            "modified": [],
            "details": []
        }
        
        all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
        added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
        removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
        
        # Track added interfaces
        for intf_name in added_interfaces:
            intf_data = second_intfs.get(intf_name, {})
            result["added"].append({
                "interface": intf_name,
                "data": intf_data,
                "command": command_name
            })
            result["details"].append(f"Added interface {intf_name} in '{command_name}'")
        
        # Track removed interfaces  
        for intf_name in removed_interfaces:
            intf_data = first_intfs.get(intf_name, {})
            result["removed"].append({
                "interface": intf_name,
                "data": intf_data,
                "command": command_name
            })
            result["details"].append(f"Removed interface {intf_name} in '{command_name}'")
        
        # Check for modifications in existing interfaces
        for intf_name in all_interfaces:
            if intf_name in added_interfaces or intf_name in removed_interfaces:
                continue
                
            first_intf = first_intfs.get(intf_name, {})
            second_intf = second_intfs.get(intf_name, {})
            
            # Compare interface data - if they're different, track the change
            if first_intf != second_intf:
                # Identify specific attribute changes
                changed_attributes = []
                for key in set(first_intf.keys()) | set(second_intf.keys()):
                    first_val = first_intf.get(key)
                    second_val = second_intf.get(key)
                    if first_val != second_val:
                        changed_attributes.append({
                            "attribute": key,
                            "before": first_val,
                            "after": second_val
                        })
                
                result["modified"].append({
                    "interface": intf_name,
                    "command": command_name,
                    "old_data": first_intf,
                    "new_data": second_intf,
                    "changed_attributes": changed_attributes
                })
                
                # Create detailed description of changes
                attr_changes = ", ".join([f"{attr['attribute']}: {attr['before']} → {attr['after']}" 
                                        for attr in changed_attributes[:3]])  # Limit to first 3 for readability
                if len(changed_attributes) > 3:
                    attr_changes += f" (+{len(changed_attributes)-3} more)"
                
                result["details"].append(f"Modified interface {intf_name} in '{command_name}': {attr_changes}")
                logger.debug(f"Interface {intf_name} changed in {command_name}: {len(changed_attributes)} attributes")
        
        result["changes_count"] = len(result["added"]) + len(result["removed"]) + len(result["modified"])
        return result

    def _command_has_changes(self, first_cmd: Dict, second_cmd: Dict) -> bool:
        """Check if a command has any changes."""
        return first_cmd != second_cmd and (first_cmd or second_cmd)

    def _get_command_breakdown(self, differences: Dict) -> Dict:
        """Get breakdown of changes by command."""
        breakdown = {}
        
        # Group changes by command
        for item in differences["added"] + differences["removed"] + differences["modified"]:
            cmd = item.get("command", "unknown")
            if cmd not in breakdown:
                breakdown[cmd] = {"added": 0, "removed": 0, "modified": 0, "interfaces": []}
            
            if item in differences["added"]:
                breakdown[cmd]["added"] += 1
                breakdown[cmd]["interfaces"].append(f"{item['interface']} (added)")
            elif item in differences["removed"]:
                breakdown[cmd]["removed"] += 1
                breakdown[cmd]["interfaces"].append(f"{item['interface']} (removed)")
            elif item in differences["modified"]:
                breakdown[cmd]["modified"] += 1
                # Add specific attribute changes for modified interfaces
                if "changed_attributes" in item:
                    attr_list = [attr["attribute"] for attr in item["changed_attributes"][:3]]
                    attr_summary = ", ".join(attr_list)
                    if len(item["changed_attributes"]) > 3:
                        attr_summary += f" (+{len(item['changed_attributes'])-3} more)"
                    breakdown[cmd]["interfaces"].append(f"{item['interface']} (modified: {attr_summary})")
                else:
                    breakdown[cmd]["interfaces"].append(f"{item['interface']} (modified)")
        
        return breakdown

    def _create_comprehensive_detailed_data(self, comparison_results: List[Dict], detailed_data: List[Dict]) -> List[Dict]:
        """Create comprehensive detailed data combining general changes and interface specifics."""
        comprehensive_data = []
        
        # Start with the general detailed changes
        for item in detailed_data:
            comprehensive_data.append({
                "Type": "General",
                "IP Address": item.get("IP Address", ""),
                "Hostname": item.get("Hostname", ""),
                "Model SW": item.get("Model SW", ""),
                "Command": item.get("Command", ""),
                "Status": item.get("Status", ""),
                "Summary": item.get("Summary", ""),
                "Added Items": item.get("Added Items", ""),
                "Removed Items": item.get("Removed Items", ""),
                "Modified Items": item.get("Modified Items", ""),
                "Details": item.get("Details", ""),
                "Interface": "",
                "Change Type": "",
                "Attribute Changed": "",
                "Before Value": "",
                "After Value": "",
                "MAC Address": "",
                "VLAN": "",
                "Bandwidth": "",
                "Duplex": "",
                "Line Protocol": ""
            })
        
        # Add detailed interface information
        for result in comparison_results:
            ip_mgmt = result.get('ip_mgmt', 'Unknown') if isinstance(result, dict) else result.ip_mgmt
            hostname = result.get('hostname', 'Unknown') if isinstance(result, dict) else result.hostname
            model_sw = result.get('model_sw', 'N/A') if isinstance(result, dict) else getattr(result, 'model_sw', 'N/A')
            command_results = result.get('command_results', {}) if isinstance(result, dict) else result.command_results or {}
            
            # Process interface commands
            for command_type in ['interfaces', 'interfaces_status']:
                if command_type in command_results:
                    cmd_result = command_results[command_type]
                    
                    # Process added interfaces
                    for item in cmd_result.get('added', []):
                        comprehensive_data.append(self._create_interface_row(
                            ip_mgmt, hostname, model_sw, item, "Added", command_type
                        ))
                    
                    # Process removed interfaces
                    for item in cmd_result.get('removed', []):
                        comprehensive_data.append(self._create_interface_row(
                            ip_mgmt, hostname, model_sw, item, "Removed", command_type
                        ))
                    
                    # Process modified interfaces
                    for item in cmd_result.get('modified', []):
                        comprehensive_data.append(self._create_interface_row(
                            ip_mgmt, hostname, model_sw, item, "Modified", command_type
                        ))
            
            # Process MLAG commands
            if 'mlag' in command_results:
                cmd_result = command_results['mlag']
                
                # Process added MLAG items
                for item in cmd_result.get('added', []):
                    comprehensive_data.append(self._create_mlag_row(
                        ip_mgmt, hostname, model_sw, item, "Added"
                    ))
                
                # Process removed MLAG items
                for item in cmd_result.get('removed', []):
                    comprehensive_data.append(self._create_mlag_row(
                        ip_mgmt, hostname, model_sw, item, "Removed"
                    ))
                
                # Process modified MLAG items
                for item in cmd_result.get('modified', []):
                    comprehensive_data.append(self._create_mlag_row(
                        ip_mgmt, hostname, model_sw, item, "Modified"
                    ))
            
            # Process ARP/Protocols commands
            if 'protocols' in command_results:
                cmd_result = command_results['protocols']
                
                # Process added ARP entries
                for item in cmd_result.get('added', []):
                    comprehensive_data.append(self._create_arp_row(
                        ip_mgmt, hostname, model_sw, item, "Added"
                    ))
                
                # Process removed ARP entries
                for item in cmd_result.get('removed', []):
                    comprehensive_data.append(self._create_arp_row(
                        ip_mgmt, hostname, model_sw, item, "Removed"
                    ))
                
                # Process modified ARP entries
                for item in cmd_result.get('modified', []):
                    comprehensive_data.append(self._create_arp_row(
                        ip_mgmt, hostname, model_sw, item, "Modified"
                    ))
            
            # Process Routing commands
            if 'routing' in command_results:
                cmd_result = command_results['routing']
                
                for item in cmd_result.get('added', []):
                    comprehensive_data.append(self._create_routing_row(
                        ip_mgmt, hostname, model_sw, item, "Added"
                    ))
                
                for item in cmd_result.get('removed', []):
                    comprehensive_data.append(self._create_routing_row(
                        ip_mgmt, hostname, model_sw, item, "Removed"
                    ))
                
                for item in cmd_result.get('modified', []):
                    comprehensive_data.append(self._create_routing_row(
                        ip_mgmt, hostname, model_sw, item, "Modified"
                    ))
            
            # Process Switching commands
            if 'switching' in command_results:
                cmd_result = command_results['switching']
                
                for item in cmd_result.get('added', []):
                    comprehensive_data.append(self._create_switching_row(
                        ip_mgmt, hostname, model_sw, item, "Added"
                    ))
                
                for item in cmd_result.get('removed', []):
                    comprehensive_data.append(self._create_switching_row(
                        ip_mgmt, hostname, model_sw, item, "Removed"
                    ))
                
                for item in cmd_result.get('modified', []):
                    comprehensive_data.append(self._create_switching_row(
                        ip_mgmt, hostname, model_sw, item, "Modified"
                    ))
            
            # Process System Info commands
            if 'system_info' in command_results:
                cmd_result = command_results['system_info']
                
                for item in cmd_result.get('added', []):
                    comprehensive_data.append(self._create_system_row(
                        ip_mgmt, hostname, model_sw, item, "Added"
                    ))
                
                for item in cmd_result.get('removed', []):
                    comprehensive_data.append(self._create_system_row(
                        ip_mgmt, hostname, model_sw, item, "Removed"
                    ))
                
                for item in cmd_result.get('modified', []):
                    comprehensive_data.append(self._create_system_row(
                        ip_mgmt, hostname, model_sw, item, "Modified"
                    ))
        
        return comprehensive_data

    def _create_interface_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str, command_type: str) -> Dict:
        """Create a row for interface changes."""
        interface_data = item.get('data', item.get('new_data', item.get('old_data', {})))
        
        return {
            "Type": "Interface",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": command_type.replace('_', ' ').title(),
            "Status": "Changed",
            "Summary": f"Interface {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description_text', f"Interface {item.get('interface', 'Unknown')} {change_type.lower()}"),
            "Interface": item.get('interface', 'Unknown'),
            "Change Type": change_type,
            "Attribute Changed": "All" if change_type in ["Added", "Removed"] else "",
            "Before Value": str(item.get('old_data', '')) if change_type != "Added" else "",
            "After Value": str(item.get('new_data', '')) if change_type != "Removed" else "",
            "MAC Address": interface_data.get('physicalAddress', interface_data.get('burnedInAddress', '')),
            "VLAN": str(interface_data.get('vlanInformation', {}).get('vlanId', '')),
            "Bandwidth": str(interface_data.get('bandwidth', '')),
            "Duplex": interface_data.get('duplex', ''),
            "Line Protocol": interface_data.get('lineProtocolStatus', '')
        }

    def _create_interface_attribute_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, attr: Dict, command_type: str) -> Dict:
        """Create a row for specific interface attribute changes."""
        interface_data = item.get('new_data', {})
        
        return {
            "Type": "Interface Attribute",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": command_type.replace('_', ' ').title(),
            "Status": "Changed",
            "Summary": f"Attribute {attr['attribute']} changed",
            "Added Items": "",
            "Removed Items": "",
            "Modified Items": 1,
            "Details": f"Interface {item.get('interface', 'Unknown')}: {attr['attribute']} changed from {attr['before']} to {attr['after']}",
            "Interface": item.get('interface', 'Unknown'),
            "Change Type": "Modified",
            "Attribute Changed": attr['attribute'],
            "Before Value": str(attr['before']),
            "After Value": str(attr['after']),
            "MAC Address": interface_data.get('physicalAddress', interface_data.get('burnedInAddress', '')),
            "VLAN": str(interface_data.get('vlanInformation', {}).get('vlanId', '')),
            "Bandwidth": str(interface_data.get('bandwidth', '')),
            "Duplex": interface_data.get('duplex', ''),
            "Line Protocol": interface_data.get('lineProtocolStatus', '')
        }

    def _create_mlag_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str) -> Dict:
        """Create a row for MLAG changes."""
        return {
            "Type": "MLAG",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": "MLAG",
            "Status": "Changed",
            "Summary": f"MLAG {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description', f"MLAG {item.get('type', 'Unknown')} {change_type.lower()}"),
            "Interface": item.get('local_interface', item.get('interface_id', '')),
            "Change Type": change_type,
            "Attribute Changed": ', '.join(item.get('changes', [])) if 'changes' in item else "All",
            "Before Value": str(item.get('before', '')) if change_type != "Added" else "",
            "After Value": str(item.get('after', '')) if change_type != "Removed" else "",
            "MAC Address": "",
            "VLAN": "",
            "Bandwidth": "",
            "Duplex": "",
            "Line Protocol": item.get('status', '')
        }

    def _create_arp_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str) -> Dict:
        """Create a row for ARP changes."""
        return {
            "Type": "ARP",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": "Protocols (ARP)",
            "Status": "Changed",
            "Summary": f"ARP {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description', f"ARP entry {item.get('address', 'Unknown')} {change_type.lower()}"),
            "Interface": item.get('interface', ''),
            "Change Type": change_type,
            "Attribute Changed": ', '.join(item.get('changes', [])) if 'changes' in item else "All",
            "Before Value": str(item.get('before', '')) if change_type != "Added" else "",
            "After Value": str(item.get('after', '')) if change_type != "Removed" else "",
            "MAC Address": item.get('hwAddress', ''),
            "VLAN": "",
            "Bandwidth": "",
            "Duplex": "",
            "Line Protocol": ""
        }

    def _create_routing_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str) -> Dict:
        """Create a row for routing changes."""
        return {
            "Type": "Routing",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": "Routing",
            "Status": "Changed",
            "Summary": f"Routing {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description', f"Route {item.get('route', 'Unknown')} {change_type.lower()}"),
            "Interface": item.get('interface', ''),
            "Change Type": change_type,
            "Attribute Changed": ', '.join(item.get('changes', [])) if 'changes' in item else "All",
            "Before Value": str(item.get('before', '')) if change_type != "Added" else "",
            "After Value": str(item.get('after', '')) if change_type != "Removed" else "",
            "MAC Address": "",
            "VLAN": "",
            "Bandwidth": "",
            "Duplex": "",
            "Line Protocol": ""
        }

    def _create_switching_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str) -> Dict:
        """Create a row for switching changes."""
        return {
            "Type": "Switching",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": "Switching",
            "Status": "Changed",
            "Summary": f"Switching {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description', f"Switching entry {change_type.lower()}"),
            "Interface": item.get('interface', ''),
            "Change Type": change_type,
            "Attribute Changed": ', '.join(item.get('changes', [])) if 'changes' in item else "All",
            "Before Value": str(item.get('before', '')) if change_type != "Added" else "",
            "After Value": str(item.get('after', '')) if change_type != "Removed" else "",
            "MAC Address": item.get('mac', item.get('hwAddress', '')),
            "VLAN": item.get('vlan', ''),
            "Bandwidth": "",
            "Duplex": "",
            "Line Protocol": ""
        }

    def _create_system_row(self, ip_mgmt: str, hostname: str, model_sw: str, item: Dict, change_type: str) -> Dict:
        """Create a row for system info changes."""
        return {
            "Type": "System",
            "IP Address": ip_mgmt,
            "Hostname": hostname,
            "Model SW": model_sw,
            "Command": "System Info",
            "Status": "Changed",
            "Summary": f"System {change_type.lower()}",
            "Added Items": 1 if change_type == "Added" else "",
            "Removed Items": 1 if change_type == "Removed" else "",
            "Modified Items": 1 if change_type == "Modified" else "",
            "Details": item.get('description', f"System info {change_type.lower()}"),
            "Interface": "",
            "Change Type": change_type,
            "Attribute Changed": ', '.join(item.get('changes', [])) if 'changes' in item else "All",
            "Before Value": str(item.get('before', '')) if change_type != "Added" else "",
            "After Value": str(item.get('after', '')) if change_type != "Removed" else "",
            "MAC Address": "",
            "VLAN": "",
            "Bandwidth": "",
            "Duplex": "",
            "Line Protocol": ""
        }

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

    def _get_specific_commands_for_category(self, command_category: str, first_data: Dict, second_data: Dict) -> List[str]:
        """Get list of specific commands for a given category based on available data."""
        specific_commands = set()
        
        # Collect all specific commands from both datasets
        if isinstance(first_data, dict):
            specific_commands.update(first_data.keys())
        if isinstance(second_data, dict):
            specific_commands.update(second_data.keys())
        
        # Filter out non-command keys (like 'error')
        specific_commands = [cmd for cmd in specific_commands if not cmd.startswith('error')]
        
        logger.debug(f"Found specific commands for category '{command_category}': {specific_commands}")
        return sorted(specific_commands)
    
    def _compare_specific_command_data(self, first_data: Dict, second_data: Dict, specific_command: str, command_category: str) -> Dict:
        """Compare data for a specific command within a category."""
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
            
            # Route to appropriate comparison method based on command type
            if command_category == "interfaces":
                if "status" in specific_command:
                    differences = self._compare_interface_status_specific(first_data, second_data, specific_command)
                elif "counters" in specific_command:
                    differences = self._compare_interface_counters_specific(first_data, second_data, specific_command)
                elif "description" in specific_command:
                    differences = self._compare_interface_description_specific(first_data, second_data, specific_command)
                else:
                    differences = self._compare_interface_generic_specific(first_data, second_data, specific_command)
            elif command_category == "mlag":
                if "config-sanity" in specific_command:
                    differences = self._compare_mlag_config_sanity_specific(first_data, second_data, specific_command)
                elif "interfaces detail" in specific_command:
                    differences = self._compare_mlag_interfaces_specific(first_data, second_data, specific_command)
                elif "detail" in specific_command:
                    differences = self._compare_mlag_detail_specific(first_data, second_data, specific_command)
                else:
                    differences = self._compare_mlag_generic_specific(first_data, second_data, specific_command)
            elif command_category == "protocols":
                if "arp" in specific_command.lower():
                    differences = self._compare_arp_specific(first_data, second_data, specific_command)
                elif "ospf" in specific_command.lower():
                    differences = self._compare_ospf_specific(first_data, second_data, specific_command)
                elif "bgp" in specific_command.lower():
                    differences = self._compare_bgp_specific(first_data, second_data, specific_command)
                elif "lldp" in specific_command.lower():
                    differences = self._compare_lldp_specific(first_data, second_data, specific_command)
                else:
                    differences = self._compare_protocol_generic_specific(first_data, second_data, specific_command)
            elif command_category == "switching":
                if "mac address-table" in specific_command:
                    differences = self._compare_mac_table_specific(first_data, second_data, specific_command)
                else:
                    differences = self._compare_switching_generic_specific(first_data, second_data, specific_command)
            else:
                # Generic comparison for unknown categories
                differences = self._generic_specific_comparison(first_data, second_data, specific_command, command_category)
            
            return differences
            
        except Exception as e:
            logger.error(f"Error comparing specific command data for '{specific_command}': {e}")
            return {
                "status": "error",
                "summary": f"Error during comparison: {str(e)}",
                "details": [],
                "added": [],
                "removed": [],
                "modified": [],
                "statistics": {"error": str(e)}
            }

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

    def _compare_interface_status_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare interface status data specifically."""
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
            first_intfs = first_data.get('interfaceStatuses', {})
            second_intfs = second_data.get('interfaceStatuses', {})
            
            all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
            added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
            
            for intf_name in all_interfaces:
                if intf_name in added_interfaces:
                    intf_data = second_intfs[intf_name]
                    differences["added"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} status added"
                    })
                elif intf_name in removed_interfaces:
                    intf_data = first_intfs[intf_name]
                    differences["removed"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} status removed"
                    })
                else:
                    # Check for modifications
                    first_intf = first_intfs[intf_name]
                    second_intf = second_intfs[intf_name]
                    if first_intf != second_intf:
                        differences["modified"].append({
                            'interface': intf_name,
                            'old_data': first_intf,
                            'new_data': second_intf,
                            'description': f"Interface {intf_name} status modified"
                        })
            
            # Set status and summary
            total_changes = len(differences["added"]) + len(differences["removed"]) + len(differences["modified"])
            if total_changes > 0:
                differences["status"] = "changed"
                differences["summary"] = f"Interface status changes: {len(differences['added'])} added, {len(differences['removed'])} removed, {len(differences['modified'])} modified"
                differences["details"] = [item['description'] for item in differences["added"] + differences["removed"] + differences["modified"]]
            
            differences["statistics"] = {
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"])
            }
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing interface status: {str(e)}"
        
        return differences

    def _compare_interface_counters_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare interface counters data specifically."""
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
            first_intfs = first_data.get('interfaces', {})
            second_intfs = second_data.get('interfaces', {})
            
            all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
            added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
            
            for intf_name in all_interfaces:
                if intf_name in added_interfaces:
                    intf_data = second_intfs[intf_name]
                    differences["added"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} counters added"
                    })
                elif intf_name in removed_interfaces:
                    intf_data = first_intfs[intf_name]
                    differences["removed"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} counters removed"
                    })
                else:
                    # Check for modifications in counters
                    first_intf = first_intfs[intf_name]
                    second_intf = second_intfs[intf_name]
                    if first_intf != second_intf:
                        differences["modified"].append({
                            'interface': intf_name,
                            'old_data': first_intf,
                            'new_data': second_intf,
                            'description': f"Interface {intf_name} counters modified"
                        })
            
            # Set status and summary
            total_changes = len(differences["added"]) + len(differences["removed"]) + len(differences["modified"])
            if total_changes > 0:
                differences["status"] = "changed"
                differences["summary"] = f"Interface counters changes: {len(differences['added'])} added, {len(differences['removed'])} removed, {len(differences['modified'])} modified"
                differences["details"] = [item['description'] for item in differences["added"] + differences["removed"] + differences["modified"]]
            
            differences["statistics"] = {
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"])
            }
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing interface counters: {str(e)}"
        
        return differences

    def _compare_interface_description_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare interface description data specifically."""
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
            first_intfs = first_data.get('interfaceDescriptions', {})
            second_intfs = second_data.get('interfaceDescriptions', {})
            
            all_interfaces = set(first_intfs.keys()) | set(second_intfs.keys())
            added_interfaces = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_interfaces = set(first_intfs.keys()) - set(second_intfs.keys())
            
            for intf_name in all_interfaces:
                if intf_name in added_interfaces:
                    intf_data = second_intfs[intf_name]
                    differences["added"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} description added"
                    })
                elif intf_name in removed_interfaces:
                    intf_data = first_intfs[intf_name]
                    differences["removed"].append({
                        'interface': intf_name,
                        'data': intf_data,
                        'description': f"Interface {intf_name} description removed"
                    })
                else:
                    # Check for modifications
                    first_intf = first_intfs[intf_name]
                    second_intf = second_intfs[intf_name]
                    if first_intf != second_intf:
                        differences["modified"].append({
                            'interface': intf_name,
                            'old_data': first_intf,
                            'new_data': second_intf,
                            'description': f"Interface {intf_name} description modified"
                        })
            
            # Set status and summary
            total_changes = len(differences["added"]) + len(differences["removed"]) + len(differences["modified"])
            if total_changes > 0:
                differences["status"] = "changed"
                differences["summary"] = f"Interface description changes: {len(differences['added'])} added, {len(differences['removed'])} removed, {len(differences['modified'])} modified"
                differences["details"] = [item['description'] for item in differences["added"] + differences["removed"] + differences["modified"]]
            
            differences["statistics"] = {
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"])
            }
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing interface descriptions: {str(e)}"
        
        return differences

    def _compare_interface_generic_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Generic interface comparison for unknown interface commands."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "interfaces")

    def _compare_mlag_config_sanity_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare MLAG config sanity data specifically."""
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
            # Compare MLAG config sanity attributes
            attrs = ['mlagActive', 'mlagConnected', 'globalConfiguration', 'interfaceConfiguration']
            changes = []
            
            for attr in attrs:
                first_val = first_data.get(attr)
                second_val = second_data.get(attr)
                if first_val != second_val:
                    changes.append(f"{attr}: {first_val} → {second_val}")
                    differences["modified"].append({
                        'attribute': attr,
                        'before': first_val,
                        'after': second_val,
                        'description': f"MLAG config sanity {attr} changed from {first_val} to {second_val}"
                    })
            
            if changes:
                differences["status"] = "changed"
                differences["summary"] = f"MLAG config sanity modified: {', '.join(changes)}"
                differences["details"] = [item['description'] for item in differences["modified"]]
            
            differences["statistics"] = {
                "modified_count": len(differences["modified"])
            }
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing MLAG config sanity: {str(e)}"
        
        return differences

    def _compare_mlag_interfaces_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare MLAG interfaces detail data specifically."""
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
            first_intfs = first_data.get('interfaces', {})
            second_intfs = second_data.get('interfaces', {})
            
            all_mlag_ids = set(first_intfs.keys()) | set(second_intfs.keys())
            added_mlag_ids = set(second_intfs.keys()) - set(first_intfs.keys())
            removed_mlag_ids = set(first_intfs.keys()) - set(second_intfs.keys())
            
            for mlag_id in all_mlag_ids:
                if mlag_id in added_mlag_ids:
                    mlag_data = second_intfs[mlag_id]
                    differences["added"].append({
                        'interface': mlag_id,
                        'data': mlag_data,
                        'description': f"MLAG interface {mlag_id} added"
                    })
                elif mlag_id in removed_mlag_ids:
                    mlag_data = first_intfs[mlag_id]
                    differences["removed"].append({
                        'interface': mlag_id,
                        'data': mlag_data,
                        'description': f"MLAG interface {mlag_id} removed"
                    })
                else:
                    # Check for modifications
                    first_mlag = first_intfs[mlag_id]
                    second_mlag = second_intfs[mlag_id]
                    if first_mlag != second_mlag:
                        differences["modified"].append({
                            'interface': mlag_id,
                            'old_data': first_mlag,
                            'new_data': second_mlag,
                            'description': f"MLAG interface {mlag_id} modified"
                        })
            
            # Set status and summary
            total_changes = len(differences["added"]) + len(differences["removed"]) + len(differences["modified"])
            if total_changes > 0:
                differences["status"] = "changed"
                differences["summary"] = f"MLAG interfaces changes: {len(differences['added'])} added, {len(differences['removed'])} removed, {len(differences['modified'])} modified"
                differences["details"] = [item['description'] for item in differences["added"] + differences["removed"] + differences["modified"]]
            
            differences["statistics"] = {
                "added_count": len(differences["added"]),
                "removed_count": len(differences["removed"]),
                "modified_count": len(differences["modified"])
            }
            
        except Exception as e:
            differences["status"] = "error"
            differences["summary"] = f"Error comparing MLAG interfaces: {str(e)}"
        
        return differences

    def _compare_mlag_detail_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare MLAG detail data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "mlag")

    def _compare_mlag_generic_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Generic MLAG comparison for unknown MLAG commands."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "mlag")

    def _compare_arp_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare ARP data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "protocols")

    def _compare_ospf_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare OSPF data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "protocols")

    def _compare_bgp_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare BGP data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "protocols")

    def _compare_lldp_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare LLDP data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "protocols")

    def _compare_protocol_generic_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Generic protocol comparison for unknown protocol commands."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "protocols")

    def _compare_mac_table_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Compare MAC address table data specifically."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "switching")

    def _compare_switching_generic_specific(self, first_data: Dict, second_data: Dict, specific_command: str) -> Dict:
        """Generic switching comparison for unknown switching commands."""
        return self._generic_specific_comparison(first_data, second_data, specific_command, "switching")

    def _generic_specific_comparison(self, first_data: Dict, second_data: Dict, specific_command: str, command_category: str) -> Dict:
        """Generic comparison for any specific command."""
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
                differences["summary"] = f"{specific_command} data has changed between snapshots"
                differences["details"] = [f"Changes detected in {specific_command}"]
                differences["modified"].append({
                    'type': 'generic_change',
                    'command': specific_command,
                    'description': f"Changes detected in {specific_command}"
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

def get_csv_separator_from_content(file_content: str):
    """Detects the separator of a CSV file from content string."""
    try:
        header = file_content.split('\n')[0]
        separators = {',': header.count(','), ';': header.count(';'), '\t': header.count('\t'), '|': header.count('|')}
        separator = max(separators.items(), key=lambda x: x[1])[0]
        logger.info(f"Detected CSV separator from content: '{separator}'")
        return separator
    except Exception as e:
        logger.warning(f"Could not detect separator from content, defaulting to comma. Error: {e}")
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

def threaded_process_devices(username: str, password: str, file_content: str, session_id: str, selected_commands: List[str] = None, retry_failed_only: bool = False):
    """Threaded processing with retry mechanism and progress tracking using APIs."""
    try:
        session = processing_sessions[session_id]
        session.start_time = datetime.now()
        
        logger.info(f"Starting API-based threaded processing for session {session_id}")
        
        if retry_failed_only:
            logger.info("Retrying failed devices only")
        
        separator = get_csv_separator_from_content(file_content)
        from io import StringIO
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
            "status": "info" if not session.is_stopped else "stopped",
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

def detect_vendors_from_data(data_list):
    """Detect vendors from device data based on model_sw field."""
    detected_vendors = set()
    
    for item in data_list:
        model_sw = ""
        
        # Handle different data structures
        if isinstance(item, dict):
            model_sw = item.get('model_sw', item.get('Model SW', item.get('Model', '')))
        elif hasattr(item, 'model_sw'):
            model_sw = item.model_sw
        
        if model_sw:
            # Use the same detection logic as the device manager
            vendor = detect_device_type_by_model_static(model_sw)
            detected_vendors.add(vendor)
    
    return list(detected_vendors)

def detect_device_type_by_model_static(model_sw: str) -> str:
    """Static version of device type detection based on model string."""
    model_upper = model_sw.upper()
    
    for device_type, patterns in VENDOR_DETECTION_MAP.items():
        for pattern in patterns:
            if pattern.upper() in model_upper:
                return device_type
    
    # Default to arista_eos if no match found
    return "arista_eos"

@app.route('/api/commands_filtered', methods=['POST'])
def get_commands_filtered():
    """Get available commands filtered by detected vendors from uploaded data."""
    try:
        data = request.get_json()
        device_data = data.get('device_data', [])
        command_type = data.get('command_type', 'execution')  # 'execution' or 'comparison'
        
        if not device_data:
            # Return all commands if no data provided
            if command_type == 'comparison':
                all_commands = config_manager.get_comparison_commands()
            else:
                all_commands = config_manager.get_commands()
            
            return jsonify({
                "status": "success",
                "data": all_commands,
                "detected_vendors": []
            })
        
        # Detect vendors from device data
        detected_vendors = detect_vendors_from_data(device_data)
        
        # Get filtered commands based on detected vendors
        if command_type == 'comparison':
            all_commands = config_manager.get_comparison_commands()
        else:
            all_commands = config_manager.get_execution_commands()
        
        filtered_commands = {}
        
        for vendor in detected_vendors:
            for command_key, command_info in all_commands.items():
                if command_key.startswith(f"{vendor}_"):
                    filtered_commands[command_key] = command_info
        
        # If no vendors detected or no matching commands, return Arista as default
        if not filtered_commands:
            for command_key, command_info in all_commands.items():
                if command_key.startswith("arista_eos_"):
                    filtered_commands[command_key] = command_info
            detected_vendors = ["arista_eos"]
        
        logger.info(f"Detected vendors from data: {detected_vendors}")
        logger.info(f"Filtered {command_type} commands: {list(filtered_commands.keys())}")
        
        return jsonify({
            "status": "success",
            "data": filtered_commands,
            "detected_vendors": detected_vendors,
            "command_type": command_type
        })
        
    except Exception as e:
        logger.error(f"Error getting filtered commands: {e}")
        return jsonify({
            "status": "error",
            "message": f"Failed to get filtered commands: {str(e)}"
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
            # Process CSV in memory without saving to disk
            try:
                # Read file content into memory
                file_content = file.read()
                file.seek(0)  # Reset file pointer for pd.read_csv
                
                separator = get_csv_separator_from_content(file_content.decode('utf-8'))
                df = pd.read_csv(file, sep=separator)
                df.columns = [col.strip() for col in df.columns]
                
                errors, warnings, column_mapping = validate_csv_columns(df)
                
                if errors:
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
                
                # Detect vendors from uploaded data
                device_data = df.to_dict('records')
                detected_vendors = detect_vendors_from_data(device_data)
                
                return jsonify({
                    "status": "success",
                    "message": f"File processed successfully. {device_count} devices found.",
                    "file_content": file_content.decode('utf-8'),  # Store content in memory
                    "device_count": device_count,
                    "detected_vendors": detected_vendors,
                    "warnings": warnings[:10] if warnings else []
                })
                
            except Exception as e:
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
        file_content = data.get('file_content', '')
        selected_commands = data.get('selected_commands', [])
        retry_failed_only = data.get('retry_failed_only', False)
        
        if not username or not password:
            return jsonify({
                "status": "error",
                "message": "Username and password are required for API authentication"
            }), 400
        
        if not file_content:
            return jsonify({
                "status": "error",
                "message": "No valid file content found. Please upload a CSV file first."
            }), 400
        
        try:
            separator = get_csv_separator_from_content(file_content)
            # Create a StringIO object from the content
            from io import StringIO
            csv_io = StringIO(file_content)
            full_df = pd.read_csv(csv_io, sep=separator)
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
            args=(username, password, file_content, session_id, selected_commands, retry_failed_only)
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
        first_data_full = data_processor.load_results(first_file_path)
        second_data_full = data_processor.load_results(second_file_path)
        
        # Extract metadata and results
        first_metadata = first_data_full.get('metadata', {}) if isinstance(first_data_full, dict) else {}
        second_metadata = second_data_full.get('metadata', {}) if isinstance(second_data_full, dict) else {}
        
        first_data = first_data_full.get('results', first_data_full) if isinstance(first_data_full, dict) and 'results' in first_data_full else first_data_full
        second_data = second_data_full.get('results', second_data_full) if isinstance(second_data_full, dict) and 'results' in second_data_full else second_data_full
        
        # Get selected commands from metadata, fallback to first file metadata if second doesn't have it
        selected_commands = first_metadata.get('selected_commands', second_metadata.get('selected_commands', []))
        
        # Get available commands by checking what data actually exists in the files
        available_commands = set()
        
        # Check all devices in both files to see what command categories have actual data (not just errors)
        for device_data in first_data + second_data:
            if device_data.get("data"):
                for category, category_data in device_data["data"].items():
                    # Only include categories that have actual data, not just error messages
                    if isinstance(category_data, dict) and category_data:
                        # Check if it's not just an error message
                        if not (len(category_data) == 1 and "error" in category_data):
                            available_commands.add(category)
        
        # Convert to list and filter by comparison commands
        # Create a mapping from category to comparison commands
        comparison_commands = config_manager.get_comparison_commands()
        valid_categories = set()
        for cmd_key, cmd_info in comparison_commands.items():
            valid_categories.add(cmd_info['category'])
        
        # Filter available commands by checking if the category exists in comparison commands
        available_commands = [cmd for cmd in available_commands if cmd in valid_categories]
        
        logger.info(f"Valid comparison categories: {sorted(valid_categories)}")
        logger.info(f"Available commands based on actual data: {available_commands}")
        logger.info(f"Found {len(available_commands)} command categories with data to compare")
        
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
                    "model_sw": first_device.get("model_sw", "Unknown"),
                    "overall_status": "no_changes",
                    "command_results": {}
                }
                
                has_changes = False
                
                # Compare each available command by breaking down categories into specific commands
                for command_category in available_commands:
                    first_cmd_data = first_device.get("data", {}).get(command_category, {})
                    second_cmd_data = second_device.get("data", {}).get(command_category, {})
                    
                    # Get specific commands for this category and compare them individually
                    specific_commands = data_processor._get_specific_commands_for_category(
                        command_category, first_cmd_data, second_cmd_data
                    )
                    
                    # Compare each specific command
                    for specific_command in specific_commands:
                        first_specific_data = first_cmd_data.get(specific_command, {})
                        second_specific_data = second_cmd_data.get(specific_command, {})
                        
                        # Only compare if at least one has data
                        if first_specific_data or second_specific_data:
                            compare_result = data_processor._compare_specific_command_data(
                                first_specific_data, second_specific_data, specific_command, command_category
                            )
                            
                            device_result["command_results"][specific_command] = compare_result
                            
                            if compare_result["status"] != "no_changes":
                                has_changes = True
                
                device_result["overall_status"] = "changed" if has_changes else "no_changes"
                comparison_results.append(device_result)
        
        # Note: Auto-export removed - users can manually download via separate endpoint
        
        return jsonify({
            "status": "success",
            "data": comparison_results,
            "first_file": first_file,
            "second_file": second_file,
            "total_compared": len(comparison_results),
            "available_commands": available_commands
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
        
        # Note: Auto-export removed - users can manually download via separate endpoint
        
        return jsonify({
            "status": "success",
            "data": comparison_results
        })
        
    except Exception as e:
        logger.error(f"Error comparing snapshots: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error comparing snapshots: {str(e)}"
        }), 500

@app.route('/api/export_comparison_excel', methods=['POST'])
def export_comparison_excel():
    """Generate and download comparison Excel file on demand."""
    try:
        data = request.get_json()
        comparison_results = data.get('comparison_results', [])
        first_file = data.get('first_file', 'file1')
        second_file = data.get('second_file', 'file2')
        
        if not comparison_results:
            return jsonify({
                "status": "error",
                "message": "No comparison data to export"
            }), 400
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"comparison_{timestamp}.xlsx"
        filepath = os.path.join(data_processor.output_dir, filename)
        
        # Generate Excel file
        data_processor.export_to_excel_comparison(comparison_results, filepath)
        
        # Return file for download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        logger.error(f"Error exporting comparison Excel: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error generating Excel file: {str(e)}"
        }), 500

@app.route('/api/export_snapshot_comparison_excel', methods=['POST'])
def export_snapshot_comparison_excel():
    """Generate and download snapshot comparison Excel file on demand."""
    try:
        data = request.get_json()
        comparison_results = data.get('comparison_results', [])
        command_category = data.get('command_category', 'unknown')
        
        if not comparison_results:
            return jsonify({
                "status": "error",
                "message": "No comparison data to export"
            }), 400
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"snapshot_comparison_{command_category}_{timestamp}.xlsx"
        filepath = os.path.join(data_processor.output_dir, filename)
        
        # Create Excel data
        excel_data = []
        for result in comparison_results:
            excel_data.append({
                "IP": result["ip_mgmt"],
                "Hostname": result["hostname"],
                "Status": result["compare_result"]["status"],
                "Summary": result["compare_result"]["summary"],
                "Details": "; ".join(result["compare_result"]["details"]) if result["compare_result"]["details"] else ""
            })
        
        # Create Excel file
        df = pd.DataFrame(excel_data)
        df.to_excel(filepath, index=False, engine=EXCEL_ENGINE)
        
        # Return file for download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        logger.error(f"Error exporting snapshot comparison Excel: {e}")
        return jsonify({
            "status": "error",
            "message": f"Error generating Excel file: {str(e)}"
        }), 500

# Additional helper function if needed for snapshot comparison
def create_snapshot_comparison_data(comparison_results, command_category):
    """Create snapshot comparison data structure for potential future use"""
    excel_data = []
    for result in comparison_results:
        excel_data.append({
            "IP": result["ip_mgmt"],
            "Hostname": result["hostname"],
            "Status": result["compare_result"]["status"],
            "Summary": result["compare_result"]["summary"],
            "Details": "; ".join(result["compare_result"]["details"]) if result["compare_result"]["details"] else ""
        })
    return excel_data

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