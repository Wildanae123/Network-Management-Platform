import json
import time
import requests
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Union
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API endpoint configurations
API_ENDPOINTS = {
    "arista_eos": {
        "path": "/command-api",
        "format": "json-rpc",
        "test_command": "show version"
    },
    "cisco_ios": {
        "path": "/ins",
        "format": "json",
        "test_command": "show version"
    },
    "cisco_nexus": {
        "path": "/ins",
        "format": "json",
        "test_command": "show version"
    },
    "cisco_iosxr": {
        "path": "/rpc/yang",
        "format": "yang",
        "test_command": "show version"
    }
}

# Vendor detection mapping
VENDOR_DETECTION_MAP = {
    "arista_eos": ["DCS", "7050", "7150", "7250", "7280", "7300", "7350", "7500", "7800"],
    "cisco_ios": ["Catalyst", "2960", "3560", "3750", "3850", "9200", "9300", "9400"],
    "cisco_nexus": ["Nexus", "3048", "3064", "3132", "3172", "5548", "5596", "7000", "7700", "9000", "9300", "9500"],
    "cisco_iosxr": ["ASR", "CRS", "NCS"]
}

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Device information container."""
    ip_mgmt: str
    nama_sw: str = ""
    sn: str = ""
    model_sw: str = ""
    username: str = ""
    password: str = ""
    device_type: str = "arista_eos"
    port: int = 443
    timeout: int = 30
    
class APIClientBase:
    """Base class for API clients."""
    
    def __init__(self, device_info: DeviceInfo):
        self.device_info = device_info
        self.base_url = f"https://{device_info.ip_mgmt}:{device_info.port}"
        self.timeout = device_info.timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = (device_info.username, device_info.password)
        
    def test_connection(self) -> Dict[str, Any]:
        """Test API connection."""
        try:
            endpoint_config = API_ENDPOINTS.get(self.device_info.device_type, API_ENDPOINTS["arista_eos"])
            test_command = endpoint_config["test_command"]
            
            start_time = time.time()
            result = self.execute_command(test_command)
            response_time = time.time() - start_time
            
            if result and not result.get("error"):
                return {
                    "status": "Connected",
                    "response_time": response_time,
                    "endpoint": f"{self.base_url}{endpoint_config['path']}",
                    "error": None
                }
            else:
                return {
                    "status": "Failed",
                    "response_time": response_time,
                    "endpoint": f"{self.base_url}{endpoint_config['path']}",
                    "error": result.get("error", "Unknown error") if result else "No response"
                }
                
        except Exception as e:
            return {
                "status": "Failed",
                "response_time": 0,
                "endpoint": f"{self.base_url}",
                "error": str(e)
            }
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command via API. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement execute_command")
    
    def execute_commands(self, commands: List[str]) -> Dict[str, Any]:
        """Execute multiple commands via API. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement execute_commands")

class AristaEAPIClient(APIClientBase):
    """Arista eAPI client."""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.api_url = f"{self.base_url}/command-api"
        
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a single command via Arista eAPI."""
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "runCmds",
                "params": {
                    "version": 1,
                    "cmds": [command],
                    "format": "json"
                },
                "id": "1"
            }
            
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if "error" in result:
                    return {"error": result["error"]}
                elif "result" in result and result["result"]:
                    return result["result"][0]
                else:
                    return {"error": "No result data"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def execute_commands(self, commands: List[str]) -> Dict[str, Any]:
        """Execute multiple commands via Arista eAPI."""
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "runCmds",
                "params": {
                    "version": 1,
                    "cmds": commands,
                    "format": "json"
                },
                "id": "1"
            }
            
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if "error" in result:
                    return {"error": result["error"]}
                elif "result" in result:
                    # Return a dictionary mapping commands to results
                    command_results = {}
                    for i, command in enumerate(commands):
                        if i < len(result["result"]):
                            command_results[command] = result["result"][i]
                        else:
                            command_results[command] = {"error": "No result for command"}
                    return command_results
                else:
                    return {"error": "No result data"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            return {"error": str(e)}

class CiscoAPIClient(APIClientBase):
    """Cisco API client for IOS/NX-OS devices."""
    
    def __init__(self, device_info: DeviceInfo):
        super().__init__(device_info)
        self.api_url = f"{self.base_url}/ins"
        
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a single command via Cisco API."""
        try:
            payload = {
                "ins_api": {
                    "version": "1.0",
                    "type": "cli_show",
                    "chunk": "0",
                    "sid": "1",
                    "input": command,
                    "output_format": "json"
                }
            }
            
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if "ins_api" in result and "outputs" in result["ins_api"]:
                    outputs = result["ins_api"]["outputs"]
                    if outputs and "output" in outputs[0]:
                        return outputs[0]["output"]
                    else:
                        return {"error": "No output data"}
                else:
                    return {"error": "Invalid response format"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def execute_commands(self, commands: List[str]) -> Dict[str, Any]:
        """Execute multiple commands via Cisco API."""
        results = {}
        for command in commands:
            results[command] = self.execute_command(command)
        return results

class NetworkDeviceAPIManager:
    """Manager for handling different network device APIs."""
    
    def __init__(self):
        self.client_classes = {
            "arista_eos": AristaEAPIClient,
            "cisco_ios": CiscoAPIClient,
            "cisco_nexus": CiscoAPIClient,
            "cisco_iosxr": CiscoAPIClient  # Can be extended for XR-specific implementation
        }
    
    def connect_and_collect_data(self, device_info, model_sw=None, retry_count=0, session=None, selected_commands=None):
        """Connect to device via API and collect data with error handling."""
        try:
            start_time = time.time()
            
            # Create device info object if it's not already one
            if not isinstance(device_info, DeviceInfo):
                device_info = DeviceInfo(
                    ip_mgmt=device_info.get('ip_mgmt', ''),
                    nama_sw=device_info.get('nama_sw', ''),
                    sn=device_info.get('sn', ''),
                    model_sw=model_sw or device_info.get('model_sw', ''),
                    username=device_info.get('username', ''),
                    password=device_info.get('password', ''),
                    device_type=device_info.get('device_type', 'arista_eos'),
                    port=device_info.get('port', 443),
                    timeout=device_info.get('timeout', 30)
                )
            
            # Auto-detect device type if not specified
            if not device_info.device_type or device_info.device_type == "unknown":
                device_info.device_type = self.detect_device_type(device_info)
            
            # Create API client
            client = self.create_client(device_info)
            
            # Test connection first
            connection_result = client.test_connection()
            if connection_result["status"] != "Connected":
                return None, f"Connection failed: {connection_result.get('error', 'Unknown error')}", "failed", None, None, connection_result
            
            # Define command mapping based on device type and selected commands
            command_groups = self._get_command_groups(device_info.device_type, selected_commands)
            
            # Collect data from device
            collected_data = {}
            
            for group_name, commands in command_groups.items():
                try:
                    group_results = {}
                    for command_name, command in commands.items():
                        result = client.execute_command(command)
                        if result and not result.get("error"):
                            group_results[command_name] = result
                        else:
                            logger.warning(f"Command '{command}' failed for {device_info.ip_mgmt}: {result.get('error', 'Unknown error')}")
                    
                    if group_results:
                        collected_data[group_name] = group_results
                        
                except Exception as e:
                    logger.error(f"Error collecting {group_name} data from {device_info.ip_mgmt}: {e}")
                    continue
            
            processing_time = time.time() - start_time
            
            # Return collected data in the expected format
            return (
                collected_data,
                None,  # error
                "success",  # status
                processing_time,
                connection_result["response_time"],
                connection_result
            )
            
        except Exception as e:
            logger.error(f"Error in connect_and_collect_data for {device_info.ip_mgmt if hasattr(device_info, 'ip_mgmt') else 'unknown'}: {e}")
            return None, str(e), "failed", 0, 0, None
    
    def _get_command_groups(self, device_type: str, selected_commands: List[str] = None) -> Dict[str, Dict[str, str]]:
        """Get command groups based on device type and selected commands."""
        
        # Define command mappings for Arista EOS
        arista_commands = {
            "interfaces": {
                "show interfaces status": "show interfaces status",
                "show interfaces description": "show interfaces description"
            },
            "mlag": {
                "show mlag config-sanity": "show mlag config-sanity",
                "show mlag interfaces detail": "show mlag interfaces detail"
            },
            "protocols": {
                "show lldp neighbors": "show lldp neighbors",
                "show ip arp": "show ip arp"
            },
            "routing": {
                "show ip route summary": "show ip route summary"
            },
            "switching": {
                "show mac address-table": "show mac address-table",
                "show vlan brief": "show vlan brief",
                "show port-channel detailed": "show port-channel detailed"
            },
            "system_info": {
                "show version": "show version",
                "show hostname": "show hostname"
            }
        }
        
        # Define command mappings for other device types (can be extended)
        cisco_commands = {
            "interfaces": {
                "show interface status": "show interface status",
                "show interface description": "show interface description"
            },
            "system_info": {
                "show version": "show version",
                "show running-config | include hostname": "show running-config | include hostname"
            }
        }
        
        # Select appropriate command set based on device type
        if device_type == "arista_eos":
            all_commands = arista_commands
        elif device_type in ["cisco_ios", "cisco_nexus", "cisco_iosxr"]:
            all_commands = cisco_commands
        else:
            all_commands = arista_commands  # Default to Arista
        
        # Filter commands based on selected_commands if provided
        if selected_commands:
            filtered_commands = {}
            for cmd in selected_commands:
                # Map selected command names to groups
                if cmd == "arista_eos_interfaces" and "interfaces" in all_commands:
                    filtered_commands["interfaces"] = all_commands["interfaces"]
                elif cmd == "arista_eos_mlag" and "mlag" in all_commands:
                    filtered_commands["mlag"] = all_commands["mlag"]
                elif cmd == "arista_eos_protocols" and "protocols" in all_commands:
                    filtered_commands["protocols"] = all_commands["protocols"]
                elif cmd == "arista_eos_routing" and "routing" in all_commands:
                    filtered_commands["routing"] = all_commands["routing"]
                elif cmd == "arista_eos_switching" and "switching" in all_commands:
                    filtered_commands["switching"] = all_commands["switching"]
                elif cmd == "arista_eos_system_info" and "system_info" in all_commands:
                    filtered_commands["system_info"] = all_commands["system_info"]
            
            return filtered_commands if filtered_commands else all_commands
        
        return all_commands
    
    def create_client(self, device_info: DeviceInfo) -> APIClientBase:
        """Create appropriate API client based on device type."""
        device_type = device_info.device_type
        client_class = self.client_classes.get(device_type, AristaEAPIClient)
        return client_class(device_info)
    
    def detect_device_type(self, device_info: DeviceInfo) -> str:
        """Detect device type based on model or test connection."""
        # First try to detect by model if available
        if device_info.model_sw:
            detected_type = self._detect_by_model(device_info.model_sw)
            if detected_type != "unknown":
                return detected_type
        
        # If model detection fails, try connection-based detection
        return self._detect_by_connection(device_info)
    
    def _detect_by_model(self, model_sw: str) -> str:
        """Detect device type by model string."""
        model_upper = model_sw.upper()
        
        for device_type, patterns in VENDOR_DETECTION_MAP.items():
            for pattern in patterns:
                if pattern.upper() in model_upper:
                    return device_type
        
        return "unknown"
    
    def _detect_by_connection(self, device_info: DeviceInfo) -> str:
        """Detect device type by testing API connections."""
        # Try different device types in order of preference
        test_types = ["arista_eos", "cisco_nexus", "cisco_ios", "cisco_iosxr"]
        
        for device_type in test_types:
            try:
                test_device = DeviceInfo(
                    ip_mgmt=device_info.ip_mgmt,
                    username=device_info.username,
                    password=device_info.password,
                    device_type=device_type,
                    port=device_info.port,
                    timeout=10  # Shorter timeout for detection
                )
                
                client = self.create_client(test_device)
                connection_result = client.test_connection()
                
                if connection_result["status"] == "Connected":
                    logger.info(f"Detected device type {device_type} for {device_info.ip_mgmt}")
                    return device_type
                    
            except Exception as e:
                logger.debug(f"Failed to test {device_type} for {device_info.ip_mgmt}: {e}")
                continue
        
        # Default to Arista if nothing else works
        logger.warning(f"Could not detect device type for {device_info.ip_mgmt}, defaulting to arista_eos")
        return "arista_eos"
    
    def test_device_connection(self, device_info: DeviceInfo) -> Dict[str, Any]:
        """Test connection to a device."""
        try:
            # Auto-detect device type if not specified or unknown
            if not device_info.device_type or device_info.device_type == "unknown":
                device_info.device_type = self.detect_device_type(device_info)
            
            client = self.create_client(device_info)
            return client.test_connection()
            
        except Exception as e:
            return {
                "status": "Failed",
                "response_time": 0,
                "endpoint": f"https://{device_info.ip_mgmt}",
                "error": str(e)
            }
    
    def execute_device_commands(self, device_info: DeviceInfo, commands: List[str]) -> Dict[str, Any]:
        """Execute commands on a device."""
        try:
            # Auto-detect device type if not specified
            if not device_info.device_type or device_info.device_type == "unknown":
                device_info.device_type = self.detect_device_type(device_info)
            
            client = self.create_client(device_info)
            
            # Test connection first
            connection_result = client.test_connection()
            if connection_result["status"] != "Connected":
                return {
                    "error": f"Connection failed: {connection_result.get('error', 'Unknown error')}",
                    "connection_result": connection_result
                }
            
            # Execute commands
            if len(commands) == 1:
                result = client.execute_command(commands[0])
                return {commands[0]: result}
            else:
                return client.execute_commands(commands)
                
        except Exception as e:
            return {"error": str(e)}
