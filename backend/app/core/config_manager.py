# backend/app/core/config_manager.py
import yaml
import os
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Enhanced configuration manager for dynamic command loading."""
    
    def __init__(self, config_file: str = "commands.yaml"):
        self.config_file = config_file
        self.config_data = {}
        self.comparison_commands = {}
        self.supported_vendors = []
        self.load_config()
    
    def get_config_path(self) -> Path:
        """Get the configuration file path."""
        # Try multiple possible locations
        possible_paths = [
            # Production/deployment path
            Path(__file__).parent.parent.parent / "config" / self.config_file,
            # Development path
            Path(__file__).parent.parent / "config" / self.config_file,
            # Fallback to same directory
            Path(__file__).parent / self.config_file,
            # Environment variable override
            Path(os.getenv("COMMANDS_CONFIG_PATH", "")) if os.getenv("COMMANDS_CONFIG_PATH") else None
        ]
        
        for path in possible_paths:
            if path and path.exists():
                logger.info(f"Found configuration file at: {path}")
                return path
        
        # If no file found, create default in config directory
        config_dir = Path(__file__).parent.parent.parent / "config"
        config_dir.mkdir(exist_ok=True)
        default_path = config_dir / self.config_file
        
        logger.warning(f"Configuration file not found. Creating default at: {default_path}")
        self._create_default_config(default_path)
        return default_path
    
    def load_config(self):
        """Load configuration from YAML file with enhanced error handling."""
        try:
            config_path = self.get_config_path()
            
            with open(config_path, "r", encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                logger.warning("Empty configuration file, creating default")
                self._create_default_config(config_path)
                with open(config_path, "r", encoding='utf-8') as f:
                    raw_config = yaml.safe_load(f)
            
            self.config_data = self._transform_config(raw_config)
            self.comparison_commands = self._generate_comparison_commands(raw_config)
            self.supported_vendors = list(self.config_data.keys())
            
            logger.info(f"Configuration loaded successfully from {config_path}")
            logger.info(f"Supported vendors: {self.supported_vendors}")
            logger.debug(f"Available command categories: {self._get_all_categories()}")
            
            return self.config_data
            
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise
        except FileNotFoundError as e:
            logger.error(f"Configuration file not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading configuration: {e}")
            raise
    
    def _create_default_config(self, file_path: Path):
        """Create a comprehensive default configuration file."""
        default_config = {
            "arista_eos": {
                "system_info": [
                    "show version",
                    "show hostname",
                    "show inventory",
                    "show boot-config"
                ],
                "interfaces": [
                    "show interfaces",
                    "show interfaces status",
                    "show interfaces counters",
                    "show interfaces description"
                ],
                "routing": [
                    "show ip route summary",
                    "show ip route",
                    "show ipv6 route summary"
                ],
                "switching": [
                    "show mac address-table",
                    "show vlan",
                    "show spanning-tree",
                    "show port-channel summary"
                ],
                "protocols": [
                    "show ip ospf neighbor",
                    "show ip bgp summary",
                    "show lldp neighbors",
                    "show cdp neighbors"
                ],
                "monitoring": [
                    "show processes top",
                    "show processes cpu",
                    "show memory",
                    "show environment all"
                ],
                "mlag": [
                    "show mlag",
                    "show mlag config-sanity",
                    "show mlag interfaces"
                ],
                "security": [
                    "show ip access-lists",
                    "show aaa accounting",
                    "show users"
                ]
            },
            "cisco_ios": {
                "system_info": [
                    "show version",
                    "show running-config | include hostname",
                    "show inventory",
                    "show boot"
                ],
                "interfaces": [
                    "show interfaces",
                    "show ip interface brief",
                    "show interfaces status",
                    "show interfaces description"
                ],
                "routing": [
                    "show ip route summary",
                    "show ip route",
                    "show ipv6 route summary"
                ],
                "switching": [
                    "show mac address-table",
                    "show vlan brief",
                    "show spanning-tree summary",
                    "show etherchannel summary"
                ],
                "protocols": [
                    "show ip ospf neighbor",
                    "show ip bgp summary",
                    "show cdp neighbors",
                    "show lldp neighbors"
                ],
                "monitoring": [
                    "show processes cpu",
                    "show memory",
                    "show environment"
                ]
            },
            "cisco_nxos": {
                "system_info": [
                    "show version",
                    "show hostname",
                    "show inventory",
                    "show boot"
                ],
                "interfaces": [
                    "show interface",
                    "show interface brief",
                    "show interface status",
                    "show interface description"
                ],
                "routing": [
                    "show ip route summary",
                    "show ip route",
                    "show ipv6 route summary"
                ],
                "switching": [
                    "show mac address-table",
                    "show vlan",
                    "show spanning-tree summary",
                    "show port-channel summary"
                ],
                "protocols": [
                    "show ip ospf neighbors",
                    "show ip bgp summary",
                    "show cdp neighbors",
                    "show lldp neighbors"
                ],
                "monitoring": [
                    "show processes cpu",
                    "show system resources",
                    "show environment"
                ],
                "vpc": [
                    "show vpc",
                    "show vpc peer-keepalive",
                    "show vpc consistency-parameters"
                ]
            },
            "juniper_junos": {
                "system_info": [
                    "show version",
                    "show system information",
                    "show chassis hardware"
                ],
                "interfaces": [
                    "show interfaces terse",
                    "show interfaces extensive",
                    "show interfaces descriptions"
                ],
                "routing": [
                    "show route summary",
                    "show route protocol ospf",
                    "show route protocol bgp"
                ],
                "protocols": [
                    "show ospf neighbor",
                    "show bgp summary",
                    "show lldp neighbors"
                ],
                "monitoring": [
                    "show system processes extensive",
                    "show system memory",
                    "show chassis environment"
                ]
            }
        }
        
        try:
            with open(file_path, "w", encoding='utf-8') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2, sort_keys=False)
            logger.info(f"Created comprehensive default configuration file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to create default config: {e}")
            raise
    
    def _transform_config(self, raw_config):
        """Transform flat YAML config to nested structure."""
        if not raw_config:
            return {}
            
        transformed = {}
        
        for device_type, categories in raw_config.items():
            if isinstance(categories, dict):
                transformed[device_type] = categories
                logger.debug(f"Device type '{device_type}' has categories: {list(categories.keys())}")
            else:
                logger.warning(f"Invalid configuration structure for device type: {device_type}")
                
        return transformed
    
    def _generate_comparison_commands(self, raw_config):
        """Generate comparison commands dynamically from config."""
        comparison_commands = {}
        
        for device_type, categories in raw_config.items():
            if not isinstance(categories, dict):
                continue
                
            for category, commands in categories.items():
                # Skip system_info as it's not suitable for comparison
                if category == 'system_info':
                    continue
                
                # Create human-readable names and descriptions
                name_mapping = {
                    'interfaces': 'Interface Status & Counters',
                    'routing': 'Routing Tables',
                    'switching': 'Switching & VLANs',
                    'protocols': 'Network Protocols',
                    'monitoring': 'System Performance',
                    'mlag': 'MLAG Status',
                    'vpc': 'vPC Configuration',
                    'security': 'Security & Access Control',
                    'mac_address_table': 'MAC Address Table',
                    'ip_arp': 'IP ARP Table',
                    'interfaces_status': 'Interface Status',
                    'mlag_interfaces': 'MLAG Interfaces'
                }
                
                description_mapping = {
                    'interfaces': 'Compare interface configurations, status, and counters',
                    'routing': 'Compare routing tables and protocol information',
                    'switching': 'Compare VLAN configurations and spanning tree status',
                    'protocols': 'Compare network protocol neighbors and status',
                    'monitoring': 'Compare system performance metrics',
                    'mlag': 'Compare MLAG configuration and status',
                    'vpc': 'Compare vPC configuration and status',
                    'security': 'Compare security configurations and access lists',
                    'mac_address_table': 'Compare MAC address tables between snapshots',
                    'ip_arp': 'Compare ARP tables between snapshots',
                    'interfaces_status': 'Compare interface status between snapshots',
                    'mlag_interfaces': 'Compare MLAG interface details between snapshots'
                }
                
                comparison_commands[f"{device_type}_{category}"] = {
                    'name': name_mapping.get(category, category.replace('_', ' ').title()),
                    'commands': commands if isinstance(commands, list) else [commands],
                    'description': description_mapping.get(category, f'Compare {category.replace("_", " ")} between snapshots'),
                    'device_type': device_type,
                    'category': category
                }
                
                # For interfaces category, also add a base "interfaces" entry for comparison
                if category == 'interfaces':
                    comparison_commands['interfaces'] = {
                        'name': 'Interfaces',
                        'commands': commands if isinstance(commands, list) else [commands],
                        'description': 'Compare all interface data between snapshots',
                        'device_type': 'generic',
                        'category': 'interfaces'
                    }
        
        return comparison_commands
    
    def get_comparison_commands(self):
        """Get available comparison commands."""
        return self.comparison_commands
    
    def get_execution_commands(self):
        """Get available execution commands in the same format as comparison commands."""
        execution_commands = {}
        
        for device_type, categories in self.config_data.items():
            if not isinstance(categories, dict):
                continue
                
            for category, commands in categories.items():
                # Create human-readable names and descriptions for execution
                name_mapping = {
                    'system_info': 'System Information',
                    'interfaces': 'Interface Status & Counters',
                    'routing': 'Routing Tables',
                    'switching': 'Switching & VLANs',
                    'protocols': 'Network Protocols',
                    'monitoring': 'System Performance',
                    'mlag': 'MLAG Status',
                    'vpc': 'vPC Configuration',
                    'security': 'Security & Access Control'
                }
                
                description_mapping = {
                    'system_info': 'Collect system version, hostname, and inventory information',
                    'interfaces': 'Collect interface configurations, status, and counters',
                    'routing': 'Collect routing tables and protocol information',
                    'switching': 'Collect VLAN configurations and spanning tree status',
                    'protocols': 'Collect network protocol neighbors and status',
                    'monitoring': 'Collect system performance metrics',
                    'mlag': 'Collect MLAG configuration and status',
                    'vpc': 'Collect vPC configuration and status',
                    'security': 'Collect security configurations and access lists'
                }
                
                execution_commands[f"{device_type}_{category}"] = {
                    'name': name_mapping.get(category, category.replace('_', ' ').title()),
                    'commands': commands if isinstance(commands, list) else [commands],
                    'description': description_mapping.get(category, f'Collect {category.replace("_", " ")} information'),
                    'device_type': device_type,
                    'category': category
                }
        
        return execution_commands
    
    def get_commands_for_device(self, device_type: str):
        """Get commands for specific device type."""
        commands = self.config_data.get(device_type)
        if commands:
            logger.debug(f"Found {len(commands)} categories for device type '{device_type}'")
        else:
            logger.warning(f"No commands found for device type '{device_type}'")
            logger.debug(f"Available device types: {list(self.config_data.keys())}")
        return commands
    
    def get_supported_device_types(self):
        """Get list of supported device types."""
        return list(self.config_data.keys())
    
    def get_vendor_commands(self, vendor: str, category: Optional[str] = None):
        """Get commands for a specific vendor and optionally category."""
        vendor_config = self.config_data.get(vendor, {})
        
        if category:
            return vendor_config.get(category, [])
        
        return vendor_config
    
    def _get_all_categories(self):
        """Get all unique categories across all vendors."""
        categories = set()
        for vendor_config in self.config_data.values():
            if isinstance(vendor_config, dict):
                categories.update(vendor_config.keys())
        return sorted(list(categories))
    
    def reload_config(self):
        """Reload configuration from file."""
        logger.info("Reloading configuration...")
        self.load_config()
        return True
    
    def validate_config(self):
        """Validate the loaded configuration."""
        errors = []
        warnings = []
        
        if not self.config_data:
            errors.append("No configuration data loaded")
            return errors, warnings
        
        for device_type, categories in self.config_data.items():
            if not isinstance(categories, dict):
                errors.append(f"Invalid structure for device type '{device_type}': expected dict, got {type(categories)}")
                continue
            
            for category, commands in categories.items():
                if not isinstance(commands, list):
                    warnings.append(f"Commands for '{device_type}.{category}' should be a list")
                elif not commands:
                    warnings.append(f"No commands defined for '{device_type}.{category}'")
        
        return errors, warnings
    
    def get_config_info(self):
        """Get information about the loaded configuration."""
        return {
            "supported_vendors": self.supported_vendors,
            "total_categories": len(self._get_all_categories()),
            "total_comparison_commands": len(self.comparison_commands),
            "config_file_path": str(self.get_config_path()),
            "categories_by_vendor": {
                vendor: list(config.keys()) if isinstance(config, dict) else []
                for vendor, config in self.config_data.items()
            }
        }