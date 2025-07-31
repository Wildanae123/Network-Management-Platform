import json
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import asdict
import logging

logger = logging.getLogger(__name__)

# Constants
DEFAULT_OUTPUT_DIR = Path("./outputs")
EXCEL_ENGINE = "openpyxl"

class DataProcessor:
    """Data processor with enhanced filtering and comparison capabilities."""
    
    def __init__(self, output_dir: str = str(DEFAULT_OUTPUT_DIR)):
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
                for interface_name, interface_info in self._extract_interface_data(cmd_result):
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

    def _extract_interface_data(self, cmd_result):
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
            
            if command_category == "interfaces_status" or command_category == "interfaces":
                differences = self._compare_interfaces_enhanced(first_data, second_data)
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
            if command_category == "interfaces" and "status" in specific_command:
                differences = self._compare_interface_status_specific(first_data, second_data, specific_command)
            else:
                # Generic comparison for all other categories
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

# CSV validation functions
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