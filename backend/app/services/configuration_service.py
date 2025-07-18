# backend/app/services/configuration_service.py
import hashlib
import difflib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from ..models.device import Device, Configuration, ConfigurationChange
from ..utils.network_utils import NetworkConnector
from ..core.ai_analyzer import AIAnalyzer
import logging

logger = logging.getLogger(__name__)

class ConfigurationService:
    def __init__(self, db: Session):
        self.db = db
        self.network_connector = NetworkConnector()
        self.ai_analyzer = AIAnalyzer()
    
    async def collect_device_configuration(self, device: Device) -> Dict:
        """Collect configuration from a device"""
        try:
            connection = await self.network_connector.connect(device)
            
            # Get running configuration
            running_config = await connection.execute_command("show running-config")
            
            # Get startup configuration
            startup_config = await connection.execute_command("show startup-config")
            
            configurations = {
                'running': running_config,
                'startup': startup_config
            }
            
            # Store configurations
            for config_type, content in configurations.items():
                if content:
                    await self.store_configuration(device, config_type, content)
            
            return configurations
            
        except Exception as e:
            logger.error(f"Error collecting configuration from {device.ip_address}: {str(e)}")
            raise
    
    async def store_configuration(self, device: Device, config_type: str, content: str):
        """Store device configuration with change detection"""
        # Calculate hash for change detection
        config_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Get latest configuration
        latest_config = self.db.query(Configuration).filter(
            Configuration.device_id == device.id,
            Configuration.config_type == config_type
        ).order_by(Configuration.collected_at.desc()).first()
        
        # Check if configuration has changed
        if latest_config and latest_config.hash == config_hash:
            logger.info(f"No configuration changes detected for {device.ip_address}")
            return
        
        # Create new configuration record
        new_config = Configuration(
            device_id=device.id,
            config_type=config_type,
            content=content,
            hash=config_hash,
            collected_at=datetime.utcnow()
        )
        
        if latest_config:
            new_config.parent_config_id = latest_config.id
        
        self.db.add(new_config)
        self.db.commit()
        
        # Analyze changes if there's a previous configuration
        if latest_config:
            await self.analyze_configuration_changes(latest_config, new_config)
    
    async def analyze_configuration_changes(self, old_config: Configuration, new_config: Configuration):
        """Analyze configuration changes and generate insights"""
        try:
            # Generate diff
            old_lines = old_config.content.splitlines()
            new_lines = new_config.content.splitlines()
            
            diff = list(difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"old_{old_config.config_type}",
                tofile=f"new_{new_config.config_type}",
                lineterm=''
            ))
            
            # Parse changes
            changes = self.parse_configuration_diff(diff)
            
            # Store changes
            for change in changes:
                change_record = ConfigurationChange(
                    configuration_id=new_config.id,
                    change_type=change['type'],
                    line_number=change['line_number'],
                    old_content=change['old_content'],
                    new_content=change['new_content'],
                    impact_level=change['impact_level']
                )
                
                # AI analysis
                analysis = await self.ai_analyzer.analyze_config_change(change)
                change_record.auto_analysis = analysis
                
                # Generate rollback suggestion
                rollback_suggestion = self.generate_rollback_suggestion(change)
                change_record.rollback_suggestion = rollback_suggestion
                
                self.db.add(change_record)
            
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Error analyzing configuration changes: {str(e)}")
    
    def parse_configuration_diff(self, diff: List[str]) -> List[Dict]:
        """Parse unified diff into structured changes"""
        changes = []
        line_number = 0
        
        for line in diff:
            if line.startswith('@@'):
                # Extract line number from diff header
                parts = line.split()
                if len(parts) >= 2:
                    line_info = parts[1].strip('-+')
                    line_number = int(line_info.split(',')[0])
                continue
            
            if line.startswith('-'):
                # Removed line
                changes.append({
                    'type': 'removed',
                    'line_number': line_number,
                    'old_content': line[1:],
                    'new_content': '',
                    'impact_level': self.assess_impact_level(line[1:])
                })
            elif line.startswith('+'):
                # Added line
                changes.append({
                    'type': 'added',
                    'line_number': line_number,
                    'old_content': '',
                    'new_content': line[1:],
                    'impact_level': self.assess_impact_level(line[1:])
                })
            
            line_number += 1
        
        return changes
    
    def assess_impact_level(self, config_line: str) -> str:
        """Assess the impact level of a configuration change"""
        line = config_line.strip().lower()
        
        # Critical impact keywords
        critical_keywords = [
            'shutdown', 'no shutdown', 'reload', 'reboot',
            'access-list', 'route-map', 'bgp', 'ospf',
            'spanning-tree', 'vlan', 'trunk'
        ]
        
        # High impact keywords
        high_keywords = [
            'interface', 'ip address', 'subnet', 'gateway',
            'snmp', 'ntp', 'dns', 'logging'
        ]
        
        # Medium impact keywords
        medium_keywords = [
            'description', 'banner', 'hostname', 'domain'
        ]
        
        for keyword in critical_keywords:
            if keyword in line:
                return 'critical'
        
        for keyword in high_keywords:
            if keyword in line:
                return 'high'
        
        for keyword in medium_keywords:
            if keyword in line:
                return 'medium'
        
        return 'low'
    
    def generate_rollback_suggestion(self, change: Dict) -> str:
        """Generate rollback suggestion for a configuration change"""
        if change['type'] == 'added':
            return f"To rollback: Remove line '{change['new_content']}'"
        elif change['type'] == 'removed':
            return f"To rollback: Add line '{change['old_content']}'"
        else:
            return f"To rollback: Change '{change['new_content']}' back to '{change['old_content']}'"
    
    def get_configuration_history(self, device_id: int, config_type: str = 'running') -> List[Dict]:
        """Get configuration history for a device"""
        configurations = self.db.query(Configuration).filter(
            Configuration.device_id == device_id,
            Configuration.config_type == config_type
        ).order_by(Configuration.collected_at.desc()).all()
        
        history = []
        for config in configurations:
            changes = self.db.query(ConfigurationChange).filter(
                ConfigurationChange.configuration_id == config.id
            ).all()
            
            history.append({
                'id': config.id,
                'collected_at': config.collected_at,
                'hash': config.hash,
                'changes_count': len(changes),
                'changes': [
                    {
                        'type': change.change_type,
                        'impact_level': change.impact_level,
                        'old_content': change.old_content,
                        'new_content': change.new_content,
                        'rollback_suggestion': change.rollback_suggestion
                    }
                    for change in changes
                ]
            })
        
        return history
    
    def compare_configurations(self, config1_id: int, config2_id: int) -> Dict:
        """Compare two configurations"""
        config1 = self.db.query(Configuration).get(config1_id)
        config2 = self.db.query(Configuration).get(config2_id)
        
        if not config1 or not config2:
            raise ValueError("Configuration not found")
        
        # Generate diff
        diff = list(difflib.unified_diff(
            config1.content.splitlines(),
            config2.content.splitlines(),
            fromfile=f"Config {config1.id}",
            tofile=f"Config {config2.id}",
            lineterm=''
        ))
        
        # Parse changes
        changes = self.parse_configuration_diff(diff)
        
        return {
            'config1': {
                'id': config1.id,
                'collected_at': config1.collected_at,
                'hash': config1.hash
            },
            'config2': {
                'id': config2.id,
                'collected_at': config2.collected_at,
                'hash': config2.hash
            },
            'changes': changes,
            'diff': diff
        }