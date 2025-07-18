# backend/app/services/monitoring_service.py
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models.device import Device, DeviceMetric, Alert, HealthCheck
from ..utils.network_utils import NetworkConnector
from ..core.ml_engine import MLEngine
from ...utils.health_utils import get_health_status, get_health_color, calculate_device_health_score
import logging

logger = logging.getLogger(__name__)

class MonitoringService:
    def __init__(self, db: Session):
        self.db = db
        self.ml_engine = MLEngine()
        self.network_connector = NetworkConnector()
        
    async def monitor_all_devices(self):
        """Main monitoring loop for all devices"""
        devices = self.db.query(Device).filter(Device.monitoring_enabled == True).all()
        
        tasks = []
        for device in devices:
            task = asyncio.create_task(self.monitor_device(device))
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def monitor_device(self, device: Device):
        """Monitor a single device comprehensively"""
        try:
            # Collect metrics
            metrics = await self.collect_device_metrics(device)
            
            # Store metrics
            await self.store_metrics(device, metrics)
            
            # Analyze health
            health_score = await self.analyze_device_health(device, metrics)
            
            # Update device status
            await self.update_device_status(device, health_score)
            
            # Check for anomalies
            await self.detect_anomalies(device, metrics)
            
            # Predict failures
            await self.predict_failures(device, metrics)
            
        except Exception as e:
            logger.error(f"Error monitoring device {device.ip_address}: {str(e)}")
            await self.create_alert(device, "monitoring_error", "error", 
                                  f"Monitoring failed: {str(e)}")
    
    async def collect_device_metrics(self, device: Device) -> Dict:
        """Collect comprehensive metrics from device"""
        metrics = {}
        
        try:
            # Connect to device
            connection = await self.network_connector.connect(device)
            
            # CPU metrics
            cpu_data = await connection.execute_command("show processes cpu")
            metrics['cpu'] = self.parse_cpu_metrics(cpu_data)
            
            # Memory metrics
            memory_data = await connection.execute_command("show memory")
            metrics['memory'] = self.parse_memory_metrics(memory_data)
            
            # Interface metrics
            interface_data = await connection.execute_command("show interfaces")
            metrics['interfaces'] = self.parse_interface_metrics(interface_data)
            
            # Performance metrics
            performance_data = await connection.execute_command("show version")
            metrics['performance'] = self.parse_performance_metrics(performance_data)
            
            # Environmental metrics (if supported)
            try:
                env_data = await connection.execute_command("show environment")
                metrics['environment'] = self.parse_environment_metrics(env_data)
            except:
                pass  # Not all devices support environmental monitoring
            
        except Exception as e:
            logger.error(f"Failed to collect metrics from {device.ip_address}: {str(e)}")
            raise
        
        return metrics
    
    async def analyze_device_health(self, device: Device, metrics: Dict) -> float:
        """Analyze overall device health and calculate score"""
        health_factors = {}
        
        # CPU health (0-100)
        cpu_usage = metrics.get('cpu', {}).get('usage', 0)
        if cpu_usage < 70:
            health_factors['cpu'] = 100
        elif cpu_usage < 85:
            health_factors['cpu'] = 50
        else:
            health_factors['cpu'] = 0
        
        # Memory health (0-100)
        memory_usage = metrics.get('memory', {}).get('usage_percent', 0)
        if memory_usage < 80:
            health_factors['memory'] = 100
        elif memory_usage < 90:
            health_factors['memory'] = 50
        else:
            health_factors['memory'] = 0
        
        # Interface health (0-100)
        interface_health = self.calculate_interface_health(metrics.get('interfaces', {}))
        health_factors['interfaces'] = interface_health
        
        # Environmental health (0-100)
        env_health = self.calculate_environmental_health(metrics.get('environment', {}))
        health_factors['environment'] = env_health
        
        # Calculate weighted average
        weights = {'cpu': 0.3, 'memory': 0.3, 'interfaces': 0.3, 'environment': 0.1}
        total_score = sum(health_factors[factor] * weights[factor] 
                         for factor in health_factors if factor in weights)
        
        # Store health check
        health_check = HealthCheck(
            device_id=device.id,
            check_type='comprehensive',
            status=get_health_status(total_score),
            score=total_score,
            details=health_factors,
            checked_at=datetime.utcnow()
        )
        self.db.add(health_check)
        self.db.commit()
        
        return total_score
    
    def calculate_interface_health(self, interfaces: Dict) -> float:
        """Calculate interface health score"""
        if not interfaces:
            return 100
        
        total_score = 0
        interface_count = 0
        
        for interface_name, interface_data in interfaces.items():
            if interface_data.get('admin_status') == 'up':
                interface_count += 1
                
                # Check link status
                if interface_data.get('link_status') == 'up':
                    score = 100
                else:
                    score = 0
                
                # Check error rates
                error_rate = interface_data.get('error_rate', 0)
                if error_rate > 0.1:  # 0.1% error rate threshold
                    score *= 0.5
                
                # Check utilization
                utilization = interface_data.get('utilization', 0)
                if utilization > 90:
                    score *= 0.7
                elif utilization > 80:
                    score *= 0.8
                
                total_score += score
        
        return total_score / interface_count if interface_count > 0 else 100
    
    def calculate_environmental_health(self, environment: Dict) -> float:
        """Calculate environmental health score"""
        if not environment:
            return 100
        
        score = 100
        
        # Temperature checks
        temp = environment.get('temperature', 0)
        if temp > 70:  # Critical temperature
            score *= 0.5
        elif temp > 60:  # Warning temperature
            score *= 0.8
        
        # Power supply checks
        power_supplies = environment.get('power_supplies', [])
        for ps in power_supplies:
            if ps.get('status') != 'ok':
                score *= 0.7
        
        # Fan checks
        fans = environment.get('fans', [])
        for fan in fans:
            if fan.get('status') != 'ok':
                score *= 0.8
        
        return score
    
    
    async def detect_anomalies(self, device: Device, metrics: Dict):
        """Detect anomalies using ML models"""
        try:
            # Get historical data
            historical_metrics = self.get_historical_metrics(device.id, days=30)
            
            # Use ML model to detect anomalies
            anomalies = await self.ml_engine.detect_anomalies(device.id, metrics, historical_metrics)
            
            # Create alerts for anomalies
            for anomaly in anomalies:
                await self.create_alert(
                    device,
                    'anomaly_detected',
                    anomaly['severity'],
                    f"Anomaly detected in {anomaly['metric']}: {anomaly['description']}"
                )
        
        except Exception as e:
            logger.error(f"Error detecting anomalies for {device.ip_address}: {str(e)}")
    
    async def predict_failures(self, device: Device, metrics: Dict):
        """Predict potential failures using ML models"""
        try:
            # Get historical data
            historical_data = self.get_historical_metrics(device.id, days=90)
            
            # Use ML model for prediction
            prediction = await self.ml_engine.predict_failure(device.id, metrics, historical_data)
            
            if prediction['failure_probability'] > 0.7:  # High probability threshold
                await self.create_alert(
                    device,
                    'failure_prediction',
                    'warning',
                    f"Potential failure predicted: {prediction['description']} "
                    f"(Probability: {prediction['failure_probability']:.2%})"
                )
        
        except Exception as e:
            logger.error(f"Error predicting failures for {device.ip_address}: {str(e)}")
    
    async def create_alert(self, device: Device, alert_type: str, severity: str, description: str):
        """Create a new alert"""
        alert = Alert(
            device_id=device.id,
            alert_type=alert_type,
            severity=severity,
            title=f"{alert_type.replace('_', ' ').title()} - {device.hostname}",
            description=description,
            created_at=datetime.utcnow()
        )
        self.db.add(alert)
        self.db.commit()
    
    def get_historical_metrics(self, device_id: int, days: int = 30) -> List[Dict]:
        """Get historical metrics for analysis"""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        metrics = self.db.query(DeviceMetric).filter(
            DeviceMetric.device_id == device_id,
            DeviceMetric.timestamp >= start_date
        ).all()
        
        return [
            {
                'metric_type': m.metric_type,
                'metric_name': m.metric_name,
                'value': m.value,
                'timestamp': m.timestamp
            }
            for m in metrics
        ]