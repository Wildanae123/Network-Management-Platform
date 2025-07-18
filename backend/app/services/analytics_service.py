# backend/app/services/analytics_service.py
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models.device import Device, DeviceMetric, Alert
from ..core.ml_engine import MLEngine
import logging

logger = logging.getLogger(__name__)

class AnalyticsService:
    def __init__(self, db: Session):
        self.db = db
        self.ml_engine = MLEngine()
    
    def get_performance_dashboard_data(self, time_range: str = '24h') -> Dict:
        """Get comprehensive performance dashboard data"""
        end_time = datetime.utcnow()
        
        if time_range == '24h':
            start_time = end_time - timedelta(hours=24)
        elif time_range == '7d':
            start_time = end_time - timedelta(days=7)
        elif time_range == '30d':
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(hours=24)
        
        # Get metrics data
        metrics = self.db.query(DeviceMetric).filter(
            DeviceMetric.timestamp >= start_time,
            DeviceMetric.timestamp <= end_time
        ).all()
        
        # Process data
        dashboard_data = {
            'overview': self.get_overview_metrics(metrics),
            'performance_trends': self.get_performance_trends(metrics),
            'capacity_analysis': self.get_capacity_analysis(metrics),
            'top_devices': self.get_top_devices_analysis(metrics),
            'alerts_summary': self.get_alerts_summary(start_time, end_time),
            'health_distribution': self.get_health_distribution(),
            'network_topology': self.get_network_topology_data()
        }
        
        return dashboard_data
    
    def get_overview_metrics(self, metrics: List[DeviceMetric]) -> Dict:
        """Get overview metrics for dashboard"""
        df = pd.DataFrame([
            {
                'device_id': m.device_id,
                'metric_type': m.metric_type,
                'metric_name': m.metric_name,
                'value': m.value,
                'timestamp': m.timestamp
            }
            for m in metrics
        ])
        
        if df.empty:
            return {
                'total_devices': 0,
                'avg_cpu_usage': 0,
                'avg_memory_usage': 0,
                'total_interfaces': 0,
                'active_alerts': 0
            }
        
        # Calculate overview metrics
        total_devices = df['device_id'].nunique()
        
        cpu_metrics = df[df['metric_type'] == 'cpu']
        avg_cpu_usage = cpu_metrics['value'].mean() if not cpu_metrics.empty else 0
        
        memory_metrics = df[df['metric_type'] == 'memory']
        avg_memory_usage = memory_metrics['value'].mean() if not memory_metrics.empty else 0
        
        interface_metrics = df[df['metric_type'] == 'interface']
        total_interfaces = interface_metrics['device_id'].value_counts().sum() if not interface_metrics.empty else 0
        
        # Active alerts
        active_alerts = self.db.query(Alert).filter(Alert.status == 'active').count()
        
        return {
            'total_devices': total_devices,
            'avg_cpu_usage': round(avg_cpu_usage, 2),
            'avg_memory_usage': round(avg_memory_usage, 2),
            'total_interfaces': total_interfaces,
            'active_alerts': active_alerts
        }
    
    def get_performance_trends(self, metrics: List[DeviceMetric]) -> Dict:
        """Get performance trends over time"""
        df = pd.DataFrame([
            {
                'device_id': m.device_id,
                'metric_type': m.metric_type,
                'value': m.value,
                'timestamp': m.timestamp
            }
            for m in metrics
        ])
        
        if df.empty:
            return {'cpu_trend': [], 'memory_trend': [], 'interface_trend': []}
        
        # Group by time intervals
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        
        # Resample to hourly averages
        cpu_trend = df[df['metric_type'] == 'cpu'].resample('1H')['value'].mean()
        memory_trend = df[df['metric_type'] == 'memory'].resample('1H')['value'].mean()
        interface_trend = df[df['metric_type'] == 'interface'].resample('1H')['value'].mean()
        
        return {
            'cpu_trend': [
                {'timestamp': ts.isoformat(), 'value': val}
                for ts, val in cpu_trend.items() if not pd.isna(val)
            ],
            'memory_trend': [
                {'timestamp': ts.isoformat(), 'value': val}
                for ts, val in memory_trend.items() if not pd.isna(val)
            ],
            'interface_trend': [
                {'timestamp': ts.isoformat(), 'value': val}
                for ts, val in interface_trend.items() if not pd.isna(val)
            ]
        }
    
    def get_capacity_analysis(self, metrics: List[DeviceMetric]) -> Dict:
        """Analyze capacity and predict future needs"""
        df = pd.DataFrame([
            {
                'device_id': m.device_id,
                'metric_type': m.metric_type,
                'value': m.value,
                'timestamp': m.timestamp
            }
            for m in metrics
        ])
        
        if df.empty:
            return {
                'capacity_utilization': [],
                'growth_predictions': [],
                'capacity_alerts': []
            }
        
        # Calculate capacity utilization
        capacity_data = []
        for device_id in df['device_id'].unique():
            device_metrics = df[df['device_id'] == device_id]
            
            cpu_usage = device_metrics[device_metrics['metric_type'] == 'cpu']['value'].mean()
            memory_usage = device_metrics[device_metrics['metric_type'] == 'memory']['value'].mean()
            
            capacity_data.append({
                'device_id': device_id,
                'cpu_utilization': cpu_usage,
                'memory_utilization': memory_usage,
                'overall_utilization': (cpu_usage + memory_usage) / 2
            })
        
        # Growth predictions using simple linear regression
        growth_predictions = []
        for device_id in df['device_id'].unique():
            device_metrics = df[df['device_id'] == device_id]
            
            # CPU growth prediction
            cpu_data = device_metrics[device_metrics['metric_type'] == 'cpu']
            if len(cpu_data) > 1:
                cpu_growth = self.calculate_growth_rate(cpu_data)
                growth_predictions.append({
                    'device_id': device_id,
                    'metric': 'cpu',
                    'current_value': cpu_data['value'].iloc[-1],
                    'predicted_30d': cpu_data['value'].iloc[-1] + (cpu_growth * 30),
                    'predicted_90d': cpu_data['value'].iloc[-1] + (cpu_growth * 90)
                })
        
        # Capacity alerts
        capacity_alerts = []
        for item in capacity_data:
            if item['overall_utilization'] > 80:
                capacity_alerts.append({
                    'device_id': item['device_id'],
                    'type': 'high_utilization',
                    'message': f"Device {item['device_id']} has high utilization ({item['overall_utilization']:.1f}%)"
                })
        
        return {
            'capacity_utilization': capacity_data,
            'growth_predictions': growth_predictions,
            'capacity_alerts': capacity_alerts
        }
    
    def calculate_growth_rate(self, data: pd.DataFrame) -> float:
        """Calculate simple growth rate"""
        if len(data) < 2:
            return 0
        
        data = data.sort_values('timestamp')
        first_value = data['value'].iloc[0]
        last_value = data['value'].iloc[-1]
        time_diff = (data['timestamp'].iloc[-1] - data['timestamp'].iloc[0]).days
        
        if time_diff == 0:
            return 0
        
        return (last_value - first_value) / time_diff
    
    def get_top_devices_analysis(self, metrics: List[DeviceMetric]) -> Dict:
        """Get top devices by various metrics"""
        df = pd.DataFrame([
            {
                'device_id': m.device_id,
                'metric_type': m.metric_type,
                'value': m.value
            }
            for m in metrics
        ])
        
        if df.empty:
            return {
                'top_cpu_users': [],
                'top_memory_users': [],
                'most_active_interfaces': []
            }
        
        # Top CPU users
        cpu_data = df[df['metric_type'] == 'cpu'].groupby('device_id')['value'].mean().sort_values(ascending=False)
        top_cpu_users = [
            {'device_id': device_id, 'cpu_usage': usage}
            for device_id, usage in cpu_data.head(10).items()
        ]
        
        # Top memory users
        memory_data = df[df['metric_type'] == 'memory'].groupby('device_id')['value'].mean().sort_values(ascending=False)
        top_memory_users = [
            {'device_id': device_id, 'memory_usage': usage}
            for device_id, usage in memory_data.head(10).items()
        ]
        
        # Most active interfaces
        interface_data = df[df['metric_type'] == 'interface'].groupby('device_id')['value'].sum().sort_values(ascending=False)
        most_active_interfaces = [
            {'device_id': device_id, 'interface_activity': activity}
            for device_id, activity in interface_data.head(10).items()
        ]
        
        return {
            'top_cpu_users': top_cpu_users,
            'top_memory_users': top_memory_users,
            'most_active_interfaces': most_active_interfaces
        }
    
    def get_alerts_summary(self, start_time: datetime, end_time: datetime) -> Dict:
        """Get alerts summary for the time period"""
        alerts = self.db.query(Alert).filter(
            Alert.created_at >= start_time,
            Alert.created_at <= end_time
        ).all()
        
        # Group by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Group by type
        type_counts = {}
        for alert in alerts:
            alert_type = alert.alert_type
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        return {
            'total_alerts': len(alerts),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'active_alerts': len([a for a in alerts if a.status == 'active'])
        }
    
    def get_health_distribution(self) -> Dict:
        """Get health distribution across all devices"""
        devices = self.db.query(Device).all()
        
        health_distribution = {'healthy': 0, 'warning': 0, 'critical': 0, 'unknown': 0}
        
        for device in devices:
            if device.health_score >= 80:
                health_distribution['healthy'] += 1
            elif device.health_score >= 60:
                health_distribution['warning'] += 1
            elif device.health_score > 0:
                health_distribution['critical'] += 1
            else:
                health_distribution['unknown'] += 1
        
        return health_distribution
    
    def get_network_topology_data(self) -> Dict:
        """Get network topology data for visualization"""
        from ..models.device import NetworkTopology
        
        devices = self.db.query(Device).all()
        connections = self.db.query(NetworkTopology).all()
        
        nodes = []
        for device in devices:
            nodes.append({
                'id': device.id,
                'label': device.hostname or device.ip_address,
                'ip': device.ip_address,
                'status': device.status,
                'health_score': device.health_score,
                'vendor': device.vendor,
                'model': device.model
            })
        
        edges = []
        for connection in connections:
            edges.append({
                'from': connection.source_device_id,
                'to': connection.destination_device_id,
                'label': f"{connection.source_interface} → {connection.destination_interface}",
                'bandwidth': connection.bandwidth,
                'latency': connection.latency,
                'utilization': connection.utilization
            })
        
        return {
            'nodes': nodes,
            'edges': edges
        }