# backend/app/api/dashboard.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
from ..services.analytics_service import AnalyticsService
from ..services.monitoring_service import MonitoringService
from ..database import get_db
from ..models.device import Device, DeviceMetric, Alert
from ...utils.health_utils import get_health_color

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/performance")
async def get_performance_dashboard(
    time_range: str = Query("24h", description="Time range: 24h, 7d, 30d"),
    db: Session = Depends(get_db)
):
    """Get performance dashboard data"""
    try:
        analytics_service = AnalyticsService(db)
        dashboard_data = analytics_service.get_performance_dashboard_data(time_range)
        return {
            "status": "success",
            "data": dashboard_data,
            "time_range": time_range
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/topology")
async def get_network_topology(db: Session = Depends(get_db)):
    """Get network topology visualization data"""
    try:
        analytics_service = AnalyticsService(db)
        topology_data = analytics_service.get_network_topology_data()
        return {
            "status": "success",
            "data": topology_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/heatmap")
async def get_device_heatmap(
    metric_type: str = Query("health", description="Metric type: health, cpu, memory"),
    db: Session = Depends(get_db)
):
    """Get device heatmap data"""
    try:
        devices = db.query(Device).all()
        heatmap_data = []
        
        for device in devices:
            if metric_type == "health":
                value = device.health_score
                color = get_health_color(value)
            elif metric_type == "cpu":
                # Get latest CPU metric
                cpu_metric = db.query(DeviceMetric).filter(
                    DeviceMetric.device_id == device.id,
                    DeviceMetric.metric_type == "cpu"
                ).order_by(DeviceMetric.timestamp.desc()).first()
                value = cpu_metric.value if cpu_metric else 0
                color = get_usage_color(value)
            elif metric_type == "memory":
                # Get latest memory metric
                memory_metric = db.query(DeviceMetric).filter(
                    DeviceMetric.device_id == device.id,
                    DeviceMetric.metric_type == "memory"
                ).order_by(DeviceMetric.timestamp.desc()).first()
                value = memory_metric.value if memory_metric else 0
                color = get_usage_color(value)
            else:
                value = 0
                color = "#cccccc"
            
            heatmap_data.append({
                "device_id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "value": value,
                "color": color,
                "status": device.status
            })
        
        return {
            "status": "success",
            "data": heatmap_data,
            "metric_type": metric_type
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_usage_color(usage: float) -> str:
    """Get color based on usage percentage"""
    if usage < 50:
        return "#52c41a"  # Green
    elif usage < 70:
        return "#faad14"  # Yellow
    elif usage < 85:
        return "#fa8c16"  # Orange
    else:
        return "#f5222d"  # Red

@router.get("/alerts")
async def get_alerts_dashboard(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, description="Limit results"),
    db: Session = Depends(get_db)
):
    """Get alerts dashboard data"""
    try:
        query = db.query(Alert).order_by(Alert.created_at.desc())
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        if status:
            query = query.filter(Alert.status == status)
        
        alerts = query.limit(limit).all()
        
        # Group alerts by device
        device_alerts = {}
        for alert in alerts:
            device_id = alert.device_id
            if device_id not in device_alerts:
                device_alerts[device_id] = []
            device_alerts[device_id].append({
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "status": alert.status,
                "created_at": alert.created_at,
                "acknowledged_by": alert.acknowledged_by
            })
        
        return {
            "status": "success",
            "data": {
                "alerts": [
                    {
                        "id": alert.id,
                        "device_id": alert.device_id,
                        "device_hostname": alert.device.hostname,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                        "title": alert.title,
                        "description": alert.description,
                        "status": alert.status,
                        "created_at": alert.created_at
                    }
                    for alert in alerts
                ],
                "by_device": device_alerts,
                "summary": {
                    "total": len(alerts),
                    "critical": len([a for a in alerts if a.severity == "critical"]),
                    "high": len([a for a in alerts if a.severity == "high"]),
                    "medium": len([a for a in alerts if a.severity == "medium"]),
                    "low": len([a for a in alerts if a.severity == "low"])
                }
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/capacity")
async def get_capacity_dashboard(db: Session = Depends(get_db)):
    """Get capacity planning dashboard"""
    try:
        analytics_service = AnalyticsService(db)
        
        # Get recent metrics for capacity analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        metrics = db.query(DeviceMetric).filter(
            DeviceMetric.timestamp >= start_time,
            DeviceMetric.timestamp <= end_time
        ).all()
        
        capacity_data = analytics_service.get_capacity_analysis(metrics)
        
        return {
            "status": "success",
            "data": capacity_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/trends")
async def get_trends_dashboard(
    metric_type: str = Query("cpu", description="Metric type: cpu, memory, interface"),
    time_range: str = Query("7d", description="Time range: 24h, 7d, 30d"),
    db: Session = Depends(get_db)
):
    """Get trends dashboard data"""
    try:
        end_time = datetime.utcnow()
        
        if time_range == "24h":
            start_time = end_time - timedelta(hours=24)
        elif time_range == "7d":
            start_time = end_time - timedelta(days=7)
        elif time_range == "30d":
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(days=7)
        
        metrics = db.query(DeviceMetric).filter(
            DeviceMetric.metric_type == metric_type,
            DeviceMetric.timestamp >= start_time,
            DeviceMetric.timestamp <= end_time
        ).all()
        
        # Group by device
        device_trends = {}
        for metric in metrics:
            device_id = metric.device_id
            if device_id not in device_trends:
                device_trends[device_id] = []
            device_trends[device_id].append({
                "timestamp": metric.timestamp,
                "value": metric.value,
                "metric_name": metric.metric_name
            })
        
        return {
            "status": "success",
            "data": {
                "trends": device_trends,
                "metric_type": metric_type,
                "time_range": time_range
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))