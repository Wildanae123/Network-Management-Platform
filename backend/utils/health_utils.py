# backend/utils/health_utils.py
"""
Shared health status calculation utilities to eliminate code duplication.
"""

def get_health_status(score: float) -> str:
    """
    Get health status based on score.
    
    Args:
        score: Health score (0-100)
        
    Returns:
        Status string: 'healthy', 'warning', or 'critical'
    """
    if score >= 80:
        return 'healthy'
    elif score >= 60:
        return 'warning'
    else:
        return 'critical'

def get_health_color(score: float) -> str:
    """
    Get color hex code based on health score.
    
    Args:
        score: Health score (0-100)
        
    Returns:
        Hex color code
    """
    status = get_health_status(score)
    color_map = {
        'healthy': '#52c41a',  # Green
        'warning': '#faad14',  # Yellow
        'critical': '#f5222d'  # Red
    }
    return color_map[status]

def calculate_device_health_score(metrics: dict) -> float:
    """
    Calculate overall health score based on device metrics.
    
    Args:
        metrics: Dictionary containing device metrics
        
    Returns:
        Health score (0-100)
    """
    # Default implementation - can be extended based on specific metrics
    if not metrics:
        return 0.0
    
    # Example scoring logic - adjust based on your metrics
    cpu_score = 100 - min(metrics.get('cpu_usage', 0), 100)
    memory_score = 100 - min(metrics.get('memory_usage', 0), 100)
    interface_score = metrics.get('interface_utilization', 0)
    
    # Weighted average
    weights = {'cpu': 0.3, 'memory': 0.3, 'interface': 0.4}
    total_score = (
        cpu_score * weights['cpu'] +
        memory_score * weights['memory'] +
        interface_score * weights['interface']
    )
    
    return max(0, min(100, total_score))