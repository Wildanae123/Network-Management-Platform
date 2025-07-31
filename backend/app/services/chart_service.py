import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

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

# Alias functions for backward compatibility
generate_comparison_summary_chart = generate_comparison_summary_chart
generate_comparison_by_command_chart = generate_comparison_by_command_chart  
generate_comparison_by_device_chart = generate_comparison_by_device_chart