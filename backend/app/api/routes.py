from flask import request, jsonify, send_file, send_from_directory, Response
from datetime import datetime
import json
import os
import uuid
import threading
import pandas as pd
from pathlib import Path
from io import StringIO
import queue
import logging

logger = logging.getLogger(__name__)

def register_routes(app, config_manager, device_manager, data_processor, processing_sessions, 
                   current_session_id, log_queue, streaming_handler, log_filename, 
                   threaded_process_devices, threaded_retry_failed_devices, 
                   allowed_file, validate_csv_columns, get_csv_separator_from_content,
                   detect_vendors_from_data, detect_device_type_by_model_static,
                   generate_comparison_chart_data, generate_comparison_summary_chart,
                   generate_comparison_by_command_chart, generate_comparison_by_device_chart,
                   create_snapshot_comparison_data, ProcessingSession, DeviceInfo, DeviceMetadata,
                   DEFAULT_TIMEOUT, EXCEL_ENGINE, API_ENDPOINTS):
    """Register all Flask routes."""
    
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
                    "max_workers": 10,
                    "default_timeout": DEFAULT_TIMEOUT,
                    "default_retry_attempts": 3,
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
        nonlocal current_session_id
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