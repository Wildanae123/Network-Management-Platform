# backend/server_refactored.py

import uuid
import concurrent.futures
from flask import Flask
from flask_cors import CORS
from app.core.config_manager import ConfigManager

# Import separated components
from app.services.api_service import NetworkDeviceAPIManager
from app.services.data_service import DataProcessor
from app.api.routes import register_routes
from app.services.chart_service import (
    generate_comparison_chart_data,
    generate_comparison_summary_chart,
    generate_comparison_by_command_chart,
    generate_comparison_by_device_chart,
    create_snapshot_comparison_data
)
from utils.config_utils import (
    setup_logging,
    create_processing_session,
    get_processing_session,
    processing_sessions,
    current_session_id,
    log_queue,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TIMEOUT,
    MAX_WORKERS,
    EXCEL_ENGINE,
    API_ENDPOINTS,
    DeviceInfo,
    DeviceMetadata,
    ProcessingSession,
    allowed_file,
    validate_csv_columns,
    get_csv_separator_from_content,
    detect_vendors_from_data,
    detect_device_type_by_model_static
)
from utils.threading_utils import process_devices_worker, retry_failed_devices_worker

def create_app():
    """Create and configure the Flask application."""
    # Create Flask app with proper configuration for packaging
    import sys
    if getattr(sys, 'frozen', False):
        # If running as PyInstaller bundle
        template_folder = os.path.join(sys._MEIPASS, '../frontend/dist')
        static_folder = os.path.join(sys._MEIPASS, '../frontend/dist')
        app = Flask(__name__, static_folder=static_folder, template_folder=template_folder)
    else:
        # If running in development
        app = Flask(__name__, static_folder='../frontend/dist', static_url_path='')

    CORS(app, origins=["http://localhost:5173", "http://127.0.0.1:5173"])
    
    # Configure file upload
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    
    # Setup logging
    streaming_handler, log_filename = setup_logging()
    
    # Initialize core components
    config_manager = ConfigManager()
    device_manager = NetworkDeviceAPIManager()
    data_processor = DataProcessor()
    
    # Threading functions
    def threaded_process_devices(username: str, password: str, file_content: str, 
                               session_id: str, selected_commands: list = None, 
                               retry_failed_only: bool = False):
        """Process devices in a separate thread."""
        return process_devices_worker(
            username, password, file_content, session_id, selected_commands,
            retry_failed_only, device_manager, data_processor, processing_sessions
        )
    
    def threaded_retry_failed_devices(username: str, password: str, 
                                    failed_devices: list, session_id: str):
        """Retry failed devices in a separate thread."""
        return retry_failed_devices_worker(
            username, password, failed_devices, session_id, 
            device_manager, data_processor, processing_sessions
        )
    
    # Register all routes with all required dependencies
    register_routes(
        app=app,
        config_manager=config_manager,
        device_manager=device_manager,
        data_processor=data_processor,
        processing_sessions=processing_sessions,
        current_session_id=current_session_id,
        log_queue=log_queue,
        streaming_handler=streaming_handler,
        log_filename=log_filename,
        threaded_process_devices=threaded_process_devices,
        threaded_retry_failed_devices=threaded_retry_failed_devices,
        allowed_file=allowed_file,
        validate_csv_columns=validate_csv_columns,
        get_csv_separator_from_content=get_csv_separator_from_content,
        detect_vendors_from_data=detect_vendors_from_data,
        detect_device_type_by_model_static=detect_device_type_by_model_static,
        generate_comparison_chart_data=generate_comparison_chart_data,
        generate_comparison_summary_chart=generate_comparison_summary_chart,
        generate_comparison_by_command_chart=generate_comparison_by_command_chart,
        generate_comparison_by_device_chart=generate_comparison_by_device_chart,
        create_snapshot_comparison_data=create_snapshot_comparison_data,
        ProcessingSession=ProcessingSession,
        DeviceInfo=DeviceInfo,
        DeviceMetadata=DeviceMetadata,
        DEFAULT_TIMEOUT=DEFAULT_TIMEOUT,
        EXCEL_ENGINE=EXCEL_ENGINE,
        API_ENDPOINTS=API_ENDPOINTS
    )
    
    return app

def main():
    """Main entry point for the application."""
    app = create_app()
    
    # Start the Flask development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )

if __name__ == '__main__':
    main()