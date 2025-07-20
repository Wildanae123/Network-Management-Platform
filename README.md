# Network Management Platform

A comprehensive enterprise network management platform that provides real-time monitoring, analytics, and automation for network infrastructure. Built with a modern microservices architecture featuring React frontend, Python backend, machine learning analytics, and Docker deployment capabilities.

## Features

### 🌐 Network Management
- **Multi-vendor API Support** - Arista eAPI, Cisco RESTCONF, and extensible architecture
- **Real-time Device Monitoring** - Live status tracking and health monitoring
- **Configuration Management** - Automated configuration deployment and backup
- **Batch Processing** - Efficient handling of large device inventories
- **Change Detection** - Automated configuration drift detection

### 📊 Analytics & Intelligence
- **Machine Learning Engine** - Predictive analytics for network performance
- **Data Processing Pipeline** - Automated data collection and analysis
- **Performance Predictions** - ML-based forecasting and anomaly detection
- **Interactive Dashboards** - Real-time visualization and reporting
- **Historical Trending** - Long-term performance analysis

### 🚀 Modern Architecture
- **Microservices Design** - Scalable and maintainable architecture
- **RESTful APIs** - Standard API interfaces for integration
- **Docker Support** - Containerized deployment and scaling
- **Event-driven Processing** - Asynchronous task handling
- **Plugin Architecture** - Extensible vendor and feature support

### 🔧 Management & Operations
- **Web-based Interface** - Modern React frontend with responsive design
- **Role-based Access** - Secure authentication and authorization
- **Audit Logging** - Comprehensive activity tracking
- **Export Capabilities** - Multiple format support (Excel, JSON, CSV)
- **Backup & Recovery** - Automated data protection

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Usage Guide](#usage-guide)
5. [Advanced Features](#advanced-features)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)
9. [API Documentation](#api-documentation)
10. [Building Standalone](#building-standalone)
11. [Support](#support)

## Requirements

### Software Requirements

- **Python 3.9+** - Required for backend services and ML analytics
- **Node.js 18+** - Required for frontend development and build process
- **Docker** (Optional) - For containerized deployment
- **PostgreSQL/SQLite** - Database backend (SQLite for development)

### System Requirements

- **Windows 10/11**, **macOS**, or **Linux** (Ubuntu 20.04+ recommended)
- **8GB RAM minimum** (16GB+ recommended for ML workloads)
- **50GB+ disk space** (for data storage and analytics)
- **Network access** to target devices via HTTPS/HTTP APIs
- **GPU support** (Optional) - For accelerated ML processing

### Core Dependencies

**Backend (Python):**
```
flask>=3.0.0
pandas>=2.1.0
numpy>=1.25.0
scikit-learn>=1.3.0
plotly>=5.17.0
sqlalchemy>=2.0.0
celery>=5.3.0
redis>=5.0.0
```

**Frontend (Node.js):**
```
react>=18.0.0
vite>=4.0.0
typescript>=5.0.0
tailwindcss>=3.3.0
```

### Supported Vendor APIs

- **Arista EOS** - eAPI (JSON-RPC)
- **Cisco IOS-XE** - RESTCONF
- **Cisco NX-OS** - REST API
- **More vendors** - Extensible architecture

## Installation

### Quick Setup (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/Network-Management-Platform.git
   cd Network-Management-Platform
   ```

2. **Run automated setup:**
   ```bash
   # Windows
   INSTALL.bat
   
   # Linux/macOS
   chmod +x required/setup.sh
   ./required/setup.sh
   ```

### Development Environment Setup

#### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Initialize database
python -m flask db init
python -m flask db migrate
python -m flask db upgrade
```

#### 2. Frontend Setup

```bash
cd frontend

# Install Node.js dependencies
npm install

# Build for development
npm run dev
```

#### 3. Analytics Setup

```bash
cd analytics

# Install analytics dependencies
pip install -r requirements.txt

# Initialize ML models
python ml_models/setup.py
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build standalone
docker build -t network-management-platform .
docker run -p 8080:8080 network-management-platform
```

#### 3. Configuration Setup

The application comes with a default commands.yaml file. You can customize it:

```yaml
arista_eos:
  mac_address_table:
    - "show mac address-table"
  ip_arp:
    - "show ip arp"
  interfaces_status:
    - "show interfaces status"
  mlag_interfaces:
    - "show mlag interfaces detail"
  system_info:
    - "show version"
    - "show hostname"
    - "show inventory"
```

## Getting Started

### Step 1: Prepare Your Device List

1. **Create a CSV file** with your device information:

   ```csv
   IP MGMT,Nama SW,SN,Model SW
   192.168.1.1,Switch-Core-01,ABC123456789,DCS-7050QX-32
   192.168.1.2,Switch-Access-01,DEF987654321,DCS-7020R-32
   ```

2. **Required CSV Columns:**

   - `IP MGMT` or `ip_mgmt` - Management IP address
   - `Nama SW` or `nama_sw` - Device hostname/name
   - `SN` or `sn` - Serial number
   - `Model SW` or `model_sw` - Device model

3. **Supported Column Variations:**
   - IP: `ip_mgmt`, `ip`, `management ip`, `mgmt_ip`, `device_ip`
   - Name: `nama_sw`, `name`, `hostname`, `device_name`, `switch_name`
   - Serial: `sn`, `serial`, `serial_number`, `serial number`, `serial_no`
   - Model: `model_sw`, `model`, `device_model`, `switch_model`

### Step 2: Start the Application

#### Option A:Development Mode

```bash
# Start both frontend and backend servers
START-HERE.bat

# This will open:
# - Frontend: http://localhost:5173
# - Backend: http://localhost:5000
# - Automatically open your browser
```

#### Option B: Standalone Mode (Recommended)

```bash
# Run the standalone executable
RUN-BUILD.bat
# OR directly:
dist\NetworkDataApp.exe

# This will:
# - Start the integrated application
# - Automatically open your browser to the interface
# - Run as a single process
```

### Step 3: Configure API Access

1. **Open the application** in your browser
2. **Enter API credentials:**
   - Username: Your device API username
   - Password: Your device API password

**Note:** The application uses vendor APIs (eAPI for Arista) instead of SSH

3. **Select commands to execute:**
   - Choose from available command categories
   - Default selections include system info, interfaces, MAC tables, etc.

### Step 4: Upload Device List

1. **Click "Upload CSV File"** or drag and drop your device list
2. **Review warnings** if any column issues are detected
3. **Verify device count** matches your expectations

### Step 5: Configure Authentication

1. **Enter API credentials:**
   - Username: Your device username
   - Password: Your device password
2. **These credentials** will be used for all devices in the list

### Step 6: Select Commands

1. **Choose commands to execute** from the available options:

   - **MAC Address Table** - Layer 2 forwarding information
   - **IP ARP Table** - Layer 3 address resolution
   - **Interface Status** - Port status and configuration
   - **MLAG Interfaces** - Multi-chassis LAG details
   - **System Info** - Device version and inventory

2. **All commands selected by default** - uncheck to exclude specific commands

### Step 7: Start Processing

1. **Click "Start API Collection"**
2. **Monitor real-time progress:**
   - Progress bar with percentage
   - Success/failure counts
   - Individual device status updates
   - Processing speed metrics

### Step 8: Review Results

1. **Check the results table** for:

   - ✅ **Successful connections** - API data collected
   - ❌ **Failed connections** - Connection or authentication errors
   - 🔄 **Retry attempts** - Automatic retry status
   - ⏱️ **Processing times** - Performance metrics

2. **View detailed data** by clicking "View" for successful devices
3. **Export results** to Excel for further analysis
4. **Compare snapshots:**
   - Select two different collection runs
   - Choose command category to compare
   - View detailed change analysis
   - Export comparison reports

### Advanced Usage

#### Retry Failed Devices

**When devices fail:**

1. After processing completes, **"Retry Failed Devices"** button appears
2. Click to reprocess only failed devices
3. Results are merged with existing successful data
4. Failed devices get additional retry attempts

#### Real-time Monitoring

**Progress tracking includes:**

- Overall completion percentage
- Devices processed/remaining
- Success/failure rates
- API response times
- Connection status per device

#### Stop Processing

**To halt processing:**

1. Click **"Stop Processing"** button
2. System gracefully stops after current batch
3. Completed results are preserved
4. Partial results can be exported

## Advanced Features

### 1. Data Filtering and Search

**Filter results by:**

- **Status:** Success/Failed
- **Model:** Device model/type
- **Connection Status:** API connection state

**Search functionality:**

- Real-time search across IP, hostname, and model
- Case-insensitive matching
- Instant results filtering

### 2. Snapshot Comparison

**Compare device states over time:**

1. **Click "Compare Snapshots"**
2. **Select two data collection files**
3. **Choose command category** to compare
4. **Review detailed differences:**
   - Added entries (MAC addresses, ARP entries, etc.)
   - Removed entries
   - Status changes
   - Configuration drift

**Comparison features:**

- Excel export of comparison results
- Device-by-device change analysis
- Summary statistics
- Change categorization

### 3. File Management

**Output Files Manager:**

- View all collected data files
- Download individual files
- Delete old files
- File metadata (size, date, device count)
- Search and filter files

### 4. System Monitoring

**Real-time Logs:**

- Live log streaming during processing
- Filter by log level (INFO, WARNING, ERROR)
- Auto-scroll functionality
- Log clearing capability
- System health monitoring

### 5. Visual Analytics

**Dashboard features:**

- Interactive charts and graphs
- Device distribution by model
- Success/failure analysis
- Processing time metrics
- Customizable grouping options

### 6. Export and Reporting

**Multiple export formats:**

- **Excel exports** with structured data
- **JSON files** for programmatic access
- **Comparison reports** showing changes
- **Metadata inclusion** (timestamps, command selection)

## Configuration

### API Endpoints Configuration

The application automatically detects and configures API endpoints:

**Arista EOS (eAPI):**

- Endpoint: `/command-api`
- Protocol: HTTPS (default) / HTTP
- Port: 443 (HTTPS) / 80 (HTTP)
- Content-Type: `application/json-rpc`

**Cisco IOS-XE (RESTCONF):**

- Endpoint: `/restconf/data`
- Protocol: HTTPS
- Port: 443
- Content-Type: `application/yang-data+json`

### Custom Commands

Edit `backend/commands.yaml` to customize commands:

```yaml
arista_eos:
  # Custom command category
  custom_monitoring:
    - "show processes top"
    - "show version detail"
    - "show environment all"

  # Security commands
  security_status:
    - "show aaa"
    - "show ip access-lists"
    - "show management api http-commands"

  # Performance monitoring
  performance:
    - "show interfaces counters"
    - "show system memory"
    - "show processes cpu"
```

### Application Settings

**Default configuration values:**

- **Timeout:** 30 seconds per device
- **Max Workers:** 10 concurrent connections
- **Retry Attempts:** 3 attempts per failed device
- **Output Directory:** `backend/output/`
- **Protocol:** HTTPS (fallback to HTTP if needed)

## Troubleshooting

### Common Issues

#### "Backend Connection Failed"

**Symptoms:** Frontend shows disconnected status

**Solutions:**

```bash
# Check if Flask server is running
netstat -an | findstr :5000

# Restart backend server
cd backend
python server.py

# Check Windows Firewall settings
# Allow Python through Windows Firewall
```

#### "API Authentication Failed"

**Symptoms:** All devices show authentication errors

**Solutions:**

- Verify API credentials are correct
- Check if eAPI/RESTCONF is enabled on devices
- Ensure proper user privileges for API access
- Test manual API connection: `curl -k https://device_ip/command-api`

#### "Connection Timeout"

**Symptoms:** Devices show timeout errors

**Solutions:**

- Check network connectivity: `ping device_ip`
- Verify API port accessibility (443/80)
- Check device API configuration
- Increase timeout value if needed

#### "CSV Parsing Errors"

**Symptoms:** "Error reading CSV file"

**Solutions:**

- Check CSV file encoding (UTF-8 recommended)
- Verify column headers match requirements
- Remove special characters from device names
- Ensure all required columns are present

#### "Memory Issues with Large Files"

**Symptoms:** Application crashes with many devices

**Solutions:**

- Process in smaller batches (50-100 devices)
- Increase available RAM
- Close other applications
- Use 64-bit Python version

### Log Files and Debugging

**Log locations:**

- **Backend logs:** `backend/logs/network_fetcher_dev.log`
- **Frontend logs:** Browser Developer Console (F12)
- **Real-time logs:** Available in application UI

**Enable debug logging:**

```python
# In server.py, change log level
logging.basicConfig(level=logging.DEBUG)
```

### Network Requirements

**Required connectivity:**

- **HTTPS/HTTP access** to device management interfaces
- **DNS resolution** for device hostnames (if used)
- **Firewall rules** allowing outbound API calls
- **Sufficient bandwidth** for concurrent connections

**Test API connectivity:**

```bash
# Test Arista eAPI
curl -k -X POST https://device_ip/command-api \
  -H "Content-Type: application/json-rpc" \
  -d '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"test"}' \
  -u username:password

# Test basic connectivity
telnet device_ip 443
nmap -p 443,80 device_ip
```

## Best Practices

### 1. Security Considerations

**Protect API credentials:**

- Use dedicated service accounts with minimal privileges
- Enable API access only on management interfaces
- Use HTTPS whenever possible
- Monitor API access logs on devices
- Implement proper certificate validation

### 2. Performance Optimization

**Speed up processing:**

- Use wired network connections for stability
- Adjust concurrent worker count based on system capacity
- Optimize API timeout values for your network
- Process during low-traffic periods
- Monitor system resources during large collections

### 3. Data Management

**Organize your data:**

- Use consistent device naming conventions
- Create dated backup folders for collections
- Export results regularly to avoid data loss
- Document configuration changes
- Maintain accurate device inventory

### 4. Operational Planning

**Before starting large collections:**

- Test with small device samples first
- Verify credentials on representative devices
- Schedule during maintenance windows
- Plan for processing time based on device count
- Prepare rollback procedures if needed

### 5. Monitoring and Maintenance

**Regular tasks:**

- Review failed device logs for patterns
- Update device credentials as needed
- Clean old export files to save space
- Monitor API rate limits on devices
- Update application dependencies

## API Documentation

### REST Endpoints

**System Information:**

```http
GET /api/system_info
```

**File Upload:**

```http
POST /api/upload_csv
Content-Type: multipart/form-data
```

**Start Processing:**

```json
POST /api/process_devices
Content-Type: application/json
{
  "username": "admin",
  "password": "password",
  "filepath": "/path/to/devices.csv",
  "selected_commands": ["mac_address_table", "ip_arp"]
}
```

**Processing Status:**

```http
GET /api/processing_status/{session_id}
```

**Compare Snapshots:**

```json
POST /api/compare_snapshots
Content-Type: application/json
{
  "first_file": "snapshot1.json",
  "second_file": "snapshot2.json",
  "command_category": "mac_address_table"
}
```

**Output Files:**

```http
GET /api/output_files
GET /api/output_files/{filename}
DELETE /api/output_files/{filename}
```

### WebSocket Events

**Real-time log streaming:**

```http
GET /api/logs/stream
Content-Type: text/event-stream
```

### Building Standalone

**Create Executable**

```bash
# Build standalone application
python build_standalone.py
```

**Build process includes:**

- **Frontend compilation** (if Node.js available)
- **Python dependency installation**
- **PyInstaller executable creation**
- **Asset bundling and optimization**

**Output:** `dist/NetworkDataApp.exe` - Single file executable

### Distribution

**The standalone executable:**

- No installation required
- Includes all dependencies
- Works on Windows without Python
- Self-contained with web interface
- Portable across similar systems

### Integration Examples

**1. Automated Monitoring**
**Schedule regular collections:**

```phyton
# scheduled_collection.py
from apscheduler.schedulers.blocking import BlockingScheduler
import requests
import json

def daily_collection():
    # Upload device list
    with open('devices.csv', 'rb') as f:
        files = {'file': f}
        upload_response = requests.post('http://localhost:5000/api/upload_csv', files=files)

    # Start processing
    process_data = {
        'username': 'admin',
        'password': 'password',
        'filepath': upload_response.json()['filepath'],
        'selected_commands': ['mac_address_table', 'interfaces_status']
    }
    requests.post('http://localhost:5000/api/process_devices', json=process_data)

scheduler = BlockingScheduler()
scheduler.add_job(daily_collection, 'cron', hour=2)  # 2 AM daily
scheduler.start()
```

**2. Change Detection**
**Monitor configuration changes:**

```python
# change_detector.py
import json
from datetime import datetime, timedelta

def detect_changes():
    # Get recent snapshots
    files_response = requests.get('http://localhost:5000/api/output_files')
    files = files_response.json()['data']

    # Compare last two collections
    if len(files) >= 2:
        recent_files = sorted(files, key=lambda x: x['modified'])[-2:]

        compare_data = {
            'first_file': recent_files[0]['filename'],
            'second_file': recent_files[1]['filename'],
            'command_category': 'mac_address_table'
        }

        comparison = requests.post('http://localhost:5000/api/compare_snapshots', json=compare_data)

        # Process changes and send alerts
        if comparison.json()['status'] == 'success':
            changes = [device for device in comparison.json()['data']
                      if device['compare_result']['status'] != 'no_changes']

            if changes:
                send_change_alert(changes)

def send_change_alert(changes):
    # Send email, ticket, or notification
    print(f"Detected {len(changes)} devices with configuration changes")
```

**3. Asset Management Integration**
**Update CMDB with collected data:**

```python
# cmdb_integration.py
def update_cmdb(collection_file):
    with open(collection_file) as f:
        data = json.load(f)

    for device in data['results']:
        if device['status'] == 'Success':
            cmdb_record = {
                'ci_name': device['nama_sw'],
                'ip_address': device['ip_mgmt'],
                'serial_number': device['sn'],
                'model': device['model_sw'],
                'last_discovered': device['last_attempt'],
                'management_status': 'reachable'
            }
            # Update CMDB via API
            update_cmdb_record(cmdb_record)
```

### Support

**Getting Help**

- **Check this documentation** for common solutions
- **Review log files** for detailed error information
- **Test with minimal configurations** to isolate issues
- **Verify network connectivity** independently
- **Check device API configurations** manually

### System Requirements Check

**Verify your environment:**

```bash
# Check Python version
python --version

# Check required packages
pip list | grep -E "(flask|pandas|plotly|jsonrpclib)"

# Test network connectivity
ping target_device_ip
curl -k https://target_device_ip

# Check available memory
# Windows: wmic computersystem get TotalPhysicalMemory
# Linux: free -h
```

### Performance Monitoring

**Monitor during large collections:**

```bash
# Windows Task Manager
# Monitor Python memory usage and CPU

# Linux system monitoring
top -p $(pgrep python)

# Network interface statistics
netstat -i
```

### Community Resources

- **GitHub Repository:** Latest updates and issue tracking
- **API Documentation:** Swagger/OpenAPI specifications
- **Video Tutorials:** Step-by-step usage guides
- **Vendor Documentation:** Device API configuration guides

## Analytics & Machine Learning

### Predictive Analytics

The platform includes advanced ML capabilities for network performance prediction:

- **Performance Forecasting** - Predict network utilization and capacity planning
- **Anomaly Detection** - Identify unusual patterns in network behavior  
- **Failure Prediction** - Early warning system for potential device failures
- **Trend Analysis** - Historical performance analysis and reporting

### Data Processing Pipeline

```bash
# Start analytics processing
cd analytics
python data_processing/pipeline.py

# Train ML models
python ml_models/train.py --model performance_predictor

# Generate predictions
python predictions/forecast.py --horizon 7d
```

### Supported Analytics

- **Traffic Analysis** - Bandwidth utilization patterns
- **Device Health Scoring** - ML-based device reliability metrics
- **Configuration Drift Detection** - Automated change analysis
- **Performance Baseline** - Dynamic threshold establishment

## Deployment Options

### 1. Docker Deployment (Production)

```bash
# Production deployment with Docker Compose
docker-compose -f docker/docker-compose.prod.yml up -d

# Scale services
docker-compose scale backend=3 analytics=2
```

### 2. Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -f deployment/k8s/

# Monitor deployment
kubectl get pods -n network-management
```

### 3. Cloud Deployment

**AWS/Azure/GCP Ready:**
- Auto-scaling backend services
- Managed database integration
- Container orchestration
- Load balancer configuration

### 4. Standalone Executable

```bash
# Build standalone executable
python required/build_standalone.py

# Run standalone version
./dist/NetworkManagementPlatform.exe
```

## Configuration Management

### Environment Configuration

Create `.env` file in the root directory:

```env
# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/netmgmt
REDIS_URL=redis://localhost:6379

# API Configuration  
API_TIMEOUT=30
MAX_CONCURRENT_CONNECTIONS=50

# Security
JWT_SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key

# Analytics
ML_MODEL_PATH=./analytics/ml_models/trained/
PREDICTION_INTERVAL=300

# Monitoring
LOG_LEVEL=INFO
METRICS_ENABLED=true
```

### Device Configuration

Configure network device access in `backend/config/devices.yaml`:

```yaml
device_types:
  arista_eos:
    api_endpoint: "/command-api"
    auth_method: "basic"
    default_port: 443
    
  cisco_iosxe:
    api_endpoint: "/restconf/data"
    auth_method: "basic"
    default_port: 443

monitoring:
  health_check_interval: 60
  retry_attempts: 3
  timeout: 30
```

**Note:** This application connects to network devices via their management APIs (eAPI, RESTCONF, etc.) and requires proper API access configuration. Always follow your organization's security policies and ensure appropriate network access controls are in place.

## Project Architecture

```
Network-Management-Platform/
├── analytics/                  # Machine Learning & Data Analytics
│   ├── data_processing/        # Data ingestion and transformation pipelines
│   ├── ml_models/             # Machine learning models and training scripts
│   └── predictions/           # Predictive analytics and forecasting
│
├── backend/                   # Python Backend Services
│   ├── app/                   # Core application modules
│   │   ├── api/               # RESTful API endpoints
│   │   │   └── dashboard.py   # Dashboard API controllers
│   │   ├── core/              # Core business logic
│   │   │   ├── config.py      # Application configuration
│   │   │   ├── config_manager.py # Configuration management
│   │   │   └── ml_engine.py   # Machine learning integration
│   │   ├── models/            # Data models and schemas
│   │   │   └── device.py      # Device model definitions
│   │   ├── services/          # Business logic services
│   │   │   ├── analytics_service.py    # Analytics processing
│   │   │   ├── configuration_service.py # Config management
│   │   │   └── monitoring_service.py   # Device monitoring
│   │   └── utils/             # Utility functions and helpers
│   ├── config/                # Configuration files
│   │   ├── commands.yaml      # Network device commands
│   │   ├── database.py        # Database configuration
│   │   └── settings.py        # Application settings
│   ├── migrations/            # Database migration scripts
│   ├── tests/                 # Backend test suites
│   ├── utils/                 # Backend utilities
│   │   ├── health_utils.py    # Health check utilities
│   │   └── ssl_utils.py       # SSL/TLS utilities
│   ├── venv/                  # Python virtual environment
│   ├── requirements.txt       # Python dependencies
│   ├── server.py              # Main Flask application server
│   └── test_connection.py     # Connection testing utility
│
├── deployment/                # Deployment configurations
│   └── (deployment scripts and configs)
│
├── docker/                    # Docker containerization
│   └── Dockerfile             # Docker image definition
│
├── docs/                      # Project documentation
│   └── (technical documentation)
│
├── frontend/                  # React Frontend Application
│   ├── public/                # Static public assets
│   ├── src/                   # React source code
│   │   ├── components/        # Reusable UI components
│   │   │   └── Dashboard/     # Dashboard components
│   │   │       └── TopologyWidget.jsx
│   │   ├── config/            # Frontend configuration
│   │   │   └── environment.js # Environment settings
│   │   ├── hooks/             # Custom React hooks
│   │   ├── pages/             # Page components
│   │   │   ├── Dashboard.jsx  # Main dashboard page
│   │   │   └── DeviceManagement.jsx # Device management page
│   │   ├── services/          # API service layer
│   │   │   └── apiService.js  # API communication
│   │   ├── styles/            # CSS and styling
│   │   │   └── global.css     # Global styles
│   │   ├── utils/             # Frontend utilities
│   │   ├── App.jsx            # Main React application
│   │   └── main.jsx           # Application entry point
│   ├── node_modules/          # Node.js dependencies (gitignored)
│   ├── package.json           # Node.js project configuration
│   ├── package-lock.json      # Dependency lock file
│   └── vite.config.js         # Vite build configuration
│
├── output/                    # Generated output files (gitignored)
│   └── *.log                  # Application logs
│
├── required/                  # Build and deployment scripts
│   ├── build_standalone.py    # Standalone executable builder
│   └── start.sh               # Application startup script
│
├── uploads/                   # User uploaded files (gitignored)
│   └── *.csv                  # Device inventory files
│
├── .gitignore                 # Git ignore rules
├── INSTALL.bat                # Windows installation script
├── LICENSE                    # Project license
├── railway.json               # Railway deployment configuration
├── README.md                  # Project documentation
├── RUN-BUILD.bat              # Windows build and run script
└── START-HERE.bat             # Quick start script
```
