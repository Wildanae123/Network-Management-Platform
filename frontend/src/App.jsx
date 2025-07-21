import React, { useState, useEffect, useCallback, useMemo } from "react";
import Plot from "react-plotly.js";
import {
  Upload,
  Key,
  Play,
  FileText,
  Download,
  BarChart2,
  Server,
  X,
  Loader2,
  StopCircle,
  RefreshCw,
  Filter,
  GitCompare,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  TrendingUp,
  Eye,
  Search,
  Moon,
  Sun,
  File,
  CloudUpload,
  FolderOpen,
  Trash2,
  Terminal,
  Activity,
  AlertCircle,
  Info,
  Settings,
} from "lucide-react";
import "./styles/global.css";

// --- Constants for flexibility ---
const STATUS = {
  IDLE: "idle",
  LOADING: "loading",
  SUCCESS: "success",
  ERROR: "error",
  INFO: "info",
  PROCESSING: "processing",
  STOPPED: "stopped",
};

const ALERT_TYPES = {
  INFO: "info",
  ERROR: "error",
  SUCCESS: "success",
  WARNING: "warning",
};

const DEVICE_STATUS = {
  PENDING: "pending",
  CONNECTING: "connecting",
  SUCCESS: "success",
  FAILED: "failed",
  RETRYING: "retrying",
  STOPPED: "stopped",
};

const MESSAGES = {
  INITIALIZING: "Initializing Backend...",
  API_READY: "Ready. Please provide credentials and upload device file.",
  PROCESSING: "Processing, please wait...",
  AWAITING_FILE: "Please upload a CSV file with device list...",
  PROCESS_FINISHED: "Process finished.",
};

// Environment Detection
const isDevelopment =
  process.env.NODE_ENV === "development" ||
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";
const API_BASE_URL = isDevelopment ? "/api" : "/api";

console.log(`Running in ${isDevelopment ? "development" : "production"} mode`);

// API Helper Functions
const api = {
  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const config = {
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("text/html")) {
        throw new Error(
          `Server returned HTML instead of JSON. Status: ${response.status}`
        );
      }

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error("API request failed:", error);
      throw error;
    }
  },

  async getSystemInfo() {
    if (isDevelopment && window.pywebview) {
      return await window.pywebview.api.get_system_info();
    } else {
      return this.request("/system_info");
    }
  },

  async getComparisonCommands() {
    return this.request("/comparison_commands");
  },

  async getFilteredCommands(deviceData, commandType = "execution") {
    return this.request("/commands_filtered", {
      method: "POST",
      body: JSON.stringify({
        device_data: deviceData,
        command_type: commandType,
      }),
    });
  },

  async generateComparisonChart(data, chartType) {
    return this.request("/generate_comparison_chart", {
      method: "POST",
      body: JSON.stringify({
        comparison_data: data,
        chart_type: chartType,
      }),
    });
  },

  async uploadCsvFile(file) {
    try {
      const formData = new FormData();
      formData.append("file", file);

      const url = `${API_BASE_URL}/upload_csv`;

      const response = await fetch(url, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error("File upload failed:", error);
      throw error;
    }
  },

  async processDevicesFromFile(
    username,
    password,
    fileContent = null,
    selectedCommands = [],
    retryFailedOnly = false
  ) {
    if (isDevelopment && window.pywebview && !fileContent) {
      return await window.pywebview.api.process_devices_from_file(
        username,
        password
      );
    } else {
      return this.request("/process_devices", {
        method: "POST",
        body: JSON.stringify({
          username,
          password,
          file_content: fileContent,
          selected_commands: selectedCommands,
          retry_failed_only: retryFailedOnly,
        }),
      });
    }
  },

  async getProcessingStatus(sessionId) {
    if (isDevelopment && !sessionId) {
      return null;
    } else {
      return this.request(`/processing_status/${sessionId}`);
    }
  },

  async stopProcessing(sessionId) {
    if (isDevelopment && sessionId) {
      return this.request(`/stop_processing/${sessionId}`, {
        method: "POST",
      });
    } else {
      return null;
    }
  },

  async retryFailedDevices(username, password, results) {
    if (isDevelopment && window.pywebview) {
      return null;
    } else {
      return this.request("/retry_failed", {
        method: "POST",
        body: JSON.stringify({ username, password, results }),
      });
    }
  },

  async filterResults(results, filterType, filterValue) {
    if (isDevelopment && window.pywebview) {
      return { status: "success", data: results };
    } else {
      return this.request("/filter_results", {
        method: "POST",
        body: JSON.stringify({
          results,
          filter_type: filterType,
          filter_value: filterValue,
        }),
      });
    }
  },

  async compareFiles() {
    if (isDevelopment && window.pywebview) {
      return await window.pywebview.api.compare_data_files();
    } else {
      return this.request("/compare_files", {
        method: "POST",
      });
    }
  },

  async compareSnapshots(firstFile, secondFile, commandCategory) {
    return this.request("/compare_snapshots", {
      method: "POST",
      body: JSON.stringify({
        first_file: firstFile,
        second_file: secondFile,
        command_category: commandCategory,
      }),
    });
  },

  async getOutputFiles() {
    return this.request("/output_files");
  },

  async downloadFile(filename) {
    const url = `${API_BASE_URL}/output_files/${filename}`;

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  },

  async exportToExcel(data, exportType = "detailed") {
    if (isDevelopment && window.pywebview) {
      return await window.pywebview.api.export_to_excel(data);
    } else {
      try {
        const url = `${API_BASE_URL}/export_excel`;

        const response = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ data, export_type: exportType }),
        });

        if (response.ok) {
          const blob = await response.blob();
          const downloadUrl = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.style.display = "none";
          a.href = downloadUrl;
          a.download = `network_data_export_${new Date()
            .toISOString()
            .slice(0, 10)}.xlsx`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(downloadUrl);
          document.body.removeChild(a);
          return { status: "success", message: "File downloaded successfully" };
        } else {
          throw new Error("Export failed");
        }
      } catch (error) {
        throw new Error(`Export error: ${error.message}`);
      }
    }
  },

  async generateChartData(data, filterBy) {
    if (isDevelopment && window.pywebview) {
      return await window.pywebview.api.generate_chart_data(data, filterBy);
    } else {
      return this.request("/generate_chart", {
        method: "POST",
        body: JSON.stringify({ data, filter_by: filterBy }),
      });
    }
  },

  async getProgressChart(sessionId) {
    if (isDevelopment && sessionId) {
      return this.request(`/progress_chart/${sessionId}`);
    } else {
      return null;
    }
  },

  // Set up log streaming
  setupLogStream(onLogReceived) {
    const eventSource = new EventSource(`${API_BASE_URL}/logs/stream`);

    eventSource.onmessage = function (event) {
      try {
        const logData = JSON.parse(event.data);
        if (logData.type !== "heartbeat") {
          onLogReceived(logData);
        }
      } catch (error) {
        console.error("Error parsing log data:", error);
      }
    };

    eventSource.onerror = function (error) {
      console.error("Log stream error:", error);
    };

    return eventSource;
  },
};

// --- Helper Components ---

// File Upload Component with enhanced requirements display
const FileUploadComponent = ({
  onFileUpload,
  disabled,
  uploadedFile,
  onFileRemove,
}) => {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);

      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        onFileUpload(e.dataTransfer.files[0]);
      }
    },
    [onFileUpload]
  );

  const handleChange = useCallback(
    (e) => {
      e.preventDefault();
      if (e.target.files && e.target.files[0]) {
        onFileUpload(e.target.files[0]);
      }
    },
    [onFileUpload]
  );

  return (
    <div className="file-upload-container">
      {!uploadedFile ? (
        <>
          <div
            className={`file-upload-area ${dragActive ? "drag-active" : ""} ${
              disabled ? "disabled" : ""
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              accept=".csv"
              onChange={handleChange}
              disabled={disabled}
              className="file-input"
            />
            <label htmlFor="file-upload" className="file-upload-label">
              <CloudUpload size={48} className="upload-icon" />
              <div className="upload-text">
                <h4>Upload CSV File</h4>
                <p>
                  Drag and drop your device list CSV file here, or click to
                  browse
                </p>
                <small>Supported format: CSV files only</small>
              </div>
            </label>
          </div>
          <div className="upload-requirements">
            <h4>CSV Requirements:</h4>
            <ul>
              <li>
                <strong>Required:</strong> IP MGMT (IP address)
              </li>
            </ul>
          </div>
        </>
      ) : (
        <div className="uploaded-file-info">
          <div className="file-success">
            <File size={24} className="file-icon" />
            <div className="file-details">
              <h4>File Uploaded Successfully</h4>
              <p>{uploadedFile.name}</p>
              <small>{uploadedFile.deviceCount} devices found</small>
              {uploadedFile.detectedVendors &&
                uploadedFile.detectedVendors.length > 0 && (
                  <small className="detected-vendors">
                    Vendors: {uploadedFile.detectedVendors.join(", ")}
                  </small>
                )}
            </div>
            {onFileRemove && (
              <button
                className="remove-file-btn"
                onClick={onFileRemove}
                disabled={disabled}
                aria-label="Remove file"
              >
                <X size={16} />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const FileUploadComponentWithWarnings = ({
  onFileUpload,
  disabled,
  uploadedFile,
  onFileRemove,
}) => {
  return (
    <div className="file-upload-wrapper">
      <FileUploadComponent
        onFileUpload={onFileUpload}
        disabled={disabled}
        uploadedFile={uploadedFile}
        onFileRemove={onFileRemove}
      />
      {uploadedFile?.warnings && uploadedFile.warnings.length > 0 && (
        <div className="upload-warnings">
          <AlertTriangle size={16} />
          <span>{uploadedFile.warnings.length} warnings found in CSV</span>
        </div>
      )}
    </div>
  );
};

// Command Selection Component
const CommandSelectionComponent = ({
  availableCommands,
  selectedCommands,
  onCommandChange,
  disabled,
}) => {
  const totalCommands = Object.keys(availableCommands).length;
  const selectedCount = selectedCommands.length;
  const isAllSelected = selectedCount === totalCommands && totalCommands > 0;
  const isIndeterminate = selectedCount > 0 && selectedCount < totalCommands;

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      // Select all commands
      onCommandChange(Object.keys(availableCommands));
    } else {
      // Deselect all commands
      onCommandChange([]);
    }
  };

  const handleCommandChange = (commandKey, checked) => {
    if (checked) {
      onCommandChange([...selectedCommands, commandKey]);
    } else {
      onCommandChange(selectedCommands.filter((cmd) => cmd !== commandKey));
    }
  };

  return (
    <div className="command-selection">
      <div className="command-selection-header">
        <h4>Select Commands to Execute:</h4>
        <div className="select-all-container">
          <label className="select-all-checkbox">
            <input
              type="checkbox"
              checked={isAllSelected}
              ref={(el) => {
                if (el) el.indeterminate = isIndeterminate;
              }}
              onChange={handleSelectAll}
              disabled={disabled}
            />
            <span>
              Select All ({selectedCount}/{totalCommands})
            </span>
          </label>
        </div>
      </div>
      <div className="command-grid">
        {Object.entries(availableCommands).map(([key, command]) => (
          <label key={key} className="command-checkbox">
            <input
              type="checkbox"
              checked={selectedCommands.includes(key)}
              onChange={(e) => handleCommandChange(key, e.target.checked)}
              disabled={disabled}
            />
            <div className="command-info">
              <strong>{command.name}</strong>
              <p>{command.description}</p>
              <small>Commands: {command.commands.join(", ")}</small>
            </div>
          </label>
        ))}
      </div>
    </div>
  );
};

// Loading Overlay Component with Progress Bar
const LoadingOverlay = ({ message, isVisible, apiStatus, progress }) => {
  if (!isVisible) return null;

  return (
    <div className="loading-overlay">
      <div className="loading-content">
        <Loader2 size={48} className="loading-spinner-icon animate-spin" />
        <h2>Network Data App</h2>
        <p>{message}</p>
        {progress && (
          <div className="progress-container">
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${progress.percentage || 0}%` }}
              ></div>
            </div>
            <div className="progress-text">
              {progress.completed || 0} / {progress.total || 0} devices (
              {progress.percentage || 0}%)
            </div>
          </div>
        )}
        <div className="api-status-indicator">
          <div className={`status-dot ${apiStatus}`}></div>
          <span className="status-text">
            {apiStatus === "connecting" && "Connecting to Backend..."}
            {apiStatus === "ready" && "Backend Connected"}
            {apiStatus === "error" && "Connection Failed"}
          </span>
        </div>
        <div className="loading-dots">
          <span></span>
          <span></span>
          <span></span>
        </div>
      </div>
    </div>
  );
};

// Alert component
const Alert = ({ info, onClose }) => {
  React.useEffect(() => {
    if (info) {
      document.documentElement.classList.add('modal-open');
      document.body.classList.add('modal-open');
    } else {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    }
    
    return () => {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    };
  }, [info]);

  if (!info) return null;
  return (
    <div className="alert-dialog-backdrop" onClick={onClose}>
      <div
        className={`alert-dialog alert-${info.type}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="alert-header">
          <h3>
            {info.type === "error" && <XCircle size={20} />}
            {info.type === "success" && <CheckCircle size={20} />}
            {info.type === "warning" && <AlertTriangle size={20} />}
            {info.type === "info" && <TrendingUp size={20} />}
            Notification
          </h3>
          <button
            className="alert-close-btn"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={24} />
          </button>
        </div>
        <p className="alert-message" style={{ whiteSpace: 'pre-line' }}>{info.message}</p>
        <button className="alert-ok-button" onClick={onClose}>
          OK
        </button>
      </div>
    </div>
  );
};

// Modal for showing detailed data
const DetailModal = ({ data, onClose, title = "Device Command Output" }) => {
  React.useEffect(() => {
    if (data) {
      document.documentElement.classList.add('modal-open');
      document.body.classList.add('modal-open');
    } else {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    }
    
    return () => {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    };
  }, [data]);

  if (!data) return null;
  const formattedData =
    typeof data === "object" ? JSON.stringify(data, null, 2) : String(data);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content large-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>{title}</h2>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <pre className="detail-content">{formattedData}</pre>
        </div>
      </div>
    </div>
  );
};

// Helper function to get device change summary
const getDeviceChangeSummary = (commandResults) => {
  let totalAdded = 0;
  let totalRemoved = 0;
  let totalModified = 0;

  Object.values(commandResults).forEach((result) => {
    if (result.statistics) {
      totalAdded +=
        result.statistics.added_count ||
        result.statistics.added_interfaces ||
        0;
      totalRemoved +=
        result.statistics.removed_count ||
        result.statistics.removed_interfaces ||
        0;
      totalModified +=
        result.statistics.modified_count ||
        result.statistics.modified_interfaces ||
        0;
    }

    // Also check for direct arrays in case statistics are not available
    if (result.added) {
      totalAdded += result.added.length;
    }
    if (result.removed) {
      totalRemoved += result.removed.length;
    }
    if (result.modified) {
      totalModified += result.modified.length;
    }
  });

  return {
    added: totalAdded,
    removed: totalRemoved,
    modified: totalModified,
    total: totalAdded + totalRemoved + totalModified,
  };
};

// Redesigned File Comparison Modal
const ComparisonModal = ({ comparisonData, onClose, onDownloadExcel }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCommand, setSelectedCommand] = useState("all");

  React.useEffect(() => {
    if (comparisonData) {
      document.documentElement.classList.add('modal-open');
      document.body.classList.add('modal-open');
    } else {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    }
    
    return () => {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    };
  }, [comparisonData]);

  if (!comparisonData) return null;

  // Filter devices based on search term
  const filteredData =
    comparisonData.data?.filter(
      (device) =>
        device.ip_mgmt?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        device.hostname?.toLowerCase().includes(searchTerm.toLowerCase())
    ) || [];

  // Get only commands that were actually compared (user selected commands)
  const availableCommands = comparisonData.available_commands || [];

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content xl-modal comparison-modal-redesigned"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>
            <GitCompare size={24} />
            File Comparison Results
          </h2>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body">
          {/* Top Section - Summary and Filters in one row */}
          <div className="comparison-top-section">
            {/* Comparison Summary */}
            <div className="comparison-summary-redesigned">
              <div>
                <div className="summary-row">
                  <span>Comparing:</span>
                  <strong>{comparisonData.first_file}</strong> vs{" "}
                  <strong>{comparisonData.second_file}</strong>
                </div>
                <div className="summary-row">
                  <span>Total devices:</span>
                  <strong>{comparisonData.total_compared}</strong>
                </div>
              </div>
              <button
                className="download-button-redesigned"
                onClick={onDownloadExcel}
              >
                <Download size={16} />
                Download Excel Report
              </button>
            </div>

            {/* Filter Section */}
            <div className="filter-commands-section">
              <div className="filter-header">
                <h3>Filters</h3>
              </div>
              <div className="filter-controls">
                <div className="search-box-redesigned">
                  <Search size={16} />
                  <input
                    type="text"
                    placeholder="Search devices..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                <div className="filter-group">
                  <label>Command:</label>
                  <select
                    value={selectedCommand}
                    onChange={(e) => setSelectedCommand(e.target.value)}
                    className="command-filter-select"
                  >
                    <option value="all">All Commands</option>
                    {availableCommands.map((cmd) => (
                      <option key={cmd} value={cmd}>
                        {cmd.replace("_", " ").toUpperCase()}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Device List - Scrollable with wider view */}
          <div className="device-comparison-list">
            <div className="device-list-header">
              <span className="device-column">Device</span>
              <span className="status-column">Status</span>
              <span className="changes-column">Changes Summary</span>
            </div>
            <div className="device-list-scrollable">
              {filteredData.map((device, index) => (
                <div key={index} className="device-comparison-row">
                  <div className="device-info">
                    <div className="device-ip">{device.ip_mgmt}</div>
                    <div className="device-hostname">{device.hostname}</div>
                    <div className="device-change-badges">
                      {(() => {
                        const changeSummary = getDeviceChangeSummary(
                          device.command_results || {}
                        );
                        return (
                          <>
                            {changeSummary.added > 0 && (
                              <span className="change-badge added">
                                <span className="badge-icon">+</span>
                                {changeSummary.added} Added
                              </span>
                            )}
                            {changeSummary.removed > 0 && (
                              <span className="change-badge removed">
                                <span className="badge-icon">-</span>
                                {changeSummary.removed} Removed
                              </span>
                            )}
                            {changeSummary.modified > 0 && (
                              <span className="change-badge modified">
                                <span className="badge-icon">~</span>
                                {changeSummary.modified} Changed
                              </span>
                            )}
                            {changeSummary.total === 0 && (
                              <span className="change-badge no-changes">
                                <span className="badge-icon">✓</span>
                                No Changes
                              </span>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  </div>
                  <div className="device-status">
                    <span
                      className={`status-indicator ${device.overall_status?.toLowerCase()}`}
                    >
                      {device.overall_status}
                    </span>
                  </div>
                  <div className="device-changes">
                    {Object.entries(device.command_results || {}).map(
                      ([command, result]) => {
                        if (
                          selectedCommand !== "all" &&
                          command !== selectedCommand
                        ) {
                          return null;
                        }
                        return (
                          <div key={command} className="command-result-summary">
                            <div className="command-name">
                              {command.replace("_", " ").toUpperCase()}
                            </div>
                            <div className="change-stats">
                              {(() => {
                                // Helper function to format change items with detailed interface properties
                                const formatChangeItem = (item, changeType, command) => {
                                  if (typeof item === 'string') {
                                    // Enhanced string processing for interface patterns
                                    if (item.includes('Interface') && item.includes('Ethernet')) {
                                      // Extract interface name and action from string like "Interface Ethernet3 added"
                                      const match = item.match(/Interface\s+(Ethernet\d+)\s+(added|removed|modified|changed)/i);
                                      if (match) {
                                        const [, interfaceName, action] = match;
                                        
                                        // Determine interface property type based on command context
                                        if (command && command.includes('show interfaces status')) {
                                          return `Interface status ${interfaceName} ${action}`;
                                        } else if (command && command.includes('show interfaces counters')) {
                                          return `Interface counters ${interfaceName} ${action}`;
                                        } else if (command && command.includes('show interfaces description')) {
                                          return `Interface description ${interfaceName} ${action}`;
                                        } else if (command && command.includes('status')) {
                                          return `Interface status ${interfaceName} ${action}`;
                                        } else if (command && command.includes('counter')) {
                                          return `Interface counters ${interfaceName} ${action}`;
                                        } else if (command && command.includes('description')) {
                                          return `Interface description ${interfaceName} ${action}`;
                                        } else {
                                          return `Interface status ${interfaceName} ${action}`;
                                        }
                                      }
                                    }
                                    
                                    return item;
                                  } else if (typeof item === 'object' && item !== null) {
                                    // Handle different object structures
                                    if (item.description) {
                                      return item.description;
                                    } else if (item.interface) {
                                      // Enhanced interface formatting with command context
                                      const interfaceName = item.interface;
                                      const action = changeType || item.action || item.change || 'changed';
                                      
                                      // Determine interface property type based on command or available data
                                      if (command && command.includes('show interfaces status')) {
                                        return `Interface status ${interfaceName} ${action}`;
                                      } else if (command && command.includes('show interfaces counters')) {
                                        return `Interface counters ${interfaceName} ${action}`;
                                      } else if (command && command.includes('show interfaces description')) {
                                        return `Interface description ${interfaceName} ${action}`;
                                      } else if (item.linkStatus || item.lineProtocolStatus || item.interfaceType) {
                                        return `Interface status ${interfaceName} ${action}`;
                                      } else if (item.inOctets || item.outOctets || item.inUcastPkts) {
                                        return `Interface counters ${interfaceName} ${action}`;
                                      } else if (item.description && item.interfaceStatus) {
                                        return `Interface description ${interfaceName} ${action}`;
                                      } else {
                                        return `Interface ${interfaceName} ${action}`;
                                      }
                                    } else if (item.name && (item.name.includes('Interface') || item.name.includes('Ethernet'))) {
                                      // Enhanced handling of interface info in the name field
                                      const action = changeType || item.action || item.change || 'changed';
                                      
                                      // Check if name already contains action
                                      if (item.name.includes(action)) {
                                        // Process existing string like "Interface Ethernet3 added"
                                        const match = item.name.match(/Interface\s+(Ethernet\d+)\s+(added|removed|modified|changed)/i);
                                        if (match) {
                                          const [, interfaceName, detectedAction] = match;
                                          
                                          // Determine interface property type based on command context
                                          if (command && command.includes('show interfaces status')) {
                                            return `Interface status ${interfaceName} ${detectedAction}`;
                                          } else if (command && command.includes('show interfaces counters')) {
                                            return `Interface counters ${interfaceName} ${detectedAction}`;
                                          } else if (command && command.includes('show interfaces description')) {
                                            return `Interface description ${interfaceName} ${detectedAction}`;
                                          } else if (command && command.includes('status')) {
                                            return `Interface status ${interfaceName} ${detectedAction}`;
                                          } else if (command && command.includes('counter')) {
                                            return `Interface counters ${interfaceName} ${detectedAction}`;
                                          } else if (command && command.includes('description')) {
                                            return `Interface description ${interfaceName} ${detectedAction}`;
                                          } else {
                                            return `Interface status ${interfaceName} ${detectedAction}`;
                                          }
                                        }
                                        return item.name;
                                      } else {
                                        // Extract interface name and apply action
                                        const match = item.name.match(/Interface\s+(Ethernet\d+)/i);
                                        if (match) {
                                          const [, interfaceName] = match;
                                          
                                          if (command && command.includes('show interfaces status')) {
                                            return `Interface status ${interfaceName} ${action}`;
                                          } else if (command && command.includes('show interfaces counters')) {
                                            return `Interface counters ${interfaceName} ${action}`;
                                          } else if (command && command.includes('show interfaces description')) {
                                            return `Interface description ${interfaceName} ${action}`;
                                          } else {
                                            return `Interface status ${interfaceName} ${action}`;
                                          }
                                        }
                                        return `${item.name} ${action}`;
                                      }
                                    } else if (item.command && item.data) {
                                      const dataStr = typeof item.data === 'object' 
                                        ? JSON.stringify(item.data).replace(/[{}"]/g, '').replace(/,/g, ', ')
                                        : item.data;
                                      return `${item.command} - ${dataStr}`;
                                    } else if (item.name) {
                                      return item.name;
                                    } else if (item.change || item.action) {
                                      // Handle change/action objects
                                      const action = item.change || item.action;
                                      const target = item.target || item.interface || item.name || '';
                                      if (target && target.includes('Ethernet')) {
                                        // Enhanced interface formatting for target-based changes
                                        if (command && command.includes('show interfaces status')) {
                                          return `Interface status ${target} ${action}`;
                                        } else if (command && command.includes('show interfaces counters')) {
                                          return `Interface counters ${target} ${action}`;
                                        } else if (command && command.includes('show interfaces description')) {
                                          return `Interface description ${target} ${action}`;
                                        } else {
                                          return `Interface ${target} ${action}`;
                                        }
                                      }
                                      return target ? `${target} ${action}` : action;
                                    } else {
                                      // Enhanced interface object detection with property-specific formatting
                                      const keys = Object.keys(item);
                                      const interfaceKey = keys.find(key => key.toLowerCase().includes('interface') || key.toLowerCase().includes('ethernet'));
                                      
                                      if (interfaceKey) {
                                        const interfaceName = item[interfaceKey];
                                        const action = changeType || 'changed';
                                        
                                        // Determine interface property type based on command context first, then properties
                                        if (command && command.includes('show interfaces status')) {
                                          return `Interface status ${interfaceName} ${action}`;
                                        } else if (command && command.includes('show interfaces counters')) {
                                          return `Interface counters ${interfaceName} ${action}`;
                                        } else if (command && command.includes('show interfaces description')) {
                                          return `Interface description ${interfaceName} ${action}`;
                                        } else if (item.linkStatus || item.lineProtocolStatus || item.interfaceType || item.bandwidth) {
                                          return `Interface status ${interfaceName} ${action}`;
                                        } else if (item.inOctets || item.outOctets || item.inUcastPkts || item.outUcastPkts) {
                                          return `Interface counters ${interfaceName} ${action}`;
                                        } else if (item.description || item.interfaceStatus) {
                                          return `Interface description ${interfaceName} ${action}`;
                                        } else {
                                          return `Interface ${interfaceName} ${action}`;
                                        }
                                      }
                                      
                                      // Check for direct Ethernet interface references in object keys
                                      const ethernetKeys = keys.filter(key => key.includes('Ethernet'));
                                      if (ethernetKeys.length > 0) {
                                        const results = ethernetKeys.map(ethKey => {
                                          const action = changeType || 'changed';
                                          // Determine property type based on command context first, then object structure
                                          if (command && command.includes('show interfaces status')) {
                                            return `Interface status ${ethKey} ${action}`;
                                          } else if (command && command.includes('show interfaces counters')) {
                                            return `Interface counters ${ethKey} ${action}`;
                                          } else if (command && command.includes('show interfaces description')) {
                                            return `Interface description ${ethKey} ${action}`;
                                          } else {
                                            const value = item[ethKey];
                                            if (typeof value === 'object' && value !== null) {
                                              if (value.linkStatus || value.lineProtocolStatus || value.interfaceType) {
                                                return `Interface status ${ethKey} ${action}`;
                                              } else if (value.inOctets || value.outOctets || value.inUcastPkts) {
                                                return `Interface counters ${ethKey} ${action}`;
                                              } else if (value.description || value.interfaceStatus) {
                                                return `Interface description ${ethKey} ${action}`;
                                              } else {
                                                return `Interface ${ethKey} ${action}`;
                                              }
                                            } else {
                                              return `Interface ${ethKey} ${action}`;
                                            }
                                          }
                                        });
                                        return results.join(', ');
                                      }
                                      
                                      // Improved fallback: create a readable string from object properties
                                      if (keys.length > 0) {
                                        return keys.map(key => {
                                          const value = item[key];
                                          if (typeof value === 'object' && value !== null) {
                                            return `${key}: ${JSON.stringify(value).replace(/[{}"]/g, '').replace(/,/g, ', ')}`;
                                          }
                                          return `${key}: ${value}`;
                                        }).join(', ');
                                      }
                                    }
                                  }
                                  // Final fallback
                                  return String(item);
                                };

                                const ChangeDetailComponent = ({ changes, changeType, command }) => {
                                  const [isExpanded, setIsExpanded] = React.useState(changes.length <= 3);
                                  const displayChanges = isExpanded ? changes : changes.slice(0, 2);
                                  const hasMore = changes.length > 3;
                                  
                                  return (
                                    <>
                                      {displayChanges.map((item, idx) => (
                                        <div key={`${changeType}-${idx}`} className={`change-detail-row ${changeType}`}>
                                          <span className="change-detail">{formatChangeItem(item, changeType, command)}</span>
                                        </div>
                                      ))}
                                      {hasMore && (
                                        <div className="change-expand-row">
                                          <button 
                                            className="change-expand-btn"
                                            onClick={() => setIsExpanded(!isExpanded)}
                                          >
                                            {isExpanded 
                                              ? `Show less` 
                                              : `Show ${changes.length - 2} more ${changeType} changes`
                                            }
                                          </button>
                                        </div>
                                      )}
                                    </>
                                  );
                                };

                                const hasDetailedChanges = (result.added && result.added.length > 0) ||
                                                          (result.removed && result.removed.length > 0) ||
                                                          (result.modified && result.modified.length > 0);

                                if (hasDetailedChanges) {
                                  return (
                                    <div className="change-detail-list">
                                      {result.added && result.added.length > 0 && (
                                        <ChangeDetailComponent 
                                          changes={result.added} 
                                          changeType="added" 
                                          command={command}
                                        />
                                      )}
                                      {result.removed && result.removed.length > 0 && (
                                        <ChangeDetailComponent 
                                          changes={result.removed} 
                                          changeType="removed" 
                                          command={command}
                                        />
                                      )}
                                      {result.modified && result.modified.length > 0 && (
                                        <ChangeDetailComponent 
                                          changes={result.modified} 
                                          changeType="modified" 
                                          command={command}
                                        />
                                      )}
                                    </div>
                                  );
                                } else if (result.statistics) {
                                  return (
                                    <div className="change-detail-list">
                                      {result.statistics.added_count > 0 && (
                                        <div className="change-detail-row added">
                                          <span className="change-detail">Added: {result.statistics.added_count} items</span>
                                        </div>
                                      )}
                                      {result.statistics.removed_count > 0 && (
                                        <div className="change-detail-row removed">
                                          <span className="change-detail">Removed: {result.statistics.removed_count} items</span>
                                        </div>
                                      )}
                                      {result.statistics.modified_count > 0 && (
                                        <div className="change-detail-row modified">
                                          <span className="change-detail">Modified: {result.statistics.modified_count} items</span>
                                        </div>
                                      )}
                                      {result.statistics.added_count === 0 && result.statistics.removed_count === 0 && result.statistics.modified_count === 0 && (
                                        <div className="change-detail-row no-changes">
                                          <span className="change-detail">No changes detected</span>
                                        </div>
                                      )}
                                    </div>
                                  );
                                } else if (result.status === "no_changes") {
                                  return (
                                    <div className="change-detail-list">
                                      <div className="change-detail-row no-changes">
                                        <span className="change-detail">No changes detected</span>
                                      </div>
                                    </div>
                                  );
                                }
                                return null;
                              })()}
                            </div>
                          </div>
                        );
                      }
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Progress Component
const ProgressBar = ({ progress, showDetails = true }) => {
  if (!progress) return null;

  const percentage = progress.percentage || 0;
  const successRate =
    progress.total > 0 ? (progress.successful / progress.total) * 100 : 0;

  return (
    <div className="progress-section">
      <div className="progress-header">
        <h4>Processing Progress</h4>
        <span className="progress-percentage">{percentage.toFixed(1)}%</span>
      </div>

      <div className="progress-bar-container">
        <div className="progress-bar">
          <div
            className="progress-fill"
            style={{ width: `${percentage}%` }}
          ></div>
        </div>
      </div>

      {showDetails && (
        <div className="progress-details">
          <div className="progress-stats">
            <div className="stat">
              <CheckCircle size={16} className="success" />
              <span>Success: {progress.successful || 0}</span>
            </div>
            <div className="stat">
              <XCircle size={16} className="error" />
              <span>Failed: {progress.failed || 0}</span>
            </div>
            <div className="stat">
              <Clock size={16} className="pending" />
              <span>
                Remaining: {(progress.total || 0) - (progress.completed || 0)}
              </span>
            </div>
          </div>
          <div className="success-rate">
            Success Rate: {successRate.toFixed(1)}%
          </div>
        </div>
      )}
    </div>
  );
};

// Device Status Icon Component
const DeviceStatusIcon = ({ status, size = 16 }) => {
  const statusIcons = {
    [DEVICE_STATUS.SUCCESS]: (
      <CheckCircle size={size} className="status-success" />
    ),
    [DEVICE_STATUS.FAILED]: <XCircle size={size} className="status-failed" />,
    [DEVICE_STATUS.CONNECTING]: (
      <Loader2 size={size} className="status-connecting animate-spin" />
    ),
    [DEVICE_STATUS.RETRYING]: (
      <RefreshCw size={size} className="status-retrying animate-spin" />
    ),
    [DEVICE_STATUS.PENDING]: <Clock size={size} className="status-pending" />,
    [DEVICE_STATUS.STOPPED]: (
      <StopCircle size={size} className="status-stopped" />
    ),
  };

  return (
    statusIcons[status] || <Clock size={size} className="status-unknown" />
  );
};

// Output Files Manager - Updated with select functionality
const OutputFilesModal = ({ isOpen, onClose, onCompareSelect }) => {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");

  React.useEffect(() => {
    if (isOpen) {
      document.documentElement.classList.add('modal-open');
      document.body.classList.add('modal-open');
    } else {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    }
    
    return () => {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    };
  }, [isOpen]);

  const loadFiles = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.request("/output_files");
      if (response.status === "success") {
        setFiles(response.data || []);
      }
    } catch (error) {
      console.error("Error loading files:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadFiles();
      setSelectedFiles([]); // Clear selection when modal opens
    }
  }, [isOpen, loadFiles]);

  const handleDelete = async (filename) => {
    if (!window.confirm(`Are you sure you want to delete ${filename}?`)) return;

    try {
      const response = await api.request(`/output_files/${filename}`, {
        method: "DELETE",
      });
      if (response.status === "success") {
        loadFiles();
        // Remove from selected files if it was selected
        setSelectedFiles((prev) => prev.filter((f) => !f.includes(filename)));
      }
    } catch (error) {
      alert(`Error deleting file: ${error.message}`);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedFiles.length === 0) return;

    const filenamesToDelete = selectedFiles
      .map((filepath) => {
        const file = files.find((f) => f.filepath === filepath);
        return file ? file.filename : null;
      })
      .filter(Boolean);

    if (
      !window.confirm(
        `Are you sure you want to delete ${filenamesToDelete.length} selected file(s)?`
      )
    )
      return;

    try {
      for (const filename of filenamesToDelete) {
        await api.request(`/output_files/${filename}`, {
          method: "DELETE",
        });
      }

      setSelectedFiles([]);
      loadFiles();
    } catch (error) {
      alert(`Error deleting files: ${error.message}`);
    }
  };

  const handleDownload = (filename) => {
    const url = `${API_BASE_URL}/output_files/${filename}`;

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const toggleFileSelection = (filepath) => {
    setSelectedFiles((prev) => {
      if (prev.includes(filepath)) {
        return prev.filter((f) => f !== filepath);
      } else {
        return [...prev, filepath];
      }
    });
  };

  const handleCompare = () => {
    if (selectedFiles.length === 2) {
      const filenames = selectedFiles
        .map((filepath) => {
          const file = files.find((f) => f.filepath === filepath);
          return file ? file.filename : null;
        })
        .filter(Boolean);

      onCompareSelect(filenames);
      onClose();
    }
  };

  const filteredFiles = files.filter((file) =>
    file.filename.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + " B";
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    else return (bytes / 1048576).toFixed(1) + " MB";
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content xl-modal output-files-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>
            <FolderOpen size={24} />
            Output Files Manager
          </h2>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <div className="file-manager-controls">
            <div className="controls-row">
              <div className="controls-left">
                <div className="search-box">
                  <Search size={16} />
                  <input
                    type="text"
                    placeholder="Search files..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
              </div>

              <div className="controls-right">
              {selectedFiles.length > 0 && (
                <>
                  <span className="selection-counter">
                    {selectedFiles.length} Selected
                  </span>
                  <button
                    className="delete-selected-button"
                    onClick={handleDeleteSelected}
                    title="Delete selected files"
                  >
                    <Trash2 size={16} />
                    Delete Selected
                  </button>
                </>
              )}

              {selectedFiles.length === 2 && (
                <button
                  className="compare-button"
                  onClick={handleCompare}
                  title="Compare selected files"
                >
                  <GitCompare size={16} />
                  Compare Selected Files
                </button>
              )}

              <button
                className="refresh-button"
                onClick={loadFiles}
                title="Refresh file list"
              >
                <RefreshCw size={16} />
                Refresh
              </button>
              </div>
            </div>
          </div>

          {loading ? (
            <div className="loading-container">
              <Loader2 size={32} className="animate-spin" />
              <p>Loading files...</p>
            </div>
          ) : (
            <div className="files-container">
              <div className="files-grid">
                {filteredFiles.length === 0 ? (
                  <div className="empty-state">
                    <FolderOpen size={48} />
                    <p>No output files found</p>
                  </div>
                ) : (
                  filteredFiles.map((file) => (
                    <div
                      key={file.filename}
                      className={`file-card ${
                        selectedFiles.includes(file.filepath) ? "selected" : ""
                      }`}
                    >
                      <div className="file-icon">
                        <File size={32} />
                      </div>
                      <div className="file-info">
                        <h4>{file.filename}</h4>
                        <p>Size: {formatFileSize(file.size)}</p>
                        <p>
                          Modified: {new Date(file.modified).toLocaleString()}
                        </p>
                      </div>
                      <div className="file-actions">
                        <button
                          className={`action-btn select ${
                            selectedFiles.includes(file.filepath)
                              ? "selected"
                              : ""
                          }`}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleFileSelection(file.filepath);
                          }}
                          title="Select for comparison"
                        >
                          <CheckCircle size={16} />
                        </button>
                        <button
                          className="action-btn download"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDownload(file.filename);
                          }}
                          title="Download"
                        >
                          <Download size={16} />
                        </button>
                        <button
                          className="action-btn delete"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDelete(file.filename);
                          }}
                          title="Delete"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Add Logs Viewer Component with Real-time Stream
const LogsViewer = ({ isOpen, onClose }) => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [filterLevel, setFilterLevel] = useState("ALL");
  const [autoScroll, setAutoScroll] = useState(true);
  const logsEndRef = React.useRef(null);

  React.useEffect(() => {
    if (isOpen) {
      document.documentElement.classList.add('modal-open');
      document.body.classList.add('modal-open');
    } else {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    }
    
    return () => {
      document.documentElement.classList.remove('modal-open');
      document.body.classList.remove('modal-open');
    };
  }, [isOpen]);

  const loadLogs = useCallback(async () => {
    try {
      const response = await api.request("/logs");
      if (response.status === "success") {
        setLogs(response.data || []);
      }
    } catch (error) {
      console.error("Error loading logs:", error);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      // Load initial logs
      loadLogs();

      // Set up real-time streaming if available
      if (isDevelopment) {
        const eventSource = api.setupLogStream((logEntry) => {
          setLogs((prev) => {
            const newLogs = [...prev, logEntry];
            return newLogs.slice(-1000);
          });
        });

        return () => {
          eventSource.close();
        };
      } else if (autoRefresh) {
        // Fallback to polling for production
        const interval = setInterval(loadLogs, 2000);
        return () => clearInterval(interval);
      }
    }
  }, [isOpen, autoRefresh, loadLogs]);

  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  const handleClearLogs = async () => {
    if (!window.confirm("Are you sure you want to clear all logs?")) return;

    try {
      const response = await api.request("/logs/clear", { method: "POST" });
      if (response.status === "success") {
        setLogs([]);
      } else {
        console.error("Failed to clear logs:", response.message);
      }
    } catch (error) {
      console.error("Error clearing logs:", error);
    }
  };

  const filteredLogs = useMemo(() => {
    if (filterLevel === "ALL") return logs;
    return logs.filter((log) => log.level === filterLevel);
  }, [logs, filterLevel]);

  const getLogLevelClass = (level) => {
    switch (level) {
      case "ERROR":
        return "log-error";
      case "WARNING":
        return "log-warning";
      case "INFO":
        return "log-info";
      default:
        return "log-debug";
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content xl-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>
            <Terminal size={24} />
            System Logs {isDevelopment && "(Real-time)"}
          </h2>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <div className="logs-controls">
            <div className="filter-group">
              <label>Level:</label>
              <div className="dropdown-container">
                <select
                  value={filterLevel}
                  onChange={(e) => setFilterLevel(e.target.value)}
                  className="dropdown-select"
                >
                  <option value="ALL">All Levels</option>
                  <option value="ERROR">Error</option>
                  <option value="WARNING">Warning</option>
                  <option value="INFO">Info</option>
                  <option value="DEBUG">Debug</option>
                </select>
              </div>
            </div>
            {!isDevelopment && (
              <label className="auto-refresh">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                Auto-refresh
              </label>
            )}
            {isDevelopment && (
              <label className="auto-scroll">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                />
                Auto-scroll
              </label>
            )}
            <button className="clear-logs-btn" onClick={handleClearLogs}>
              <Trash2 size={16} />
              Clear Logs
            </button>
          </div>

          <div className="logs-container">
            {filteredLogs.length === 0 ? (
              <div className="empty-logs">
                <Terminal size={48} />
                <p>No logs to display</p>
              </div>
            ) : (
              <div className="logs-list">
                {filteredLogs.map((log, index) => (
                  <div
                    key={index}
                    className={`log-entry ${getLogLevelClass(log.level)}`}
                  >
                    <span className="log-timestamp">
                      {isDevelopment
                        ? new Date(log.timestamp).toLocaleTimeString()
                        : log.timestamp}
                    </span>
                    <span className="log-level">[{log.level}]</span>
                    <span className="log-module">{log.module}:</span>
                    <span className="log-message">{log.message}</span>
                  </div>
                ))}
                {isDevelopment && <div ref={logsEndRef} />}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// --- Main App Component ---
function App() {
  // State management
  const [message, setMessage] = useState(MESSAGES.INITIALIZING);
  const [status, setStatus] = useState(STATUS.LOADING);
  const [results, setResults] = useState([]);
  const [filteredResults, setFilteredResults] = useState([]);
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });
  const [detailData, setDetailData] = useState(null);
  const [chartData, setChartData] = useState(null);
  const [chartFilter, setChartFilter] = useState("model_sw");
  const [alertInfo, setAlertInfo] = useState(null);
  const [isApiReady, setIsApiReady] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [systemInfo, setSystemInfo] = useState(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [apiStatus, setApiStatus] = useState("connecting");

  // API endpoint information
  const [apiEndpoints, setApiEndpoints] = useState({});

  // File upload state
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedFilePath, setUploadedFilePath] = useState("");

  // Command selection state
  const [availableCommands, setAvailableCommands] = useState({});
  const [selectedCommands, setSelectedCommands] = useState([]);

  // Processing state
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [progress, setProgress] = useState(null);
  const [canRetry, setCanRetry] = useState(false);
  const [comparisonData, setComparisonData] = useState(null);
  const [showFileManager, setShowFileManager] = useState(false);
  const [showLogsViewer, setShowLogsViewer] = useState(false);
  const [comparisonFiles, setComparisonFiles] = useState(null);
  const [outputFiles, setOutputFiles] = useState([]);
  const [comparisonChartData, setComparisonChartData] = useState(null);
  const [comparisonChartFilter, setComparisonChartFilter] = useState("summary");
  const [showComparisonDashboard, setShowComparisonDashboard] = useState(false);

  // Filtering state
  const [filterType, setFilterType] = useState("all");
  const [filterValue, setFilterValue] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  // Dark mode
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    return saved ? JSON.parse(saved) : false;
  });

  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(isDarkMode));
    if (isDarkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [isDarkMode]);

  const toggleDarkMode = useCallback(() => {
    setIsDarkMode((prev) => !prev);
  }, []);

  // Memoized derived state for performance
  const hasResults = useMemo(() => results.length > 0, [results]);
  const displayResults = useMemo(() => {
    let filtered = filteredResults.length > 0 ? filteredResults : results;

    if (searchTerm) {
      filtered = filtered.filter(
        (device) =>
          device.ip_mgmt?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          device.nama_sw?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          device.model_sw?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    return filtered;
  }, [filteredResults, results, searchTerm]);

  const successCount = useMemo(
    () => displayResults.filter((r) => r.status === "Success").length,
    [displayResults]
  );
  const failureCount = useMemo(
    () => displayResults.filter((r) => r.status === "Failed").length,
    [displayResults]
  );

  // Callback for showing alerts
  const showAlert = useCallback((message, type = ALERT_TYPES.INFO) => {
    setAlertInfo({ message, type });
  }, []);

  // Load output files
  const loadOutputFiles = useCallback(async () => {
    try {
      const response = await api.getOutputFiles();
      if (response.status === "success") {
        setOutputFiles(response.data);
      }
    } catch (error) {
      console.error("Error loading output files:", error);
    }
  }, []);

  // File upload handler
  const handleFileUpload = useCallback(
    async (file) => {
      if (!file || file.type !== "text/csv") {
        showAlert("Please select a valid CSV file", ALERT_TYPES.ERROR);
        return;
      }

      if (file.size > 16 * 1024 * 1024) {
        showAlert(
          "File size too large. Maximum size is 16MB",
          ALERT_TYPES.ERROR
        );
        return;
      }

      try {
        setMessage("Uploading file...");
        const result = await api.uploadCsvFile(file);

        if (result.status === "success") {
          setUploadedFile({
            name: file.name,
            deviceCount: result.device_count,
            warnings: result.warnings || [],
            content: result.file_content, // Store file content instead of filepath
            detectedVendors: result.detected_vendors || [],
          });
          setUploadedFilePath(result.file_content); // Use content instead of filepath

          // Create combined message with upload status and detected vendors
          let message = `✅ File uploaded successfully!\nFound ${result.device_count} devices`;

          if (result.detected_vendors && result.detected_vendors.length > 0) {
            message += `\nDetected vendors: ${result.detected_vendors.join(", ")}`;
          }

          if (result.warnings && result.warnings.length > 0) {
            message += `\n⚠️ ${result.warnings.length} warnings found`;
            showAlert(message, ALERT_TYPES.WARNING);
          } else {
            showAlert(message, ALERT_TYPES.SUCCESS);
          }

          setMessage(MESSAGES.API_READY);

          // Update available commands based on detected vendors
          await updateCommandsBasedOnFile(result.file_content);
        } else {
          let errorMessage = result.message || "File upload failed";
          if (result.errors && result.errors.length > 0) {
            errorMessage = result.errors.join("\n");
          }
          showAlert(errorMessage, ALERT_TYPES.ERROR);
        }
      } catch (error) {
        console.error("File upload error:", error);
        showAlert(`Upload failed: ${error.message}`, ALERT_TYPES.ERROR);
      }
    },
    [showAlert]
  );

  // Remove uploaded file
  const handleFileRemove = useCallback(() => {
    setUploadedFile(null);
    setUploadedFilePath("");
    setMessage(MESSAGES.AWAITING_FILE);
  }, []);

  // Callback to handle responses from backend
  const handleBackendResponse = useCallback(
    (response) => {
      console.log("Response from backend:", response);
      setIsProcessing(false);
      setProgress(null);

      if (!response) {
        setMessage("Received an empty response from backend.");
        setStatus(STATUS.ERROR);
        showAlert(
          "Received an empty response from backend.",
          ALERT_TYPES.ERROR
        );
        return;
      }

      setMessage(response.message || MESSAGES.PROCESS_FINISHED);
      setStatus(response.status || STATUS.IDLE);

      if (response.data) {
        setResults(response.data);
        setFilteredResults([]);
        setCanRetry(response.data.some((device) => device.status === "Failed"));
        loadOutputFiles();
      }

      if (
        response.status === STATUS.ERROR ||
        response.status === STATUS.SUCCESS
      ) {
        showAlert(response.message, response.status);
      }
    },
    [showAlert, loadOutputFiles]
  );

  // Effect to check processing status
  useEffect(() => {
    let statusInterval;

    if (isProcessing && currentSessionId) {
      statusInterval = setInterval(async () => {
        try {
          const statusResponse = await api.getProcessingStatus(
            currentSessionId
          );

          if (statusResponse && statusResponse.status !== "processing") {
            handleBackendResponse(statusResponse);
            setCurrentSessionId(null);
          } else if (statusResponse && statusResponse.progress) {
            setProgress(statusResponse.progress);
            setMessage(statusResponse.message);
          }
        } catch (error) {
          console.error("Error checking processing status:", error);
          setIsProcessing(false);
          setCurrentSessionId(null);
          setProgress(null);
          showAlert("Error checking processing status", ALERT_TYPES.ERROR);
        }
      }, 2000);
    }

    return () => {
      if (statusInterval) {
        clearInterval(statusInterval);
      }
    };
  }, [isProcessing, currentSessionId, handleBackendResponse, showAlert]);

  // Effect to set up API and listeners on component mount
  useEffect(() => {
    const initializeApi = async () => {
      try {
        setApiStatus("ready");
        setMessage("Backend connected successfully");

        // Test connection and get API endpoint information
        try {
          const [sysInfo, cmdInfo] = await Promise.all([
            api.getSystemInfo(),
            api.getComparisonCommands(),
          ]);

          if (sysInfo && sysInfo.status === "success") {
            setSystemInfo(sysInfo.data);
            setApiEndpoints(sysInfo.data.api_endpoints || {});
            console.log("API endpoints:", sysInfo);
          }

          if (cmdInfo && cmdInfo.status === "success") {
            // Dynamic command detection from backend
            const dynamicCommands = cmdInfo.data;
            setAvailableCommands(dynamicCommands);
            // Don't select any commands by default
            setSelectedCommands([]);
          }
        } catch (error) {
          console.error("Failed to connect to backend:", error);
          setApiStatus("error");
          setMessage("Failed to connect to backend");
          showAlert(
            `Cannot connect to backend server. ${
              isDevelopment
                ? "Make sure Flask server is running on localhost:5000"
                : "Backend service unavailable"
            }`,
            ALERT_TYPES.ERROR
          );
        }

        setTimeout(() => {
          setIsApiReady(true);
          setIsInitializing(false);
          setMessage(
            isDevelopment && !window.pywebview
              ? MESSAGES.AWAITING_FILE
              : MESSAGES.API_READY
          );
          setStatus(STATUS.IDLE);
        }, 1000);
      } catch (error) {
        console.error("Error initializing API:", error);
        setApiStatus("error");
        setIsInitializing(false);
        showAlert("Failed to initialize backend connection", ALERT_TYPES.ERROR);
      }
    };

    initializeApi();
  }, [handleBackendResponse, showAlert]);

  // Load output files when API is ready
  useEffect(() => {
    if (isApiReady) {
      loadOutputFiles();
    }
  }, [isApiReady, loadOutputFiles]);

  const generateComparisonChart = useCallback(
    async (data, chartType = "summary") => {
      try {
        setComparisonChartData(null);

        const response = await api.generateComparisonChart(data, chartType);

        if (response?.status === "success") {
          setComparisonChartData(response.data);
        } else {
          setComparisonChartData(null);
          console.error(
            "Comparison chart generation failed:",
            response?.message
          );
          showAlert("Failed to generate comparison chart", ALERT_TYPES.ERROR);
        }
      } catch (e) {
        console.error("Error generating comparison chart:", e);
        setComparisonChartData(null);
        showAlert(`Chart generation error: ${e.message}`, ALERT_TYPES.ERROR);
      }
    },
    [showAlert]
  );

  // Effect to generate chart data when results or filter change
  useEffect(() => {
    const generateChart = async () => {
      if (showComparisonDashboard && comparisonData?.data) {
        // Generate comparison chart
        await generateComparisonChart(
          comparisonData.data,
          comparisonChartFilter
        );
      } else if (!showComparisonDashboard && hasResults && isApiReady) {
        // Generate regular device chart
        try {
          const dataToChart =
            displayResults.length > 0 ? displayResults : results;
          const chartResponse = await api.generateChartData(
            dataToChart,
            chartFilter
          );
          if (chartResponse?.status === "success") {
            setChartData(chartResponse.data);
          } else {
            setChartData(null);
            console.error("Chart generation failed:", chartResponse?.message);
          }
        } catch (e) {
          console.error("Error fetching chart data:", e);
          setChartData(null);
        }
      }
    };

    generateChart();
  }, [
    results,
    displayResults,
    chartFilter,
    hasResults,
    isApiReady,
    showComparisonDashboard,
    comparisonData,
    comparisonChartFilter,
    generateComparisonChart,
  ]);

  // Handler to start the main process
  const handleRunScript = useCallback(
    async (retryFailedOnly = false) => {
      if (!isApiReady) {
        return showAlert(
          "API is not ready. Please restart the application.",
          ALERT_TYPES.ERROR
        );
      }

      // Check if we need a file upload (production mode) or can use file dialog (development)
      if (!isDevelopment || !window.pywebview) {
        if (!uploadedFilePath && !retryFailedOnly) {
          showAlert("Please upload a CSV file first", ALERT_TYPES.ERROR);
          return;
        }
      }

      if (!credentials.username.trim() || !credentials.password.trim()) {
        showAlert("Username and password are required", ALERT_TYPES.ERROR);
        return;
      }

      if (selectedCommands.length === 0) {
        showAlert(
          "Please select at least one command to execute",
          ALERT_TYPES.ERROR
        );
        return;
      }

      setMessage(
        retryFailedOnly
          ? "Starting retry process..."
          : isDevelopment && window.pywebview
          ? MESSAGES.AWAITING_FILE
          : "Starting processing..."
      );
      setStatus(STATUS.LOADING);
      setIsProcessing(true);
      if (!retryFailedOnly) {
        setResults([]);
        setFilteredResults([]);
      }
      setChartData(null);
      setAlertInfo(null);
      setProgress(null);

      try {
        let initialResponse;

        if (retryFailedOnly) {
          initialResponse = await api.retryFailedDevices(
            credentials.username,
            credentials.password,
            results
          );
        } else {
          initialResponse = await api.processDevicesFromFile(
            credentials.username,
            credentials.password,
            uploadedFilePath,
            selectedCommands,
            retryFailedOnly
          );
        }

        if (initialResponse) {
          setMessage(initialResponse.message);
          setStatus(initialResponse.status);

          if (initialResponse.session_id) {
            setCurrentSessionId(initialResponse.session_id);
            if (initialResponse.total_devices) {
              setProgress({
                total: initialResponse.total_devices,
                completed: 0,
                successful: 0,
                failed: 0,
                percentage: 0,
              });
            }
          }

          if (
            initialResponse.status === "error" ||
            initialResponse.status === "info"
          ) {
            setIsProcessing(false);
            setProgress(null);
            showAlert(initialResponse.message, initialResponse.status);
          }
        }
      } catch (e) {
        console.error("Error starting script:", e);
        const errorMessage = `An error occurred: ${e.message || e}`;
        showAlert(errorMessage, ALERT_TYPES.ERROR);
        setMessage(errorMessage);
        setStatus(STATUS.ERROR);
        setIsProcessing(false);
        setProgress(null);
      }
    },
    [
      isApiReady,
      credentials,
      showAlert,
      results,
      uploadedFilePath,
      selectedCommands,
    ]
  );

  // Handler to stop processing
  const handleStopProcessing = useCallback(async () => {
    if (!currentSessionId) return;

    try {
      const response = await api.stopProcessing(currentSessionId);
      if (response && response.status === "success") {
        showAlert("Stop request sent successfully", ALERT_TYPES.INFO);
        setStatus(STATUS.STOPPED);
        setMessage("Stopping processing...");
      }
    } catch (e) {
      showAlert(`Error stopping process: ${e.message || e}`, ALERT_TYPES.ERROR);
    }
  }, [currentSessionId, showAlert]);

  // Handler for filtering results
  const handleFilterChange = useCallback(
    async (newFilterType, newFilterValue) => {
      setFilterType(newFilterType);
      setFilterValue(newFilterValue);

      if (newFilterType === "all" || !newFilterValue) {
        setFilteredResults([]);
        return;
      }

      try {
        const response = await api.filterResults(
          results,
          newFilterType,
          newFilterValue
        );
        if (response && response.status === "success") {
          setFilteredResults(response.data);
        }
      } catch (e) {
        console.error("Error filtering results:", e);
        showAlert("Error applying filter", ALERT_TYPES.ERROR);
      }
    },
    [results, showAlert]
  );

  // Handler for file comparison
  const handleCompareFiles = useCallback(
    async (files = null) => {
      try {
        if (!files) {
          setShowFileManager(true);
          return;
        }

        if (files.length !== 2) {
          showAlert(
            "Please select exactly 2 files to compare",
            ALERT_TYPES.ERROR
          );
          return;
        }

        const response = await api.request("/compare_files", {
          method: "POST",
          body: JSON.stringify({
            first_file: files[0],
            second_file: files[1],
          }),
        });

        if (response && response.status === "success") {
          setComparisonData(response);
          setShowComparisonDashboard(true); // Switch to comparison dashboard
          // Generate initial comparison chart
          await generateComparisonChart(response.data, "summary");
          showAlert(
            "Enhanced file comparison completed successfully!",
            ALERT_TYPES.SUCCESS
          );
        } else {
          showAlert(
            response?.message || "Error comparing files",
            ALERT_TYPES.ERROR
          );
        }
      } catch (e) {
        showAlert(`Comparison error: ${e.message || e}`, ALERT_TYPES.ERROR);
      }
    },
    [showAlert, generateComparisonChart]
  );

  // Handle file comparison selection from file manager
  const handleCompareSelect = useCallback(
    (selectedFiles) => {
      setComparisonFiles(selectedFiles);
      handleCompareFiles(selectedFiles);
    },
    [handleCompareFiles]
  );

  // Handler for downloading comparison Excel
  const downloadComparisonExcel = useCallback(async () => {
    if (!comparisonData) {
      showAlert("No comparison data available to export", ALERT_TYPES.ERROR);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/export_comparison_excel`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          comparison_results: comparisonData.data || [],
          first_file: comparisonData.first_file || "file1",
          second_file: comparisonData.second_file || "file2",
        }),
      });

      if (response.ok) {
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = downloadUrl;
        a.download = `comparison_${new Date()
          .toISOString()
          .slice(0, 19)
          .replace(/[:-]/g, "")}.xlsx`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        showAlert(
          "Comparison Excel file downloaded successfully",
          ALERT_TYPES.SUCCESS
        );
      } else {
        const errorData = await response.json();
        showAlert(`Export error: ${errorData.message}`, ALERT_TYPES.ERROR);
      }
    } catch (error) {
      console.error("Error downloading comparison Excel:", error);
      showAlert(
        `Error downloading Excel file: ${error.message}`,
        ALERT_TYPES.ERROR
      );
    }
  }, [comparisonData, showAlert]);

  // Handler for updating commands based on uploaded file data
  const updateCommandsBasedOnFile = useCallback(
    async (fileContent) => {
      if (!fileContent) return;

      try {
        // Parse CSV content to extract device data
        const lines = fileContent.split("\n").filter((line) => line.trim());
        if (lines.length < 2) return; // Need header + at least one data row

        const headers = lines[0]
          .split(",")
          .map((h) => h.trim().replace(/"/g, ""));
        const deviceData = [];

        for (let i = 1; i < lines.length; i++) {
          const values = lines[i]
            .split(",")
            .map((v) => v.trim().replace(/"/g, ""));
          if (values.length >= headers.length) {
            const device = {};
            headers.forEach((header, index) => {
              device[header] = values[index] || "";
            });
            deviceData.push(device);
          }
        }

        if (deviceData.length === 0) return;

        // Get filtered commands based on detected vendors
        const filteredResult = await api.getFilteredCommands(
          deviceData,
          "execution"
        );

        if (filteredResult && filteredResult.status === "success") {
          setAvailableCommands(filteredResult.data);
          setSelectedCommands([]); // Reset selected commands

          // Don't show vendor detection alert here since it's already shown in upload success message
        }
      } catch (error) {
        console.error("Error updating commands based on file data:", error);
        // Fallback to loading all commands
        try {
          const cmdInfo = await api.getComparisonCommands();
          if (cmdInfo && cmdInfo.status === "success") {
            setAvailableCommands(cmdInfo.data);
          }
        } catch (fallbackError) {
          console.error("Error loading fallback commands:", fallbackError);
        }
      }
    },
    [showAlert]
  );

  // Handler for exporting data to Excel
  const handleExport = useCallback(async () => {
    if (!hasResults) return showAlert("No data to export.", ALERT_TYPES.INFO);
    if (isProcessing) return;

    try {
      const dataToExport = displayResults.length > 0 ? displayResults : results;
      const response = await api.exportToExcel(dataToExport, "detailed"); // Use enhanced export
      if (response && response.status === "success") {
        showAlert(response.message, ALERT_TYPES.SUCCESS);
      }
    } catch (e) {
      showAlert(`Export error: ${e.message || e}`, ALERT_TYPES.ERROR);
    }
  }, [hasResults, isProcessing, displayResults, results, showAlert]);

  return (
    <div className="app-container">
      <LoadingOverlay
        message={message}
        isVisible={isInitializing}
        apiStatus={apiStatus}
        progress={progress}
      />

      <Alert info={alertInfo} onClose={() => setAlertInfo(null)} />
      <DetailModal data={detailData} onClose={() => setDetailData(null)} />
      <ComparisonModal
        comparisonData={comparisonData}
        onClose={() => setComparisonData(null)}
        onDownloadExcel={downloadComparisonExcel}
      />
      <OutputFilesModal
        isOpen={showFileManager}
        onClose={() => setShowFileManager(false)}
        onCompareSelect={handleCompareSelect}
      />
      <LogsViewer
        isOpen={showLogsViewer}
        onClose={() => setShowLogsViewer(false)}
      />

      <header className="app-header">
        <div className="logo">
          <Server size={40} className="logo-icon" />
          <div>
            <h1>Network Data App{isDevelopment && " (Dev)"}</h1>
            <p>Automated data collection from network devices via APIs</p>
          </div>
        </div>
        <div className="header-controls">
          {systemInfo && (
            <div className="system-info">
              <small>Version: {systemInfo.version || "2.0.0"}</small>
              <div className={`api-connection-status ${apiStatus}`}>
                <div className="status-indicator"></div>
                <span>
                  {apiStatus === "ready" ? "Connected" : "Disconnected"}
                  {isDevelopment && " (Dev Mode)"}
                </span>
              </div>
            </div>
          )}
          <div className="header-buttons">
            <button
              className="header-btn"
              onClick={() => setShowFileManager(true)}
              title="Output Files"
            >
              <FolderOpen size={20} />
            </button>
            <button
              className="header-btn"
              onClick={() => setShowLogsViewer(true)}
              title="System Logs"
            >
              <Terminal size={20} />
            </button>
            <button
              className="dark-mode-toggle"
              onClick={toggleDarkMode}
              aria-label="Toggle dark mode"
            >
              {isDarkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
          </div>
        </div>
      </header>

      <main className="main-content">
        <div className="setup-grid">
          {/* File Upload Section */}
          {(!isDevelopment || !window.pywebview) && (
            <div className="card">
              <div className="card-header">
                <Upload size={20} />
                <h3>1. Upload Device List</h3>
              </div>
              <div className="card-content">
                <FileUploadComponentWithWarnings
                  onFileUpload={handleFileUpload}
                  disabled={isProcessing}
                  uploadedFile={uploadedFile}
                  onFileRemove={handleFileRemove}
                />
              </div>
            </div>
          )}

          <div className="card">
            <div className="card-header">
              <Key size={20} />
              <h3>2. Authentication Credentials</h3>
            </div>
            <div className="card-content">
              <input
                type="text"
                placeholder="Username (required)"
                value={credentials.username}
                onChange={(e) =>
                  setCredentials((p) => ({ ...p, username: e.target.value }))
                }
                className="credential-input"
                disabled={isProcessing}
                required
              />
              <input
                type="password"
                placeholder="Password (required)"
                value={credentials.password}
                onChange={(e) =>
                  setCredentials((p) => ({ ...p, password: e.target.value }))
                }
                className="credential-input"
                disabled={isProcessing}
                required
              />
              <small className="credential-note">
                <AlertCircle size={12} />
                Credentials are required for API authentication
              </small>
            </div>
          </div>

          {/* Command Selection */}
          <div className="card">
            <div className="card-header">
              <Settings size={20} />
              <h3>3. Select Commands</h3>
            </div>
            <div className="card-content">
              {Object.keys(availableCommands).length > 0 ? (
                <CommandSelectionComponent
                  availableCommands={availableCommands}
                  selectedCommands={selectedCommands}
                  onCommandChange={setSelectedCommands}
                  disabled={isProcessing}
                />
              ) : (
                <p>Loading available commands...</p>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <Play size={20} />
              <h3>4. Run Process</h3>
            </div>
            <div className="card-content">
              <p className="start-description">
                {isDevelopment && window.pywebview
                  ? "Click Start to open the file dialog and begin processing the devices from your CSV list."
                  : "Upload your device list CSV file, select commands, and click Start to begin processing."}
              </p>
              <div className="button-group">
                <button
                  onClick={() => handleRunScript(false)}
                  disabled={
                    !isApiReady ||
                    isProcessing ||
                    !credentials.username ||
                    !credentials.password ||
                    ((!isDevelopment || !window.pywebview) &&
                      !uploadedFilePath) ||
                    selectedCommands.length === 0
                  }
                  className="run-button primary"
                >
                  <Activity size={18} />
                  {isProcessing ? MESSAGES.PROCESSING : "Start API Collection"}
                </button>

                {canRetry && (
                  <button
                    onClick={() => handleRunScript(true)}
                    disabled={
                      !isApiReady ||
                      isProcessing ||
                      !credentials.username ||
                      !credentials.password
                    }
                    className="run-button secondary"
                  >
                    <RefreshCw size={18} />
                    Retry Failed Devices
                  </button>
                )}

                {isProcessing && currentSessionId && (
                  <button
                    onClick={handleStopProcessing}
                    className="stop-button"
                  >
                    <StopCircle size={18} />
                    Stop Processing
                  </button>
                )}
              </div>

              {(!credentials.username || !credentials.password) && (
                <div className="validation-warning">
                  <Info size={16} />
                  <span>Please provide both username and password</span>
                </div>
              )}

              {selectedCommands.length === 0 && (
                <div className="validation-warning">
                  <Info size={16} />
                  <span>Please select at least one command</span>
                </div>
              )}

              {!isApiReady && (
                <div className="api-status">
                  <Loader2 size={16} className="animate-spin" />
                  <span>Waiting for backend...</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Progress Section */}
        {isProcessing && progress && (
          <div className="card">
            <div className="card-header">
              <TrendingUp size={20} />
              <h3>Processing Progress</h3>
            </div>
            <div className="card-content">
              <ProgressBar progress={progress} />
            </div>
          </div>
        )}

        {hasResults && (
          <>
            {/* Results Summary */}
            <div className="card results-summary">
              <div className="card-header">
                <h3>Processing Complete</h3>
                <div className="summary-stats">
                  <span>
                    Total: <strong>{displayResults.length}</strong>
                  </span>
                  <span className="success">
                    Success: <strong>{successCount}</strong>
                  </span>
                  <span className="failure">
                    Failed: <strong>{failureCount}</strong>
                  </span>
                  {filteredResults.length > 0 && (
                    <span className="filtered">
                      Filtered:{" "}
                      <strong>
                        {filteredResults.length}/{results.length}
                      </strong>
                    </span>
                  )}
                </div>
                <div className="action-buttons">
                  <button
                    onClick={handleExport}
                    className="action-button"
                    disabled={isProcessing}
                  >
                    <Download size={16} /> Export to Excel
                  </button>
                  <button
                    onClick={() => handleCompareFiles()}
                    className="action-button"
                    disabled={isProcessing}
                  >
                    <GitCompare size={16} /> Compare Files
                  </button>
                </div>
              </div>
            </div>

            {/* Filtering Section */}
            <div className="card">
              <div className="card-header">
                <Filter size={20} />
                <h3>Data Filtering</h3>
                <div className="filter-controls">
                  <div className="filter-group">
                    <label>Filter by:</label>
                    <select
                      value={filterType}
                      onChange={(e) =>
                        handleFilterChange(e.target.value, filterValue)
                      }
                      disabled={isProcessing}
                    >
                      <option value="all">All Devices</option>
                      <option value="status">Status</option>
                      <option value="model_sw">Model</option>
                      <option value="connection_status">
                        Connection Status
                      </option>
                    </select>
                  </div>

                  {filterType !== "all" && (
                    <div className="filter-group">
                      <label>Value:</label>
                      {filterType === "status" ? (
                        <select
                          value={filterValue}
                          onChange={(e) =>
                            handleFilterChange(filterType, e.target.value)
                          }
                          disabled={isProcessing}
                        >
                          <option value="">Select Status</option>
                          <option value="Success">Success</option>
                          <option value="Failed">Failed</option>
                        </select>
                      ) : filterType === "connection_status" ? (
                        <select
                          value={filterValue}
                          onChange={(e) =>
                            handleFilterChange(filterType, e.target.value)
                          }
                          disabled={isProcessing}
                        >
                          <option value="">Select Connection Status</option>
                          <option value="success">Success</option>
                          <option value="failed">Failed</option>
                          <option value="connecting">Connecting</option>
                          <option value="retrying">Retrying</option>
                          <option value="stopped">Stopped</option>
                        </select>
                      ) : (
                        <input
                          type="text"
                          placeholder="Enter filter value"
                          value={filterValue}
                          onChange={(e) =>
                            handleFilterChange(filterType, e.target.value)
                          }
                          disabled={isProcessing}
                        />
                      )}
                    </div>
                  )}

                  <div className="search-group">
                    <Search size={16} />
                    <input
                      type="text"
                      placeholder="Search devices..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      disabled={isProcessing}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Enhanced Dashboard Section */}
            {(hasResults || showComparisonDashboard) && (
              <div className="card">
                <div className="card-header">
                  <BarChart2 size={20} />
                  <h3>
                    {showComparisonDashboard
                      ? "Comparison Dashboard"
                      : "Device Dashboard"}
                  </h3>

                  {/* Dashboard Toggle Buttons */}
                  <div className="dashboard-toggle">
                    <button
                      className={`toggle-btn ${
                        !showComparisonDashboard ? "active" : ""
                      }`}
                      onClick={() => {
                        setShowComparisonDashboard(false);
                        setComparisonData(null);
                      }}
                      disabled={!hasResults}
                    >
                      <Server size={16} />
                      Device Stats
                    </button>
                    <button
                      className={`toggle-btn ${
                        showComparisonDashboard ? "active" : ""
                      }`}
                      onClick={() => setShowComparisonDashboard(true)}
                      disabled={!comparisonData}
                    >
                      <GitCompare size={16} />
                      Comparison Stats
                    </button>
                  </div>

                  {/* Chart Filter Controls */}
                  <div className="chart-controls">
                    {showComparisonDashboard ? (
                      <div className="filter-group">
                        <label htmlFor="comparison-chart-filter">
                          Chart Type:
                        </label>
                        <select
                          id="comparison-chart-filter"
                          value={comparisonChartFilter}
                          onChange={(e) => {
                            setComparisonChartFilter(e.target.value);
                            if (comparisonData?.data) {
                              generateComparisonChart(
                                comparisonData.data,
                                e.target.value
                              );
                            }
                          }}
                          disabled={isProcessing || !comparisonData}
                        >
                          <option value="summary">Summary Overview</option>
                          <option value="by_command">By Command</option>
                          <option value="by_device">By Device</option>
                        </select>
                      </div>
                    ) : (
                      <div className="filter-group">
                        <label htmlFor="chart-filter">Group by:</label>
                        <select
                          id="chart-filter"
                          value={chartFilter}
                          onChange={(e) => setChartFilter(e.target.value)}
                          disabled={isProcessing}
                        >
                          <option value="model_sw">Model</option>
                          <option value="status">Status</option>
                          <option value="connection_status">
                            Connection Status
                          </option>
                        </select>
                      </div>
                    )}
                  </div>
                </div>

                <div className="card-content">
                  {/* Comparison Dashboard */}
                  {showComparisonDashboard && comparisonData ? (
                    <div className="comparison-dashboard">
                      {/* Comparison Summary Info */}
                      <div className="comparison-info">
                        <div className="comparison-meta">
                          <h4>Comparison Details</h4>
                          <p>
                            <strong>Files:</strong> {comparisonData.first_file}{" "}
                            vs {comparisonData.second_file}
                          </p>
                          <p>
                            <strong>Devices Compared:</strong>{" "}
                            {comparisonData.total_compared}
                          </p>
                          <p>
                            <strong>Commands:</strong>{" "}
                            {comparisonData.available_commands?.join(", ") ||
                              "N/A"}
                          </p>
                          <button
                            className="download-button small"
                            onClick={onDownloadExcel}
                          >
                            <Download size={14} />
                            Download Excel Report
                          </button>
                        </div>
                      </div>

                      {/* Comparison Chart */}
                      <div className="chart-container">
                        {comparisonChartData ? (
                          <Plot
                            data={comparisonChartData.data}
                            layout={{
                              ...comparisonChartData.layout,
                              autosize: true,
                              paper_bgcolor: "var(--secondary-bg)",
                              plot_bgcolor: "var(--card-bg)",
                              font: { color: "var(--text-color)" },
                            }}
                            style={{ width: "100%", height: "400px" }}
                            useResizeHandler
                            config={{ responsive: true, displaylogo: false }}
                          />
                        ) : (
                          <div className="chart-loading">
                            <Loader2 size={32} className="animate-spin" />
                            <p>Generating comparison chart...</p>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    /* Regular Device Dashboard */
                    <div className="device-dashboard">
                      {chartData ? (
                        <Plot
                          data={chartData.data}
                          layout={{
                            ...chartData.layout,
                            autosize: true,
                            paper_bgcolor: "var(--secondary-bg)",
                            plot_bgcolor: "var(--card-bg)",
                            font: { color: "var(--text-color)" },
                          }}
                          style={{ width: "100%", height: "400px" }}
                          useResizeHandler
                          config={{ responsive: true, displaylogo: false }}
                        />
                      ) : (
                        <div className="chart-loading">
                          <Loader2 size={32} className="animate-spin" />
                          <p>Loading chart data...</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Results Details */}
            <div className="card">
              <div className="card-header">
                <FileText size={20} />
                <h3>Results Details</h3>
                {displayResults.length !== results.length && (
                  <span className="filter-indicator">
                    Showing {displayResults.length} of {results.length} devices
                  </span>
                )}
              </div>
              <div className="table-wrapper">
                <table className="results-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>IP</th>
                      <th>Hostname</th>
                      <th>Model</th>
                      <th>Serial</th>
                      <th>Time (s)</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayResults.map((device, index) => (
                      <tr
                        key={`${device.ip_mgmt}-${index}`}
                        className={`status-${device.status?.toLowerCase()}`}
                      >
                        <td className="status-cell">
                          <DeviceStatusIcon status={device.connection_status} />
                          <span
                            className={`badge ${
                              device.status === "Success"
                                ? "badge-success"
                                : "badge-danger"
                            }`}
                          >
                            {device.status}
                          </span>
                        </td>
                        <td className="ip-cell">{device.ip_mgmt || "N/A"}</td>
                        <td>{device.nama_sw || "N/A"}</td>
                        <td>{device.model_sw || "N/A"}</td>
                        <td>{device.sn || "N/A"}</td>
                        <td>{device.processing_time?.toFixed(2) ?? "N/A"}</td>
                        <td className="details-cell">
                          {device.status === "Success" ? (
                            <button
                              className="view-button"
                              onClick={() => setDetailData(device.data)}
                            >
                              <Eye size={14} />
                              View
                            </button>
                          ) : (
                            <span className="error-text" title={device.error}>
                              {device.error
                                ? device.error.length > 50
                                  ? `${device.error.substring(0, 50)}...`
                                  : device.error
                                : "Unknown"}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
