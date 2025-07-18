// frontend/src/pages/DeviceManagement.jsx
import React, { useState, useEffect, useCallback } from "react";
import {
  Search,
  Filter,
  Plus,
  Edit,
  Trash2,
  Power,
  Settings,
  Download,
  Upload,
  RefreshCw,
  Eye,
  CheckCircle,
  XCircle,
  AlertTriangle,
  MoreVertical,
} from "lucide-react";

// Components
import BulkOperations from "../components/DeviceManagement/BulkOperations";
import DeviceHealthCard from "../components/DeviceManagement/DeviceHealthCard";
import DeviceConfigModal from "../components/DeviceManagement/DeviceConfigModal";
import DeviceAddModal from "../components/DeviceManagement/DeviceAddModal";
import DeviceGroupManager from "../components/DeviceManagement/DeviceGroupManager";
import AdvancedFilters from "../components/DeviceManagement/AdvancedFilters";

// Services
import { ApiService } from "../services/api";
import { useRealtimeData } from "../hooks/useRealtimeData";

const DeviceManagement = () => {
  // State
  const [devices, setDevices] = useState([]);
  const [selectedDevices, setSelectedDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [filters, setFilters] = useState({
    status: "all",
    vendor: "all",
    group: "all",
    health: "all",
  });
  const [sortBy, setSortBy] = useState("hostname");
  const [sortOrder, setSortOrder] = useState("asc");
  const [viewMode, setViewMode] = useState("table"); // table, grid, health
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showGroupManager, setShowGroupManager] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [bulkOperationMode, setBulkOperationMode] = useState(false);

  // Services
  const apiService = new ApiService();

  // Real-time updates
  const realtimeDevices = useRealtimeData("device_status");

  // Load devices
  const loadDevices = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiService.getDevices({
        search: searchTerm,
        filters,
        sortBy,
        sortOrder,
      });
      setDevices(response.data);
    } catch (error) {
      console.error("Failed to load devices:", error);
    } finally {
      setLoading(false);
    }
  }, [searchTerm, filters, sortBy, sortOrder]);

  // Initialize
  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  // Update with real-time data
  useEffect(() => {
    if (realtimeDevices) {
      setDevices((prev) =>
        prev.map((device) => {
          const update = realtimeDevices.find((u) => u.id === device.id);
          return update ? { ...device, ...update } : device;
        })
      );
    }
  }, [realtimeDevices]);

  // Filter devices
  const filteredDevices = devices.filter((device) => {
    const matchesSearch =
      device.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.ip_address?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.model?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus =
      filters.status === "all" || device.status === filters.status;
    const matchesVendor =
      filters.vendor === "all" || device.vendor === filters.vendor;
    const matchesGroup =
      filters.group === "all" ||
      device.groups?.some((g) => g.id === filters.group);
    const matchesHealth =
      filters.health === "all" ||
      getHealthStatus(device.health_score) === filters.health;

    return (
      matchesSearch &&
      matchesStatus &&
      matchesVendor &&
      matchesGroup &&
      matchesHealth
    );
  });

  // Sort devices
  const sortedDevices = [...filteredDevices].sort((a, b) => {
    const aValue = a[sortBy] || "";
    const bValue = b[sortBy] || "";

    if (sortOrder === "asc") {
      return aValue.localeCompare(bValue);
    } else {
      return bValue.localeCompare(aValue);
    }
  });

  // Helper functions
  const getHealthStatus = (score) => {
    if (score >= 80) return "healthy";
    if (score >= 60) return "warning";
    if (score > 0) return "critical";
    return "unknown";
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "online":
        return <CheckCircle className="text-green-500" size={16} />;
      case "offline":
        return <XCircle className="text-red-500" size={16} />;
      case "unreachable":
        return <AlertTriangle className="text-yellow-500" size={16} />;
      default:
        return <XCircle className="text-gray-500" size={16} />;
    }
  };

  // Event handlers
  const handleDeviceSelect = (device, selected) => {
    if (selected) {
      setSelectedDevices((prev) => [...prev, device]);
    } else {
      setSelectedDevices((prev) => prev.filter((d) => d.id !== device.id));
    }
  };

  const handleSelectAll = (selected) => {
    if (selected) {
      setSelectedDevices(sortedDevices);
    } else {
      setSelectedDevices([]);
    }
  };

  const handleBulkOperation = async (operation, params) => {
    try {
      await apiService.bulkDeviceOperation(
        selectedDevices.map((d) => d.id),
        operation,
        params
      );
      setSelectedDevices([]);
      loadDevices();
    } catch (error) {
      console.error("Bulk operation failed:", error);
    }
  };

  const handleDeviceAction = async (device, action) => {
    try {
      switch (action) {
        case "view":
          setSelectedDevice(device);
          break;
        case "edit":
          setSelectedDevice(device);
          setShowAddModal(true);
          break;
        case "config":
          setSelectedDevice(device);
          setShowConfigModal(true);
          break;
        case "delete":
          if (
            window.confirm(
              `Are you sure you want to delete ${device.hostname}?`
            )
          ) {
            await apiService.deleteDevice(device.id);
            loadDevices();
          }
          break;
        case "reboot":
          if (
            window.confirm(
              `Are you sure you want to reboot ${device.hostname}?`
            )
          ) {
            await apiService.rebootDevice(device.id);
          }
          break;
        case "collect":
          await apiService.collectDeviceData(device.id);
          break;
        default:
          break;
      }
    } catch (error) {
      console.error("Device action failed:", error);
    }
  };

  // Render functions
  const renderTableView = () => (
    <div className="device-table-container">
      <table className="device-table">
        <thead>
          <tr>
            <th>
              <input
                type="checkbox"
                checked={selectedDevices.length === sortedDevices.length}
                onChange={(e) => handleSelectAll(e.target.checked)}
              />
            </th>
            <th onClick={() => setSortBy("status")}>Status</th>
            <th onClick={() => setSortBy("hostname")}>Hostname</th>
            <th onClick={() => setSortBy("ip_address")}>IP Address</th>
            <th onClick={() => setSortBy("vendor")}>Vendor</th>
            <th onClick={() => setSortBy("model")}>Model</th>
            <th onClick={() => setSortBy("health_score")}>Health</th>
            <th onClick={() => setSortBy("last_seen")}>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {sortedDevices.map((device) => (
            <tr
              key={device.id}
              className={selectedDevices.includes(device) ? "selected" : ""}
            >
              <td>
                <input
                  type="checkbox"
                  checked={selectedDevices.includes(device)}
                  onChange={(e) => handleDeviceSelect(device, e.target.checked)}
                />
              </td>
              <td>
                <div className="status-cell">
                  {getStatusIcon(device.status)}
                  <span className={`status-text ${device.status}`}>
                    {device.status}
                  </span>
                </div>
              </td>
              <td>
                <div className="hostname-cell">
                  <span className="hostname">{device.hostname}</span>
                  {device.groups && device.groups.length > 0 && (
                    <div className="device-groups">
                      {device.groups.map((group) => (
                        <span key={group.id} className="group-tag">
                          {group.name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </td>
              <td className="ip-cell">{device.ip_address}</td>
              <td>{device.vendor}</td>
              <td>{device.model}</td>
              <td>
                <div className="health-cell">
                  <div
                    className={`health-score ${getHealthStatus(
                      device.health_score
                    )}`}
                  >
                    {device.health_score}%
                  </div>
                </div>
              </td>
              <td>
                <span className="last-seen">
                  {device.last_seen
                    ? new Date(device.last_seen).toLocaleString()
                    : "Never"}
                </span>
              </td>
              <td>
                <div className="actions-cell">
                  <button
                    onClick={() => handleDeviceAction(device, "view")}
                    className="action-btn view"
                    title="View Details"
                  >
                    <Eye size={14} />
                  </button>
                  <button
                    onClick={() => handleDeviceAction(device, "edit")}
                    className="action-btn edit"
                    title="Edit Device"
                  >
                    <Edit size={14} />
                  </button>
                  <button
                    onClick={() => handleDeviceAction(device, "config")}
                    className="action-btn config"
                    title="Configuration"
                  >
                    <Settings size={14} />
                  </button>
                  <div className="dropdown">
                    <button className="action-btn dropdown-trigger">
                      <MoreVertical size={14} />
                    </button>
                    <div className="dropdown-menu">
                      <button
                        onClick={() => handleDeviceAction(device, "collect")}
                      >
                        Collect Data
                      </button>
                      <button
                        onClick={() => handleDeviceAction(device, "reboot")}
                      >
                        Reboot
                      </button>
                      <button
                        onClick={() => handleDeviceAction(device, "delete")}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  const renderGridView = () => (
    <div className="device-grid">
      {sortedDevices.map((device) => (
        <div
          key={device.id}
          className={`device-card ${
            selectedDevices.includes(device) ? "selected" : ""
          }`}
        >
          <div className="device-card-header">
            <input
              type="checkbox"
              checked={selectedDevices.includes(device)}
              onChange={(e) => handleDeviceSelect(device, e.target.checked)}
            />
            <div className="device-status">{getStatusIcon(device.status)}</div>
          </div>

          <div className="device-card-content">
            <h3 className="device-hostname">{device.hostname}</h3>
            <p className="device-ip">{device.ip_address}</p>
            <p className="device-model">
              {device.vendor} {device.model}
            </p>

            <div className="device-health">
              <div
                className={`health-bar ${getHealthStatus(device.health_score)}`}
              >
                <div
                  className="health-fill"
                  style={{ width: `${device.health_score}%` }}
                />
              </div>
              <span className="health-text">{device.health_score}%</span>
            </div>
          </div>

          <div className="device-card-actions">
            <button
              onClick={() => handleDeviceAction(device, "view")}
              className="card-action-btn"
            >
              <Eye size={16} />
            </button>
            <button
              onClick={() => handleDeviceAction(device, "edit")}
              className="card-action-btn"
            >
              <Edit size={16} />
            </button>
            <button
              onClick={() => handleDeviceAction(device, "config")}
              className="card-action-btn"
            >
              <Settings size={16} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );

  const renderHealthView = () => (
    <div className="device-health-grid">
      {sortedDevices.map((device) => (
        <DeviceHealthCard
          key={device.id}
          device={device}
          selected={selectedDevices.includes(device)}
          onSelect={(selected) => handleDeviceSelect(device, selected)}
          onAction={(action) => handleDeviceAction(device, action)}
        />
      ))}
    </div>
  );

  return (
    <div className="device-management">
      <div className="device-management-header">
        <h1>Device Management</h1>
        <div className="header-actions">
          <button onClick={() => setShowAddModal(true)} className="primary-btn">
            <Plus size={16} />
            Add Device
          </button>
          <button
            onClick={() => setShowGroupManager(true)}
            className="secondary-btn"
          >
            <Settings size={16} />
            Manage Groups
          </button>
        </div>
      </div>

      <div className="device-management-toolbar">
        <div className="search-section">
          <div className="search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search devices..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <button
            onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
            className={`filter-btn ${showAdvancedFilters ? "active" : ""}`}
          >
            <Filter size={16} />
            Filters
          </button>
        </div>

        <div className="view-controls">
          <div className="view-mode-selector">
            <button
              onClick={() => setViewMode("table")}
              className={viewMode === "table" ? "active" : ""}
            >
              Table
            </button>
            <button
              onClick={() => setViewMode("grid")}
              className={viewMode === "grid" ? "active" : ""}
            >
              Grid
            </button>
            <button
              onClick={() => setViewMode("health")}
              className={viewMode === "health" ? "active" : ""}
            >
              Health
            </button>
          </div>

          <button
            onClick={() => setBulkOperationMode(!bulkOperationMode)}
            className={`bulk-btn ${bulkOperationMode ? "active" : ""}`}
          >
            Bulk Operations
          </button>

          <button onClick={loadDevices} className="refresh-btn">
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {showAdvancedFilters && (
        <AdvancedFilters
          filters={filters}
          onChange={setFilters}
          onClose={() => setShowAdvancedFilters(false)}
        />
      )}

      {bulkOperationMode && selectedDevices.length > 0 && (
        <BulkOperations
          selectedDevices={selectedDevices}
          onOperation={handleBulkOperation}
          onClose={() => setBulkOperationMode(false)}
        />
      )}

      <div className="device-list-container">
        {loading ? (
          <div className="loading-container">
            <div className="loading-spinner" />
            <p>Loading devices...</p>
          </div>
        ) : (
          <>
            <div className="device-list-header">
              <span className="device-count">
                {sortedDevices.length} devices
                {selectedDevices.length > 0 &&
                  ` (${selectedDevices.length} selected)`}
              </span>
            </div>

            {viewMode === "table" && renderTableView()}
            {viewMode === "grid" && renderGridView()}
            {viewMode === "health" && renderHealthView()}
          </>
        )}
      </div>

      {/* Modals */}
      {showAddModal && (
        <DeviceAddModal
          device={selectedDevice}
          onClose={() => {
            setShowAddModal(false);
            setSelectedDevice(null);
          }}
          onSave={loadDevices}
        />
      )}

      {showConfigModal && (
        <DeviceConfigModal
          device={selectedDevice}
          onClose={() => {
            setShowConfigModal(false);
            setSelectedDevice(null);
          }}
        />
      )}

      {showGroupManager && (
        <DeviceGroupManager
          onClose={() => setShowGroupManager(false)}
          onSave={loadDevices}
        />
      )}
    </div>
  );
};

export default DeviceManagement;
