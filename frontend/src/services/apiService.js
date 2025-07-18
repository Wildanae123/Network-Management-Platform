// frontend/src/services/apiService.js
/**
 * Shared API service to eliminate duplicate request patterns
 */

// Environment Detection
const isDevelopment =
  process.env.NODE_ENV === "development" ||
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";

const API_BASE_URL = isDevelopment ? "/api" : "/api";

class ApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  // Base request method to eliminate duplicate error handling
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
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
        let errorMessage = `HTTP error! status: ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch {
          // Fallback to status text if JSON parsing fails
          errorMessage = response.statusText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      return await response.json();
    } catch (error) {
      console.error(`API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // GET request
  async get(endpoint) {
    return this.request(endpoint, { method: "GET" });
  }

  // POST request
  async post(endpoint, data) {
    return this.request(endpoint, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  // File upload with progress tracking
  async uploadFile(endpoint, file, onProgress) {
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error("File upload failed:", error);
      throw error;
    }
  }

  // Download file
  async downloadFile(endpoint, filename) {
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.style.display = "none";
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error("File download failed:", error);
      throw error;
    }
  }

  // Specific API methods
  async getSystemInfo() {
    return this.get("/system-info");
  }

  async uploadCsvFile(file) {
    return this.uploadFile("/upload-csv", file);
  }

  async processDevicesFromFile(credentials, selectedCommands = []) {
    return this.post("/process-devices-from-file", {
      credentials,
      selected_commands: selectedCommands,
    });
  }

  async retryFailedDevices(credentials, selectedCommands = []) {
    return this.post("/retry-failed-devices", {
      credentials,
      selected_commands: selectedCommands,
    });
  }

  async stopCurrentProcess() {
    return this.post("/stop-process");
  }

  async getProcessingStatus() {
    return this.get("/processing-status");
  }

  async exportToExcel() {
    return this.downloadFile("/export-to-excel", "network_data.xlsx");
  }

  async getComparisonCommands() {
    return this.get("/comparison-commands");
  }

  async generateComparison(snapshot1, snapshot2, commandKey) {
    return this.post("/generate-comparison", {
      snapshot1,
      snapshot2,
      command_key: commandKey,
    });
  }

  async getAvailableSnapshots() {
    return this.get("/snapshots");
  }

  async deleteSnapshot(snapshotId) {
    return this.request(`/snapshots/${snapshotId}`, { method: "DELETE" });
  }

  async getChartData() {
    return this.get("/chart-data");
  }

  async getHealthMetrics() {
    return this.get("/health-metrics");
  }
}

// Create and export singleton instance
const apiService = new ApiService();
export default apiService;

// Export health status utilities to eliminate duplication
export const getHealthStatus = (healthScore) => {
  if (healthScore >= 80) return "healthy";
  if (healthScore >= 60) return "warning";
  if (healthScore > 0) return "critical";
  return "unknown";
};

export const getHealthColor = (status) => {
  const colors = {
    healthy: "#52c41a",
    warning: "#faad14", 
    critical: "#f5222d",
    unknown: "#8c8c8c"
  };
  return colors[status] || colors.unknown;
};