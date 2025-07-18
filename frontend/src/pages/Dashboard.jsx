// frontend/src/pages/Dashboard.jsx
import React, { useState, useEffect, useCallback } from "react";
import { Grid, Card, CardContent, Typography, Box } from "@mui/material";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Heatmap,
} from "recharts";

// Import components
import MetricCard from "../components/Dashboard/MetricCard";
import PerformanceChart from "../components/Dashboard/PerformanceChart";
import NetworkHeatmap from "../components/Dashboard/NetworkHeatmap";
import AlertsWidget from "../components/Dashboard/AlertsWidget";
import TopologyWidget from "../components/Dashboard/TopologyWidget";
import CapacityWidget from "../components/Dashboard/CapacityWidget";
import TrendAnalysis from "../components/Dashboard/TrendAnalysis";

// Import services
import { ApiService } from "../services/api";
import { useRealtimeData } from "../hooks/useRealtimeData";

const Dashboard = () => {
  // State
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState("24h");
  const [refreshInterval, setRefreshInterval] = useState(30); // seconds

  // Services
  const apiService = new ApiService();

  // Real-time data
  const realtimeMetrics = useRealtimeData("dashboard_metrics");

  // Load dashboard data
  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      const data = await apiService.getDashboardData(timeRange);
      setDashboardData(data);
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  // Initialize dashboard
  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Auto-refresh
  useEffect(() => {
    const interval = setInterval(loadDashboardData, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [loadDashboardData, refreshInterval]);

  // Update with real-time data
  useEffect(() => {
    if (realtimeMetrics && dashboardData) {
      setDashboardData((prev) => ({
        ...prev,
        overview: {
          ...prev.overview,
          ...realtimeMetrics,
        },
      }));
    }
  }, [realtimeMetrics, dashboardData]);

  if (loading && !dashboardData) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Network Operations Dashboard</h1>
        <div className="dashboard-controls">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="time-range-selector"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>

          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            className="refresh-interval-selector"
          >
            <option value="10">10 seconds</option>
            <option value="30">30 seconds</option>
            <option value="60">1 minute</option>
            <option value="300">5 minutes</option>
          </select>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Overview Metrics */}
        <div className="metrics-row">
          <MetricCard
            title="Total Devices"
            value={dashboardData?.overview?.total_devices || 0}
            trend={dashboardData?.overview?.device_trend}
            icon="devices"
            color="primary"
          />
          <MetricCard
            title="Average CPU Usage"
            value={`${dashboardData?.overview?.avg_cpu_usage || 0}%`}
            trend={dashboardData?.overview?.cpu_trend}
            icon="cpu"
            color="warning"
          />
          <MetricCard
            title="Average Memory Usage"
            value={`${dashboardData?.overview?.avg_memory_usage || 0}%`}
            trend={dashboardData?.overview?.memory_trend}
            icon="memory"
            color="info"
          />
          <MetricCard
            title="Active Alerts"
            value={dashboardData?.overview?.active_alerts || 0}
            trend={dashboardData?.overview?.alerts_trend}
            icon="alert"
            color="error"
          />
        </div>

        {/* Performance Charts */}
        <div className="charts-row">
          <div className="chart-container">
            <h3>Performance Trends</h3>
            <PerformanceChart
              data={dashboardData?.performance_trends}
              timeRange={timeRange}
            />
          </div>

          <div className="chart-container">
            <h3>Health Distribution</h3>
            <PieChart width={400} height={300}>
              <Pie
                data={[
                  {
                    name: "Healthy",
                    value: dashboardData?.health_distribution?.healthy || 0,
                    fill: "#52c41a",
                  },
                  {
                    name: "Warning",
                    value: dashboardData?.health_distribution?.warning || 0,
                    fill: "#faad14",
                  },
                  {
                    name: "Critical",
                    value: dashboardData?.health_distribution?.critical || 0,
                    fill: "#f5222d",
                  },
                  {
                    name: "Unknown",
                    value: dashboardData?.health_distribution?.unknown || 0,
                    fill: "#8c8c8c",
                  },
                ]}
                cx={200}
                cy={150}
                labelLine={false}
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {dashboardData?.health_distribution &&
                  Object.entries(dashboardData.health_distribution).map(
                    (entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    )
                  )}
              </Pie>
              <Tooltip />
            </PieChart>
          </div>
        </div>

        {/* Network Heatmap */}
        <div className="heatmap-container">
          <h3>Network Health Heatmap</h3>
          <NetworkHeatmap
            data={dashboardData?.network_topology}
            metric="health"
          />
        </div>

        {/* Alerts and Capacity */}
        <div className="widgets-row">
          <div className="widget-container">
            <AlertsWidget
              alerts={dashboardData?.alerts_summary}
              onAlertClick={(alert) => {
                // Handle alert click
              }}
            />
          </div>

          <div className="widget-container">
            <CapacityWidget
              data={dashboardData?.capacity_analysis}
              onCapacityAlert={(alert) => {
                // Handle capacity alert
              }}
            />
          </div>
        </div>

        {/* Topology Visualization */}
        <div className="topology-container">
          <h3>Network Topology</h3>
          <TopologyWidget
            nodes={dashboardData?.network_topology?.nodes}
            edges={dashboardData?.network_topology?.edges}
            onNodeClick={(node) => {
              // Handle node click
            }}
          />
        </div>

        {/* Trend Analysis */}
        <div className="trends-container">
          <h3>Trend Analysis & Predictions</h3>
          <TrendAnalysis
            data={dashboardData?.capacity_analysis?.growth_predictions}
            timeRange={timeRange}
          />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
