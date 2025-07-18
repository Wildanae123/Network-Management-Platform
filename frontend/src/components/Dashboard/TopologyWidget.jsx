// frontend/src/components/Dashboard/TopologyWidget.jsx
import React, { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { ZoomIn, ZoomOut, RotateCcw, Settings } from "lucide-react";

const TopologyWidget = ({ nodes, edges, onNodeClick, onEdgeClick }) => {
  const svgRef = useRef();
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState(null);
  const [layoutType, setLayoutType] = useState("force");

  useEffect(() => {
    if (!nodes || !edges) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove(); // Clear previous render

    const width = 800;
    const height = 600;
    const margin = { top: 20, right: 20, bottom: 20, left: 20 };

    // Create main group
    const g = svg.append("g");

    // Define color scale based on device health
    const colorScale = d3
      .scaleOrdinal()
      .domain(["healthy", "warning", "critical", "unknown"])
      .range(["#52c41a", "#faad14", "#f5222d", "#8c8c8c"]);

    // Create force simulation
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(edges)
          .id((d) => d.id)
          .distance(100)
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    // Create edges
    const link = g
      .append("g")
      .selectAll("line")
      .data(edges)
      .enter()
      .append("line")
      .attr("stroke", "#999")
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", (d) => Math.sqrt(d.bandwidth || 1))
      .style("cursor", "pointer")
      .on("click", (event, d) => {
        onEdgeClick && onEdgeClick(d);
      })
      .on("mouseover", function (event, d) {
        // Show edge tooltip
        const tooltip = d3
          .select("body")
          .append("div")
          .attr("class", "topology-tooltip")
          .style("opacity", 0);

        tooltip.transition().duration(200).style("opacity", 0.9);

        tooltip
          .html(
            `
          <strong>Connection</strong><br/>
          Bandwidth: ${d.bandwidth || "Unknown"}<br/>
          Latency: ${d.latency || "Unknown"}ms<br/>
          Utilization: ${d.utilization || "Unknown"}%
        `
          )
          .style("left", event.pageX + 10 + "px")
          .style("top", event.pageY - 28 + "px");
      })
      .on("mouseout", function () {
        d3.selectAll(".topology-tooltip").remove();
      });

    // Create node groups
    const node = g
      .append("g")
      .selectAll("g")
      .data(nodes)
      .enter()
      .append("g")
      .attr("class", "node")
      .style("cursor", "pointer")
      .call(
        d3
          .drag()
          .on("start", dragstarted)
          .on("drag", dragged)
          .on("end", dragended)
      )
      .on("click", (event, d) => {
        setSelectedNode(d);
        onNodeClick && onNodeClick(d);
      });

    // Add circles to nodes
    node
      .append("circle")
      .attr("r", (d) => {
        if (d.model && d.model.includes("Switch")) return 15;
        if (d.model && d.model.includes("Router")) return 20;
        return 12;
      })
      .attr("fill", (d) => {
        const status = getHealthStatus(d.health_score);
        return colorScale(status);
      })
      .attr("stroke", (d) => (selectedNode?.id === d.id ? "#1890ff" : "#fff"))
      .attr("stroke-width", (d) => (selectedNode?.id === d.id ? 3 : 1.5));

    // Add status indicators
    node
      .append("circle")
      .attr("r", 4)
      .attr("cx", 12)
      .attr("cy", -12)
      .attr("fill", (d) => (d.status === "online" ? "#52c41a" : "#f5222d"))
      .attr("stroke", "#fff")
      .attr("stroke-width", 1);

    // Add labels
    node
      .append("text")
      .attr("dx", 0)
      .attr("dy", -25)
      .attr("text-anchor", "middle")
      .style("font-size", "12px")
      .style("font-weight", "bold")
      .text((d) => d.label);

    // Add IP addresses
    node
      .append("text")
      .attr("dx", 0)
      .attr("dy", 35)
      .attr("text-anchor", "middle")
      .style("font-size", "10px")
      .style("fill", "#666")
      .text((d) => d.ip);

    // Add device type icons
    node
      .append("text")
      .attr("dx", 0)
      .attr("dy", 5)
      .attr("text-anchor", "middle")
      .style("font-size", "14px")
      .text((d) => {
        if (d.model && d.model.includes("Switch")) return "🔀";
        if (d.model && d.model.includes("Router")) return "🌐";
        return "📡";
      });

    // Add tooltips
    node
      .on("mouseover", function (event, d) {
        const tooltip = d3
          .select("body")
          .append("div")
          .attr("class", "topology-tooltip")
          .style("opacity", 0);

        tooltip.transition().duration(200).style("opacity", 0.9);

        tooltip
          .html(
            `
        <strong>${d.label}</strong><br/>
        IP: ${d.ip}<br/>
        Model: ${d.model || "Unknown"}<br/>
        Status: ${d.status}<br/>
        Health: ${d.health_score}%<br/>
        Vendor: ${d.vendor || "Unknown"}
      `
          )
          .style("left", event.pageX + 10 + "px")
          .style("top", event.pageY - 28 + "px");
      })
      .on("mouseout", function () {
        d3.selectAll(".topology-tooltip").remove();
      });

    // Update simulation
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Zoom behavior
    const zoomBehavior = d3
      .zoom()
      .scaleExtent([0.1, 3])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
        setZoom(event.transform.k);
      });

    svg.call(zoomBehavior);

    // Cleanup
    return () => {
      simulation.stop();
    };
  }, [nodes, edges, selectedNode, layoutType]);

  const getHealthStatus = (healthScore) => {
    if (healthScore >= 80) return "healthy";
    if (healthScore >= 60) return "warning";
    if (healthScore > 0) return "critical";
    return "unknown";
  };

  const handleZoomIn = () => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(d3.zoom().scaleBy(svg, 1.2));
  };

  const handleZoomOut = () => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(d3.zoom().scaleBy(svg, 0.8));
  };

  const handleReset = () => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(d3.zoom().transform, d3.zoomIdentity);
  };

  return (
    <div className="topology-widget">
      <div className="topology-controls">
        <div className="zoom-controls">
          <button onClick={handleZoomIn} title="Zoom In">
            <ZoomIn size={16} />
          </button>
          <button onClick={handleZoomOut} title="Zoom Out">
            <ZoomOut size={16} />
          </button>
          <button onClick={handleReset} title="Reset View">
            <RotateCcw size={16} />
          </button>
          <span className="zoom-level">Zoom: {(zoom * 100).toFixed(0)}%</span>
        </div>

        <div className="layout-controls">
          <select
            value={layoutType}
            onChange={(e) => setLayoutType(e.target.value)}
          >
            <option value="force">Force Layout</option>
            <option value="circular">Circular Layout</option>
            <option value="hierarchical">Hierarchical Layout</option>
          </select>
        </div>
      </div>

      <div className="topology-container">
        <svg ref={svgRef} width="100%" height="600" viewBox="0 0 800 600" />
      </div>

      <div className="topology-legend">
        <div className="legend-item">
          <div
            className="legend-color"
            style={{ backgroundColor: "#52c41a" }}
          ></div>
          <span>Healthy</span>
        </div>
        <div className="legend-item">
          <div
            className="legend-color"
            style={{ backgroundColor: "#faad14" }}
          ></div>
          <span>Warning</span>
        </div>
        <div className="legend-item">
          <div
            className="legend-color"
            style={{ backgroundColor: "#f5222d" }}
          ></div>
          <span>Critical</span>
        </div>
        <div className="legend-item">
          <div
            className="legend-color"
            style={{ backgroundColor: "#8c8c8c" }}
          ></div>
          <span>Unknown</span>
        </div>
      </div>

      {selectedNode && (
        <div className="selected-node-info">
          <h4>{selectedNode.label}</h4>
          <p>IP: {selectedNode.ip}</p>
          <p>Status: {selectedNode.status}</p>
          <p>Health: {selectedNode.health_score}%</p>
          <p>Model: {selectedNode.model}</p>
          <button onClick={() => setSelectedNode(null)}>Close</button>
        </div>
      )}
    </div>
  );
};

export default TopologyWidget;
