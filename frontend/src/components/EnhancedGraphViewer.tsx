"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import * as d3 from "d3";

interface GraphNode {
  id: string;
  name: string;
  type: "module" | "function" | "import";
  group: string;
  file?: string;
  visibility?: string;
  vulnerabilities?: Array<string | {
    id: string;
    name: string;
    severity: string;
    description: string;
  }>;
}

interface GraphLink {
  source: string;
  target: string;
  type: "calls" | "imports" | "contains" | "depends";
  sharedVulnerabilities?: string[];
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  modules?: any[];
  functions?: any[];
  vulnerabilities?: any[];
}

interface GraphViewerProps {
  data: GraphData | null;
}

export default function EnhancedGraphViewer({ data }: GraphViewerProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [showConnections, setShowConnections] = useState(true);
  const [filterBySeverity, setFilterBySeverity] = useState('all');
  const [currentTransform, setCurrentTransform] = useState(d3.zoomIdentity);
  
  // Reset selected node when data changes
  useEffect(() => {
    setSelectedNode(null);
  }, [data]);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      const zoom = d3.zoom().on("zoom", (event) => {
        setCurrentTransform(event.transform);
        svg.select('.graph-container').attr("transform", event.transform);
      });
      
      svg.transition().duration(300).call(
        zoom.scaleBy as any, 1.5
      );
    }
  }, []);

  const handleZoomOut = useCallback(() => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      const zoom = d3.zoom().on("zoom", (event) => {
        setCurrentTransform(event.transform);
        svg.select('.graph-container').attr("transform", event.transform);
      });
      
      svg.transition().duration(300).call(
        zoom.scaleBy as any, 0.67
      );
    }
  }, []);

  const handleZoomReset = useCallback(() => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      const zoom = d3.zoom().on("zoom", (event) => {
        setCurrentTransform(event.transform);
        svg.select('.graph-container').attr("transform", event.transform);
      });
      
      svg.transition().duration(500).call(
        zoom.transform as any, d3.zoomIdentity
      );
    }
  }, []);

  // Filter nodes by severity
  const getFilteredNodes = useCallback((nodes: GraphNode[]) => {
    if (filterBySeverity === 'all') return nodes;
    
    return nodes.filter(node => {
      if (!node.vulnerabilities || node.vulnerabilities.length === 0) {
        return filterBySeverity === 'secure';
      }
      
      return node.vulnerabilities.some(vuln => {
        const severity = typeof vuln === 'string' ? 'medium' : vuln.severity;
        return severity === filterBySeverity;
      });
    });
  }, [filterBySeverity]);

  // Enhanced connection detection
  const generateEnhancedConnections = useCallback((nodes: GraphNode[], originalLinks: GraphLink[]) => {
    const links = [...originalLinks];
    
    // Add module-function containment relationships
    const moduleNodes = nodes.filter(n => n.type === 'module');
    const functionNodes = nodes.filter(n => n.type === 'function');
    
    for (const func of functionNodes) {
      const parentModule = moduleNodes.find(mod => 
        func.group === mod.group || func.id.startsWith(mod.id) || func.group === mod.name
      );
      
      if (parentModule && !links.some(l => l.source === parentModule.id && l.target === func.id)) {
        links.push({
          source: parentModule.id,
          target: func.id,
          type: 'contains'
        });
      }
    }

    // Add vulnerability-based connections (functions with similar vulnerabilities)
    for (let i = 0; i < functionNodes.length; i++) {
      for (let j = i + 1; j < functionNodes.length; j++) {
        const func1 = functionNodes[i];
        const func2 = functionNodes[j];
        
        if (func1.vulnerabilities && func2.vulnerabilities && 
            func1.vulnerabilities.length > 0 && func2.vulnerabilities.length > 0) {
          
          const sharedVulns = findSharedVulnerabilities(func1.vulnerabilities, func2.vulnerabilities);
          
          if (sharedVulns.length > 0 && !links.some(l => 
            (l.source === func1.id && l.target === func2.id) || 
            (l.source === func2.id && l.target === func1.id)
          )) {
            links.push({
              source: func1.id,
              target: func2.id,
              type: 'depends',
              sharedVulnerabilities: sharedVulns
            });
          }
        }
      }
    }

    return links;
  }, []);

  const findSharedVulnerabilities = (vulns1: any[], vulns2: any[]) => {
    const getVulnId = (vuln: any) => typeof vuln === 'string' ? vuln : vuln.id;
    const ids1 = vulns1.map(getVulnId);
    const ids2 = vulns2.map(getVulnId);
    return ids1.filter(id => ids2.includes(id));
  };

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 900;
    const height = 600;
    
    svg.attr("width", width).attr("height", height);

    // Process actual data from analysis
    let nodes: GraphNode[] = [];
    let links: GraphLink[] = [];

    if (data.nodes && data.nodes.length > 0) {
      // Use actual analysis data
      nodes = data.nodes.map(node => ({
        ...node,
        vulnerabilities: node.vulnerabilities || data.vulnerabilities?.filter(v => 
          v.file === node.file || v.match?.includes(node.name)
        ) || []
      }));
      links = data.links || [];
    } else {
      // Create nodes from modules and functions if nodes array is missing
      if (data.modules) {
        data.modules.forEach(module => {
          nodes.push({
            id: module.id || `module_${module.name}`,
            name: module.name,
            type: "module",
            group: module.name.toLowerCase(),
            file: module.file,
            vulnerabilities: data.vulnerabilities?.filter(v => v.file === module.file) || []
          });
        });
      }

      if (data.functions) {
        data.functions.forEach(func => {
          nodes.push({
            id: func.id || `func_${func.module}_${func.name}`,
            name: func.name,
            type: "function",
            group: func.module?.toLowerCase() || "unknown",
            file: func.file,
            visibility: func.visibility,
            vulnerabilities: data.vulnerabilities?.filter(v => 
              v.file === func.file && (v.code?.includes(func.name) || v.match === func.name)
            ) || []
          });
        });
      }
    }

    // Generate enhanced connections
    if (showConnections) {
      links = generateEnhancedConnections(nodes, links);
    }

    // Filter nodes by severity
    const filteredNodes = getFilteredNodes(nodes);
    const filteredLinks = links.filter(link => 
      filteredNodes.some(n => n.id === link.source) && 
      filteredNodes.some(n => n.id === link.target)
    );

    // Ensure we have some data to display
    if (filteredNodes.length === 0) {
      filteredNodes.push({
        id: "placeholder", 
        name: "No data matching filter", 
        type: "module", 
        group: "empty", 
        vulnerabilities: []
      });
    }

    // Enhanced color scale for different node types with better visibility
    const getNodeColor = (d: any) => {
      if (d.vulnerabilities && d.vulnerabilities.length > 0) {
        // Color by highest severity vulnerability
        const severities = d.vulnerabilities.map((v: any) => v.severity || 'low');
        if (severities.includes('critical')) return '#991b1b'; // Dark red
        if (severities.includes('high')) return '#dc2626'; // Red
        if (severities.includes('medium')) return '#ea580c'; // Orange
        return '#2563eb'; // Blue for low
      }
      
      // Default colors by type
      switch (d.type) {
        case 'module': return '#6366f1'; // Indigo
        case 'function': return '#10b981'; // Emerald
        case 'import': return '#8b5cf6'; // Purple
        default: return '#6b7280'; // Gray
      }
    };

    const getNodeSize = (d: any) => {
      const baseSize = d.type === 'module' ? 20 : 15;
      const vulnBonus = d.vulnerabilities?.length > 0 ? Math.min(d.vulnerabilities.length * 2, 8) : 0;
      return baseSize + vulnBonus;
    };

    const getLinkColor = (d: any) => {
      switch (d.type) {
        case 'contains': return '#94a3b8'; // Slate
        case 'calls': return '#3b82f6'; // Blue
        case 'imports': return '#8b5cf6'; // Purple
        case 'depends': return '#ef4444'; // Red for vulnerability connections
        default: return '#9ca3af'; // Gray
      }
    };

    const getLinkWidth = (d: any) => {
      switch (d.type) {
        case 'contains': return 2;
        case 'calls': return 1.5;
        case 'imports': return 1;
        case 'depends': return 3; // Thicker for vulnerability connections
        default: return 1;
      }
    };

    // Create zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.1, 4])
      .on("zoom", (event) => {
        setCurrentTransform(event.transform);
        container.attr("transform", event.transform);
      });

    svg.call(zoom as any);

    // Create main container group
    const container = svg.append("g").attr("class", "graph-container");

    // Create enhanced force simulation with better layout
    const simulation = d3.forceSimulation(filteredNodes as any)
      .force("link", d3.forceLink(filteredLinks).id((d: any) => d.id).distance((d: any) => {
        // Shorter distance for module-function relationships
        if (d.type === 'contains') return 80;
        if (d.type === 'depends') return 120;
        return 100;
      }).strength(0.8))
      .force("charge", d3.forceManyBody().strength((d: any) => {
        // Stronger repulsion for larger nodes
        return -300 - (getNodeSize(d) * 10);
      }))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: any) => getNodeSize(d) + 5));

    // Create gradient definitions for enhanced visuals
    const defs = container.append("defs");
    
    // Shadow filter
    const filter = defs.append("filter")
      .attr("id", "drop-shadow")
      .attr("height", "130%");
    
    filter.append("feDropShadow")
      .attr("dx", 2)
      .attr("dy", 2)
      .attr("stdDeviation", 3)
      .attr("flood-color", "rgba(0,0,0,0.3)");

    // Create links with enhanced styling
    const link = container.append("g")
      .attr("class", "links")
      .selectAll("line")
      .data(filteredLinks)
      .enter().append("line")
      .attr("stroke", getLinkColor)
      .attr("stroke-width", getLinkWidth)
      .attr("stroke-opacity", 0.6)
      .attr("stroke-dasharray", (d: any) => d.type === 'depends' ? "5,5" : null);

    // Create nodes with enhanced styling
    const node = container.append("g")
      .attr("class", "nodes")
      .selectAll("g")
      .data(filteredNodes)
      .enter().append("g")
      .attr("class", "node")
      .style("cursor", "pointer")
      .call(d3.drag<any, any>()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended) as any);

    // Add circles for nodes
    node.append("circle")
      .attr("r", getNodeSize)
      .attr("fill", getNodeColor)
      .attr("stroke", "#fff")
      .attr("stroke-width", 2)
      .attr("filter", "url(#drop-shadow)")
      .on("click", (event, d) => {
        event.stopPropagation();
        setSelectedNode(d as GraphNode);
      })
      .on("mouseover", function(event, d) {
        d3.select(this)
          .transition()
          .duration(200)
          .attr("r", getNodeSize(d) * 1.2)
          .attr("stroke-width", 3);
      })
      .on("mouseout", function(event, d) {
        d3.select(this)
          .transition()
          .duration(200)
          .attr("r", getNodeSize(d))
          .attr("stroke-width", 2);
      });

    // Add labels with better positioning
    node.append("text")
      .text((d: any) => d.name)
      .attr("x", 0)
      .attr("y", (d: any) => getNodeSize(d) + 15)
      .attr("text-anchor", "middle")
      .attr("font-size", "12px")
      .attr("font-family", "Inter, sans-serif")
      .attr("font-weight", "500")
      .attr("fill", "#374151")
      .style("pointer-events", "none");

    // Add vulnerability indicators
    node.filter((d: any) => d.vulnerabilities && d.vulnerabilities.length > 0)
      .append("circle")
      .attr("r", 6)
      .attr("cx", (d: any) => getNodeSize(d) - 8)
      .attr("cy", (d: any) => -getNodeSize(d) + 8)
      .attr("fill", "#ef4444")
      .attr("stroke", "#fff")
      .attr("stroke-width", 1);

    // Add vulnerability count text
    node.filter((d: any) => d.vulnerabilities && d.vulnerabilities.length > 0)
      .append("text")
      .text((d: any) => d.vulnerabilities.length)
      .attr("x", (d: any) => getNodeSize(d) - 8)
      .attr("y", (d: any) => -getNodeSize(d) + 12)
      .attr("text-anchor", "middle")
      .attr("font-size", "10px")
      .attr("font-weight", "bold")
      .attr("fill", "white")
      .style("pointer-events", "none");

    // Simulation tick function
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Clear selection when clicking on empty space
    svg.on("click", () => {
      setSelectedNode(null);
    });

  }, [data, showConnections, filterBySeverity, generateEnhancedConnections, getFilteredNodes]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-96 bg-gray-50 dark:bg-gray-800 rounded-lg">
        <p className="text-gray-500 dark:text-gray-400">No graph data available</p>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="w-full h-full flex flex-col bg-white dark:bg-gray-900 rounded-lg shadow-lg">
      {/* Enhanced Controls */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <div className="flex items-center space-x-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Security Graph Visualization
          </h3>
          <div className="flex items-center space-x-2">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={showConnections}
                onChange={(e) => setShowConnections(e.target.checked)}
                className="mr-2"
              />
              <span className="text-sm text-gray-600 dark:text-gray-300">Show Connections</span>
            </label>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Severity Filter */}
          <select
            value={filterBySeverity}
            onChange={(e) => setFilterBySeverity(e.target.value)}
            className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="secure">Secure</option>
          </select>

          {/* Zoom Controls */}
          <div className="flex items-center space-x-1 bg-white dark:bg-gray-700 rounded-md border border-gray-300 dark:border-gray-600">
            <button
              onClick={handleZoomOut}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-l-md transition-colors"
              title="Zoom Out"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
              </svg>
            </button>
            <button
              onClick={handleZoomReset}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors text-xs font-medium"
              title="Reset Zoom"
            >
              1:1
            </button>
            <button
              onClick={handleZoomIn}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-r-md transition-colors"
              title="Zoom In"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Graph Container */}
      <div className="flex-1 relative overflow-hidden">
        <svg ref={svgRef} className="w-full h-full" />
        
        {/* Legend */}
        <div className="absolute top-4 left-4 bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Legend</h4>
          <div className="space-y-2 text-xs">
            <div className="flex items-center space-x-2">
              <div className="w-4 h-4 rounded-full bg-indigo-500"></div>
              <span className="text-gray-600 dark:text-gray-300">Module</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
              <span className="text-gray-600 dark:text-gray-300">Function</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 rounded-full bg-red-600"></div>
              <span className="text-gray-600 dark:text-gray-300">Has Vulnerabilities</span>
            </div>
            <div className="border-t border-gray-200 dark:border-gray-600 pt-2 mt-2">
              <div className="flex items-center space-x-2 mb-1">
                <div className="w-6 h-0.5 bg-slate-400"></div>
                <span className="text-gray-600 dark:text-gray-300">Contains</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-6 h-0.5 bg-red-400 border-dashed border-t-2 border-red-400"></div>
                <span className="text-gray-600 dark:text-gray-300">Shared Vulnerabilities</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <div className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 p-4">
          <div className="flex justify-between items-start">
            <div className="flex-1">
              <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                {selectedNode.name}
              </h4>
              <p className="text-sm text-gray-600 dark:text-gray-300 capitalize">
                {selectedNode.type} • {selectedNode.visibility || 'unknown'} visibility
              </p>
              
              {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 ? (
                <div className="mt-3">
                  <h5 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Vulnerabilities ({selectedNode.vulnerabilities.length})
                  </h5>
                  <ul className="space-y-1 text-sm">
                    {selectedNode.vulnerabilities.map((vuln, index) => {
                      let displayName = 'Unknown vulnerability';
                      let severity = 'medium';
                      try {
                        if (typeof vuln === 'string') {
                          displayName = vuln;
                        } else if (typeof vuln === 'object' && vuln !== null) {
                          displayName = vuln.name || vuln.id || 'Unknown vulnerability';
                          severity = vuln.severity || 'medium';
                        }
                      } catch (error) {
                        console.error('Error processing vulnerability:', vuln, error);
                        displayName = 'Error displaying vulnerability';
                      }
                      
                      const severityColor = {
                        critical: 'text-red-800 bg-red-100 dark:text-red-200 dark:bg-red-900',
                        high: 'text-red-700 bg-red-50 dark:text-red-300 dark:bg-red-800',
                        medium: 'text-orange-700 bg-orange-50 dark:text-orange-300 dark:bg-orange-800',
                        low: 'text-blue-700 bg-blue-50 dark:text-blue-300 dark:bg-blue-800'
                      }[severity] || 'text-gray-700 bg-gray-50 dark:text-gray-300 dark:bg-gray-800';
                      
                      return (
                        <li key={index} className={`px-2 py-1 rounded text-xs ${severityColor}`}>
                          <span className="font-medium">{severity.toUpperCase()}</span>: {String(displayName)}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ) : (
                <div className="mt-3">
                  <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    ✓ No vulnerabilities detected
                  </span>
                </div>
              )}
            </div>
            
            <button
              onClick={() => setSelectedNode(null)}
              className="ml-4 p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}