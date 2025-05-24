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

export default function GraphViewer({ data }: GraphViewerProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [showConnections, setShowConnections] = useState(true);
  const [filterBySeverity, setFilterBySeverity] = useState('all');
  
  // Reset selected node when data changes
  useEffect(() => {
    setSelectedNode(null);
  }, [data]);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    setZoomLevel(prev => Math.min(prev * 1.5, 5));
  }, []);

  const handleZoomOut = useCallback(() => {
    setZoomLevel(prev => Math.max(prev / 1.5, 0.2));
  }, []);

  const handleZoomReset = useCallback(() => {
    setZoomLevel(1);
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
        func.group === mod.group || func.id.startsWith(mod.id)
      );
      
      if (parentModule) {
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
          
          const sharedVulns = this.findSharedVulnerabilities(func1.vulnerabilities, func2.vulnerabilities);
          
          if (sharedVulns.length > 0) {
            links.push({
              source: func1.id,
              target: func2.id,
              type: 'depends',
              sharedVulnerabilities: sharedVulns
            } as any);
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

    const width = 800;
    const height = 500;
    
    svg.attr("width", width).attr("height", height);

    // Process actual data from analysis
    let nodes: GraphNode[] = [];
    let links: GraphLink[] = [];

    if (data.nodes && data.nodes.length > 0) {
      // Use actual analysis data
      nodes = data.nodes.map(node => ({
        ...node,
        vulnerabilities: data.vulnerabilities?.filter(v => 
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
            vulnerabilities: data.vulnerabilities?.filter(v => 
              v.file === func.file && v.code?.includes(func.name)
            ) || []
          });

          // Create links from modules to functions
          const moduleNode = nodes.find(n => n.type === "module" && n.name === func.module);
          if (moduleNode) {
            links.push({
              source: moduleNode.id,
              target: func.id || `func_${func.module}_${func.name}`,
              type: "contains"
            });
          }
        });
      }
    }

    // Ensure we have some data to display
    if (nodes.length === 0) {
      nodes = [
        { id: "placeholder", name: "No data", type: "module", group: "empty", vulnerabilities: [] }
      ];
    }

    // Enhanced color scale for different node types with better visibility
    const getNodeColor = (d: any) => {
      if (d.vulnerabilities && d.vulnerabilities.length > 0) {
        // Color by highest severity vulnerability
        const severities = d.vulnerabilities.map(v => v.severity || 'low');
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
      const baseSize = d.type === 'module' ? 16 : 12;
      const vulnBonus = d.vulnerabilities?.length > 0 ? 4 : 0;
      return baseSize + vulnBonus;
    };

    // Create enhanced force simulation with better layout
    const simulation = d3.forceSimulation(nodes as any)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance((d: any) => {
        // Shorter distance for module-function relationships
        return d.type === 'contains' ? 80 : 120;
      }))
      .force("charge", d3.forceManyBody().strength((d: any) => {
        // Stronger repulsion for modules to spread them out
        return d.type === 'module' ? -400 : -200;
      }))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: any) => getNodeSize(d) + 5));

    // Add enhanced links with different styles
    const link = svg.append("g")
      .attr("class", "links")
      .selectAll("line")
      .data(links)
      .enter().append("line")
      .attr("stroke", (d: any) => {
        switch (d.type) {
          case 'contains': return '#6b7280'; // Gray for containment
          case 'calls': return '#3b82f6'; // Blue for function calls
          case 'imports': return '#8b5cf6'; // Purple for imports
          default: return '#9ca3af';
        }
      })
      .attr("stroke-opacity", 0.7)
      .attr("stroke-width", (d: any) => d.type === 'contains' ? 3 : 2)
      .attr("stroke-dasharray", (d: any) => d.type === 'imports' ? "5,5" : "none");

    // Add nodes
    const node = svg.append("g")
      .attr("class", "nodes")
      .selectAll("g")
      .data(nodes)
      .enter().append("g")
      .attr("class", "node")
      .style("cursor", "pointer")
      .call(d3.drag<any, any>()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended));

    // Add enhanced node circles with better styling
    node.append("circle")
      .attr("r", getNodeSize)
      .attr("fill", getNodeColor)
      .attr("stroke", "#fff")
      .attr("stroke-width", 3)
      .attr("filter", (d: any) => d.vulnerabilities?.length > 0 ? "drop-shadow(0 0 6px rgba(220, 38, 38, 0.6))" : "none");

    // Add enhanced labels with better positioning
    node.append("text")
      .text((d) => d.name)
      .attr("dy", (d: any) => -getNodeSize(d) - 5)
      .attr("text-anchor", "middle")
      .style("font-size", (d: any) => d.type === 'module' ? "14px" : "11px")
      .style("font-weight", (d: any) => d.type === 'module' ? "bold" : "600")
      .style("fill", "#1f2937")
      .style("text-shadow", "1px 1px 2px rgba(255,255,255,0.8)")
      .style("pointer-events", "none");

    // Add enhanced vulnerability indicators
    node.filter((d) => d.vulnerabilities?.length)
      .append("circle")
      .attr("r", 6)
      .attr("cx", (d: any) => getNodeSize(d) - 2)
      .attr("cy", (d: any) => -getNodeSize(d) + 2)
      .attr("fill", (d: any) => {
        const severities = d.vulnerabilities.map(v => v.severity || 'low');
        if (severities.includes('high')) return '#dc2626';
        if (severities.includes('medium')) return '#ea580c';
        return '#2563eb';
      })
      .attr("stroke", "#fff")
      .attr("stroke-width", 2)
      .style("filter", "drop-shadow(0 0 4px rgba(0,0,0,0.3))");

    // Node click handler
    node.on("click", (event, d) => {
      try {
        console.log("Node clicked:", d);
        console.log("Node vulnerabilities:", d.vulnerabilities);
        setSelectedNode(d as GraphNode);
      } catch (error) {
        console.error("Error handling node click:", error);
        console.log("Node data:", d);
      }
    });

    // Update positions on simulation tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node
        .attr("transform", (d: any) => `translate(${d.x},${d.y})`);
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

    return () => {
      simulation.stop();
    };
  }, [data]);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        <div className="text-center">
          <svg className="mx-auto h-12 w-12 text-gray-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          <p>Upload Move files or scan a contract to see the dependency graph</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full">
      <svg ref={svgRef} className="w-full h-full border border-gray-200 rounded" />
      
      {/* Enhanced Legend */}
      <div className="absolute top-4 right-4 bg-white/90 dark:bg-gray-900/90 backdrop-blur-sm p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
        <h4 className="text-sm font-semibold mb-3 text-gray-900 dark:text-white">Graph Legend</h4>
        <div className="space-y-2 text-xs">
          <div className="space-y-1">
            <p className="font-medium text-gray-700 dark:text-gray-300">Node Types:</p>
            <div className="flex items-center">
              <div className="w-4 h-4 rounded-full bg-indigo-500 mr-2 border-2 border-white shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">Module</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-emerald-500 mr-2 ml-0.5 border-2 border-white shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">Function</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-purple-500 mr-2 ml-0.5 border-2 border-white shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">Import</span>
            </div>
          </div>
          <div className="space-y-1 pt-2 border-t border-gray-200 dark:border-gray-700">
            <p className="font-medium text-gray-700 dark:text-gray-300">Security Status:</p>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-red-600 mr-2 ml-0.5 shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">High Risk</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-orange-500 mr-2 ml-0.5 shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">Medium Risk</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-blue-600 mr-2 ml-0.5 shadow-sm"></div>
              <span className="text-gray-600 dark:text-gray-400">Low Risk</span>
            </div>
          </div>
        </div>
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <div className="absolute bottom-4 left-4 bg-white p-4 rounded shadow border max-w-xs">
          <h4 className="font-semibold text-lg">{selectedNode.name || 'Unknown'}</h4>
          <div className="space-y-1 text-sm text-gray-600">
            <p className="capitalize">Type: {selectedNode.type}</p>
            {selectedNode.group && <p>Group: {selectedNode.group}</p>}
            {selectedNode.file && <p>File: {selectedNode.file}</p>}
            {selectedNode.visibility && <p>Visibility: {selectedNode.visibility}</p>}
          </div>
          
          {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 && (
            <div className="mt-3">
              <h5 className="text-sm font-medium text-red-600">
                Vulnerabilities ({selectedNode.vulnerabilities.length}):
              </h5>
              <ul className="mt-1 text-xs text-red-600 space-y-1 max-h-20 overflow-y-auto">
                {selectedNode.vulnerabilities.map((vuln, index) => {
                  let displayName = 'Unknown vulnerability';
                  try {
                    if (typeof vuln === 'string') {
                      displayName = vuln;
                    } else if (typeof vuln === 'object' && vuln !== null) {
                      displayName = vuln.name || vuln.id || 'Unknown vulnerability';
                    }
                  } catch (error) {
                    console.error('Error processing vulnerability:', vuln, error);
                    displayName = 'Error displaying vulnerability';
                  }
                  return (
                    <li key={index} className="truncate" title={String(displayName)}>
                      • {String(displayName)}
                    </li>
                  );
                })}
              </ul>
              <p className="text-xs text-gray-500 mt-1">
                Click "Security Report" tab for details
              </p>
            </div>
          )}
          
          {(!selectedNode.vulnerabilities || selectedNode.vulnerabilities.length === 0) && (
            <div className="mt-3">
              <p className="text-xs text-green-600">✓ No vulnerabilities found</p>
            </div>
          )}
          
          <button
            onClick={() => setSelectedNode(null)}
            className="mt-3 text-xs text-blue-600 hover:text-blue-800 underline"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
}