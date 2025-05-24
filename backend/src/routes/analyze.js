const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const graphBuilder = require('../services/graphBuilder');
const securityScanner = require('../services/securityScanner');
const enhancedSecurityScanner = require('../services/enhancedSecurityScanner');
const llmEnhancedSecurityScanner = require('../services/llmEnhancedSecurityScanner');
const moveBitEnhancedScanner = require('../services/moveBitEnhancedScanner');
const moveParser = require('../parsers/wasmBridge');

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const { fileIds, code, fileName } = req.body;
    
    let filesToAnalyze = [];
    
    if (fileIds && fileIds.length > 0) {
      // Analyze uploaded files
      const uploadsDir = path.join(__dirname, '../../uploads');
      
      for (const fileInfo of fileIds) {
        const filePath = path.join(uploadsDir, fileInfo.filename);
        const content = await fs.readFile(filePath, 'utf8');
        filesToAnalyze.push({
          name: fileInfo.originalName,
          content: content,
          path: filePath
        });
      }
    } else if (code) {
      // Analyze provided code
      filesToAnalyze.push({
        name: fileName || 'unnamed.move',
        content: code,
        path: null
      });
    } else {
      return res.status(400).json({ error: 'No files or code provided for analysis' });
    }

    console.log(`Analyzing ${filesToAnalyze.length} Move files`);

    // Parse Move files to AST
    const parsedFiles = [];
    for (const file of filesToAnalyze) {
      try {
        const ast = await moveParser.parseMove(file.content, file.name);
        parsedFiles.push({
          ...file,
          ast: ast
        });
      } catch (parseError) {
        console.error(`Parse error for ${file.name}:`, parseError);
        // Continue with other files, but note the error
        parsedFiles.push({
          ...file,
          ast: null,
          parseError: parseError.message
        });
      }
    }

    // Build dependency graph
    const graphData = graphBuilder.buildGraph(parsedFiles);
    
    // Run MoveBit-enhanced security analysis (combines static + LLM with 15 vulnerability categories)
    const allVulnerabilities = await moveBitEnhancedScanner.scanForVulnerabilities(parsedFiles);
    
    // Run enhanced AST-based security analysis for additional patterns
    let enhancedResults = { vulnerabilities: [], simulations: [], metadata: {} };
    try {
      enhancedResults = await enhancedSecurityScanner.scan(parsedFiles, graphData);
      
      // Add enhanced vulnerabilities that aren't duplicates
      const enhancedVulns = enhancedResults.vulnerabilities.filter(enhancedVuln => 
        !allVulnerabilities.some(existingVuln => 
          existingVuln.file === enhancedVuln.file && 
          Math.abs(existingVuln.line - enhancedVuln.line) <= 2 &&
          existingVuln.description.toLowerCase().includes(enhancedVuln.name.toLowerCase().split(' ')[0])
        )
      );
      
      allVulnerabilities.push(...enhancedVulns);
    } catch (error) {
      console.error('Enhanced security scan failed:', error);
    }
    
    // Associate vulnerabilities with graph nodes
    const nodesWithVulnerabilities = graphData.nodes.map(node => ({
      ...node,
      vulnerabilities: allVulnerabilities.filter(vuln => 
        vuln.file === node.file || 
        (node.type === 'function' && vuln.code?.includes(node.name)) ||
        (node.type === 'module' && vuln.file === node.file)
      )
    }));
    
    // Combine results
    const analysisResult = {
      files: parsedFiles.map(f => ({
        name: f.name,
        hasError: !!f.parseError,
        error: f.parseError
      })),
      ast: parsedFiles, // Include AST for frontend
      graph: graphData, // Include graph data
      modules: graphData.modules,
      functions: graphData.functions,
      nodes: nodesWithVulnerabilities,
      links: graphData.links,
      vulnerabilities: allVulnerabilities,
      simulations: enhancedResults.simulations || [], // Include simulation results
      metadata: {
        totalFiles: filesToAnalyze.length,
        totalModules: graphData.modules.length,
        totalFunctions: graphData.functions.length,
        totalNodes: nodesWithVulnerabilities.length,
        totalLinks: graphData.links.length,
        totalVulnerabilities: allVulnerabilities.length,
        llmEnhancedVulnerabilities: allVulnerabilities.filter(v => v.source === 'llm').length,
        staticVulnerabilities: allVulnerabilities.filter(v => v.source === 'static').length,
        moveBitCategories: [...new Set(allVulnerabilities.map(v => v.category).filter(Boolean))].length,
        enhancedVulnerabilities: enhancedResults.vulnerabilities.length,
        simulationCount: enhancedResults.simulations?.length || 0,
        analysisTimestamp: new Date().toISOString(),
        enhancedMetadata: enhancedResults.metadata,
        analysisTypes: ['static', 'llm', 'ast-enhanced', 'movebit-categories']
      }
    };

    const llmCount = allVulnerabilities.filter(v => v.source === 'llm').length;
    const staticCount = allVulnerabilities.filter(v => v.source === 'static').length;
    console.log(`Analysis complete: ${graphData.modules.length} modules, ${graphData.functions.length} functions, ${allVulnerabilities.length} total vulnerabilities (${staticCount} static + ${llmCount} LLM + ${enhancedResults.vulnerabilities.length} enhanced), ${enhancedResults.simulations?.length || 0} simulations`);

    res.json(analysisResult);

  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ 
      error: 'Analysis failed', 
      message: error.message 
    });
  }
});

module.exports = router;