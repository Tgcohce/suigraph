const express = require('express');
const suiscanFetcher = require('../services/suiscanFetcher');
const graphBuilder = require('../services/graphBuilder');
const securityScanner = require('../services/securityScanner');
const moveParser = require('../parsers/wasmBridge');

const router = express.Router();

router.post('/', async (req, res) => {
  try {
    const { input, type } = req.body;
    
    if (!input || !type) {
      return res.status(400).json({ 
        error: 'Missing required fields: input and type' 
      });
    }

    console.log(`Fetching contract: ${input} (type: ${type})`);

    // Fetch contract source code
    const contractData = await suiscanFetcher.fetchContract(input, type);
    
    if (!contractData || !contractData.sourceCode) {
      return res.status(404).json({ 
        error: 'Contract source code not found',
        message: 'The contract may not have source code available or the ID/URL is invalid'
      });
    }

    // Parse the fetched Move code
    const filesToAnalyze = contractData.modules.map(module => ({
      name: module.name,
      content: module.sourceCode,
      path: null
    }));

    console.log(`Analyzing ${filesToAnalyze.length} modules from contract`);

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
        parsedFiles.push({
          ...file,
          ast: null,
          parseError: parseError.message
        });
      }
    }

    // Build dependency graph
    const graphData = graphBuilder.buildGraph(parsedFiles);
    
    // Run security analysis
    const vulnerabilities = securityScanner.scanForVulnerabilities(parsedFiles);
    
    // Associate vulnerabilities with graph nodes
    const nodesWithVulnerabilities = graphData.nodes.map(node => ({
      ...node,
      vulnerabilities: vulnerabilities.filter(vuln => 
        vuln.file === node.file || 
        (node.type === 'function' && vuln.code?.includes(node.name)) ||
        (node.type === 'module' && vuln.file === node.file)
      )
    }));
    
    // Combine results
    const analysisResult = {
      contract: {
        address: contractData.address,
        packageId: contractData.packageId,
        network: contractData.network,
        fetchedAt: new Date().toISOString()
      },
      files: parsedFiles.map(f => ({
        name: f.name,
        hasError: !!f.parseError,
        error: f.parseError
      })),
      modules: graphData.modules,
      functions: graphData.functions,
      nodes: nodesWithVulnerabilities,
      links: graphData.links,
      vulnerabilities: vulnerabilities,
      metadata: {
        totalModules: graphData.modules.length,
        totalFunctions: graphData.functions.length,
        totalNodes: nodesWithVulnerabilities.length,
        totalLinks: graphData.links.length,
        totalVulnerabilities: vulnerabilities.length,
        analysisTimestamp: new Date().toISOString()
      }
    };

    console.log(`Contract analysis complete: ${graphData.modules.length} modules, ${vulnerabilities.length} vulnerabilities`);

    res.json(analysisResult);

  } catch (error) {
    console.error('Contract fetch error:', error);
    
    if (error.message.includes('not found') || error.message.includes('404')) {
      res.status(404).json({ 
        error: 'Contract not found', 
        message: error.message 
      });
    } else if (error.message.includes('network') || error.message.includes('timeout')) {
      res.status(503).json({ 
        error: 'Network error', 
        message: 'Unable to fetch contract data. Please try again later.' 
      });
    } else {
      res.status(500).json({ 
        error: 'Contract fetch failed', 
        message: error.message 
      });
    }
  }
});

module.exports = router;