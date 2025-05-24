/**
 * GraphBuilder Service
 * Builds dependency graphs from parsed Move AST data
 */

class GraphBuilder {
  buildGraph(parsedFiles) {
    const modules = [];
    const functions = [];
    const nodes = [];
    const links = [];
    
    // Process each parsed file
    for (const file of parsedFiles) {
      if (!file.ast || file.parseError) {
        console.warn(`Skipping file ${file.name} due to parse error`);
        continue;
      }
      
      this.processFile(file, modules, functions, nodes, links);
    }
    
    return {
      modules,
      functions,
      nodes,
      links
    };
  }
  
  processFile(file, modules, functions, nodes, links) {
    const ast = file.ast;
    
    // For now, we'll create a simplified AST structure
    // In a real implementation, this would parse the actual Move AST
    
    // Extract module information
    const moduleInfo = this.extractModuleInfo(file);
    if (moduleInfo) {
      modules.push(moduleInfo);
      nodes.push({
        id: moduleInfo.id,
        name: moduleInfo.name,
        type: 'module',
        group: moduleInfo.name.toLowerCase(),
        file: file.name,
        vulnerabilities: []
      });
    }
    
    // Extract function information
    const fileFunctions = this.extractFunctions(file, moduleInfo);
    functions.push(...fileFunctions);
    
    // Add function nodes
    for (const func of fileFunctions) {
      nodes.push({
        id: func.id,
        name: func.name,
        type: 'function',
        group: func.module,
        visibility: func.visibility,
        file: file.name,
        vulnerabilities: []
      });
      
      // Add link from module to function
      if (moduleInfo) {
        links.push({
          source: moduleInfo.id,
          target: func.id,
          type: 'contains'
        });
      }
    }
    
    // Extract function calls and imports
    this.extractDependencies(file, functions, links);
  }
  
  extractModuleInfo(file) {
    // Simple regex-based parsing for demo
    // In production, use proper Move AST parser
    const moduleMatch = file.content.match(/module\s+([a-zA-Z_][a-zA-Z0-9_]*::)?([a-zA-Z_][a-zA-Z0-9_]*)/);
    
    if (moduleMatch) {
      const fullName = moduleMatch[0].replace('module ', '');
      const moduleName = moduleMatch[2];
      
      return {
        id: `module_${moduleName}`,
        name: moduleName,
        fullName: fullName,
        file: file.name,
        address: moduleMatch[1] ? moduleMatch[1].slice(0, -2) : null
      };
    }
    
    return null;
  }
  
  extractFunctions(file, moduleInfo) {
    const functions = [];
    
    // Simple regex to find function definitions
    const functionRegex = /(?:public\s+)?(?:entry\s+)?fun\s+([a-zA-Z_][a-zA-Z0-9_]*)/g;
    let match;
    
    while ((match = functionRegex.exec(file.content)) !== null) {
      const functionName = match[1];
      const isPublic = match[0].includes('public');
      const isEntry = match[0].includes('entry');
      
      functions.push({
        id: `func_${moduleInfo ? moduleInfo.name : 'unknown'}_${functionName}`,
        name: functionName,
        module: moduleInfo ? moduleInfo.name : 'unknown',
        visibility: isPublic ? 'public' : 'private',
        isEntry: isEntry,
        file: file.name,
        line: this.getLineNumber(file.content, match.index)
      });
    }
    
    return functions;
  }
  
  extractDependencies(file, allFunctions, links) {
    // Simple pattern matching for function calls
    // This would be much more sophisticated with a real AST
    
    const callRegex = /([a-zA-Z_][a-zA-Z0-9_]*)::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
    let match;
    
    while ((match = callRegex.exec(file.content)) !== null) {
      const calledModule = match[1];
      const calledFunction = match[2];
      
      // Find the corresponding function in our list
      const targetFunction = allFunctions.find(f => 
        f.module === calledModule && f.name === calledFunction
      );
      
      if (targetFunction) {
        // Find the calling function (this is simplified)
        const callingFunction = this.findCallingFunction(file, match.index, allFunctions);
        
        if (callingFunction) {
          links.push({
            source: callingFunction.id,
            target: targetFunction.id,
            type: 'calls'
          });
        }
      }
    }
  }
  
  findCallingFunction(file, callIndex, functions) {
    // Find which function contains this call
    // This is a simplified implementation
    const lines = file.content.split('\n');
    const callLine = this.getLineNumber(file.content, callIndex);
    
    // Look for the most recent function definition before this line
    for (const func of functions.reverse()) {
      if (func.file === file.name && func.line < callLine) {
        return func;
      }
    }
    
    return null;
  }
  
  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }
}

module.exports = new GraphBuilder();