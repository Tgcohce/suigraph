/**
 * LLM-Enhanced Security Scanner Service
 * Combines static AST analysis with OpenAI GPT-4 based vulnerability detection
 */

const OpenAI = require('openai');
const securityScanner = require('./securityScanner');

class LLMEnhancedSecurityScanner {
  constructor() {
    // Initialize OpenAI client only if API key is available
    this.openai = null;
    this.llmAvailable = false;
    
    if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here') {
      try {
        this.openai = new OpenAI({
          apiKey: process.env.OPENAI_API_KEY
        });
        this.llmAvailable = true;
        console.log('✅ OpenAI client initialized for LLM analysis');
      } catch (error) {
        console.warn('⚠️ Failed to initialize OpenAI client:', error.message);
        this.llmAvailable = false;
      }
    } else {
      console.log('⚠️ OpenAI API key not configured, LLM analysis disabled');
    }
    
    // Token limits for chunking
    this.maxTokensPerChunk = 1500;
    this.estimatedTokensPerChar = 0.25; // Rough estimate for Move code
  }

  /**
   * Main scanning function that combines static and LLM analysis
   */
  async scanForVulnerabilities(parsedFiles) {
    console.log('🔍 Starting enhanced security scan with LLM analysis...');
    
    try {
      // Step 1: Run existing static scan first
      console.log('📊 Running static AST analysis...');
      const staticVulnerabilities = securityScanner.scanForVulnerabilities(parsedFiles);
      
      // Step 2: Run LLM-based analysis (if available)
      let llmVulnerabilities = [];
      if (this.llmAvailable) {
        console.log('🤖 Running LLM-based analysis...');
        llmVulnerabilities = await this.runLLMAnalysis(parsedFiles);
      } else {
        console.log('⚠️ Skipping LLM analysis (API key not configured)');
      }
      
      // Step 3: Combine and deduplicate results
      console.log('🔄 Combining and deduplicating results...');
      const combinedVulnerabilities = this.combineAndDeduplicateResults(
        staticVulnerabilities, 
        llmVulnerabilities
      );
      
      console.log(`✅ Enhanced scan complete: ${staticVulnerabilities.length} static + ${llmVulnerabilities.length} LLM = ${combinedVulnerabilities.length} total vulnerabilities`);
      
      return combinedVulnerabilities;
      
    } catch (error) {
      console.error('❌ LLM-enhanced scan failed:', error);
      // Fallback to static analysis only
      console.log('🔄 Falling back to static analysis only...');
      return securityScanner.scanForVulnerabilities(parsedFiles);
    }
  }

  /**
   * Run LLM analysis on all parsed files
   */
  async runLLMAnalysis(parsedFiles) {
    const allLLMVulnerabilities = [];
    
    for (const file of parsedFiles) {
      if (!file.content || file.parseError) continue;
      
      console.log(`🔍 Analyzing ${file.name} with LLM...`);
      
      // Split file into chunks
      const chunks = this.splitIntoChunks(file.content, file.name);
      
      // Analyze each chunk with LLM
      for (const chunk of chunks) {
        try {
          const chunkVulnerabilities = await this.analyzeChunkWithLLM(chunk);
          allLLMVulnerabilities.push(...chunkVulnerabilities);
        } catch (error) {
          console.error(`❌ Error analyzing chunk from ${file.name}:`, error.message);
          // Continue with other chunks
        }
      }
    }
    
    return allLLMVulnerabilities;
  }

  /**
   * Split file content into manageable chunks for LLM analysis
   */
  splitIntoChunks(content, fileName) {
    const lines = content.split('\n');
    const chunks = [];
    let currentChunk = '';
    let currentStartLine = 1;
    let currentLine = 1;
    let estimatedTokens = 0;

    for (const line of lines) {
      const lineTokens = line.length * this.estimatedTokensPerChar;
      
      // If adding this line would exceed token limit, save current chunk
      if (estimatedTokens + lineTokens > this.maxTokensPerChunk && currentChunk.length > 0) {
        chunks.push({
          content: currentChunk,
          fileName: fileName,
          startLine: currentStartLine,
          endLine: currentLine - 1
        });
        
        // Start new chunk
        currentChunk = line + '\n';
        currentStartLine = currentLine;
        estimatedTokens = lineTokens;
      } else {
        currentChunk += line + '\n';
        estimatedTokens += lineTokens;
      }
      
      currentLine++;
    }
    
    // Add final chunk if it has content
    if (currentChunk.trim().length > 0) {
      chunks.push({
        content: currentChunk,
        fileName: fileName,
        startLine: currentStartLine,
        endLine: currentLine - 1
      });
    }
    
    console.log(`📄 Split ${fileName} into ${chunks.length} chunks`);
    return chunks;
  }

  /**
   * Analyze a single chunk with OpenAI GPT-4
   */
  async analyzeChunkWithLLM(chunk) {
    const systemPrompt = `You are an expert smart contract engineer, bug hunter and auditor. In this MOVE contract on Sui find any vulnerabilities or problematic code.

You are analyzing Move smart contracts for security vulnerabilities. Focus on:

1. **Token Security**: Spoof-token misuse, unauthorized minting/burning, balance manipulation
2. **Access Controls**: Missing capability checks, unrestricted public functions, privilege escalation
3. **Financial Logic**: Reserve calculation errors, arithmetic overflow/underflow, precision loss
4. **DeFi Patterns**: Flash loan exploits, MEV vulnerabilities, slippage attacks, oracle manipulation
5. **Resource Management**: Improper object lifecycle, memory leaks, resource exhaustion
6. **Authority Misuse**: Excessive permissions, missing ownership validation, capability abuse
7. **Concurrency Issues**: Race conditions, reentrancy attacks, state inconsistencies

For each vulnerability found, provide:
- Exact line numbers within the provided chunk
- Clear description of the vulnerability
- Severity: high, medium, or low
- Even flag low-risk or suspicious patterns that warrant review

Be thorough but precise. Flag any suspicious patterns even if uncertain.`;

    const userPrompt = `Analyze the following Move code chunk for security vulnerabilities:

File: ${chunk.fileName}
Lines: ${chunk.startLine}-${chunk.endLine}

\`\`\`move
${chunk.content}
\`\`\`

Return findings in this exact JSON format:
[
  {
    "file": "${chunk.fileName}",
    "line": <absolute_line_number>,
    "description": "Clear description of the vulnerability",
    "severity": "high|medium|low"
  }
]

If no vulnerabilities are found, return an empty array: []`;

    try {
      const response = await this.openai.chat.completions.create({
        model: "gpt-4o-mini", // Use cost-effective GPT-4o mini
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        temperature: 0.1, // Low temperature for consistent results
        max_tokens: 1000,
        response_format: { type: "json_object" }
      });

      const content = response.choices[0].message.content;
      let vulnerabilities = [];

      try {
        // Try to parse as JSON object first
        const parsed = JSON.parse(content);
        if (Array.isArray(parsed)) {
          vulnerabilities = parsed;
        } else if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
          vulnerabilities = parsed.vulnerabilities;
        } else if (parsed.findings && Array.isArray(parsed.findings)) {
          vulnerabilities = parsed.findings;
        }
      } catch (parseError) {
        console.warn(`⚠️ Failed to parse LLM response as JSON:`, content.substring(0, 200));
        return [];
      }

      // Validate and adjust line numbers
      const validatedVulnerabilities = vulnerabilities.map(vuln => ({
        file: vuln.file || chunk.fileName,
        line: this.adjustLineNumber(vuln.line, chunk.startLine, chunk.endLine),
        description: vuln.description || 'LLM-detected vulnerability',
        severity: this.normalizeSeverity(vuln.severity),
        source: 'llm',
        id: `llm-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        name: this.generateVulnerabilityName(vuln.description),
        recommendation: this.generateRecommendation(vuln.description),
        confidence: 'medium' // LLM findings have medium confidence
      }));

      console.log(`🤖 LLM found ${validatedVulnerabilities.length} vulnerabilities in chunk`);
      return validatedVulnerabilities;

    } catch (error) {
      console.error('❌ OpenAI API error:', error.message);
      return [];
    }
  }

  /**
   * Adjust line numbers to be absolute within the file
   */
  adjustLineNumber(reportedLine, chunkStartLine, chunkEndLine) {
    if (typeof reportedLine !== 'number') return chunkStartLine;
    
    // If line seems to be relative to chunk, make it absolute
    if (reportedLine <= (chunkEndLine - chunkStartLine + 1)) {
      return chunkStartLine + reportedLine - 1;
    }
    
    // If line seems already absolute, validate it's within chunk range
    if (reportedLine >= chunkStartLine && reportedLine <= chunkEndLine) {
      return reportedLine;
    }
    
    // Default to chunk start if invalid
    return chunkStartLine;
  }

  /**
   * Normalize severity levels
   */
  normalizeSeverity(severity) {
    if (!severity) return 'medium';
    
    const normalized = severity.toLowerCase();
    if (['high', 'critical'].includes(normalized)) return 'high';
    if (['medium', 'moderate'].includes(normalized)) return 'medium';
    if (['low', 'minor', 'info'].includes(normalized)) return 'low';
    
    return 'medium'; // Default fallback
  }

  /**
   * Generate vulnerability name from description
   */
  generateVulnerabilityName(description) {
    if (!description) return 'LLM-Detected Vulnerability';
    
    // Extract key terms to create a concise name
    const desc = description.toLowerCase();
    
    if (desc.includes('unchecked') && desc.includes('transfer')) {
      return 'Unchecked Transfer Operation';
    }
    if (desc.includes('access control') || desc.includes('authorization')) {
      return 'Missing Access Control';
    }
    if (desc.includes('overflow') || desc.includes('underflow')) {
      return 'Arithmetic Overflow Risk';
    }
    if (desc.includes('reentrancy')) {
      return 'Reentrancy Vulnerability';
    }
    if (desc.includes('oracle') && desc.includes('manipulation')) {
      return 'Oracle Manipulation Risk';
    }
    if (desc.includes('privilege') || desc.includes('capability')) {
      return 'Privilege Escalation Risk';
    }
    
    // Generic name based on first few words
    const words = description.split(' ').slice(0, 4).join(' ');
    return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
  }

  /**
   * Generate recommendation from description
   */
  generateRecommendation(description) {
    if (!description) return 'Review and address the identified security concern';
    
    const desc = description.toLowerCase();
    
    if (desc.includes('access control') || desc.includes('authorization')) {
      return 'Add proper capability checks and assert statements';
    }
    if (desc.includes('overflow') || desc.includes('arithmetic')) {
      return 'Use checked arithmetic operations or add bounds validation';
    }
    if (desc.includes('reentrancy')) {
      return 'Implement reentrancy guards or use checks-effects-interactions pattern';
    }
    if (desc.includes('validation') || desc.includes('input')) {
      return 'Add input validation with assert statements';
    }
    
    return 'Review the flagged code and implement appropriate security measures';
  }

  /**
   * Combine static and LLM results, removing duplicates
   */
  combineAndDeduplicateResults(staticVulnerabilities, llmVulnerabilities) {
    // Convert static vulnerabilities to standardized format
    const normalizedStatic = staticVulnerabilities.map(vuln => ({
      ...vuln,
      source: 'static',
      file: vuln.file || 'unknown',
      line: vuln.line || 1,
      description: vuln.description || vuln.name || 'Static analysis vulnerability',
      severity: vuln.severity || 'medium'
    }));

    // Combine all vulnerabilities
    const allVulnerabilities = [...normalizedStatic, ...llmVulnerabilities];

    // Deduplicate based on file, line, and similar descriptions
    const deduplicatedVulnerabilities = [];
    const seenVulnerabilities = new Set();

    for (const vuln of allVulnerabilities) {
      const key = this.generateDeduplicationKey(vuln);
      
      if (!seenVulnerabilities.has(key)) {
        seenVulnerabilities.add(key);
        deduplicatedVulnerabilities.push(vuln);
      } else {
        // If duplicate found, potentially merge information
        const existingIndex = deduplicatedVulnerabilities.findIndex(
          existing => this.generateDeduplicationKey(existing) === key
        );
        
        if (existingIndex >= 0) {
          const existing = deduplicatedVulnerabilities[existingIndex];
          
          // Prefer higher severity
          if (this.severityScore(vuln.severity) > this.severityScore(existing.severity)) {
            deduplicatedVulnerabilities[existingIndex] = {
              ...existing,
              severity: vuln.severity,
              description: `${existing.description} | ${vuln.description}`
            };
          }
        }
      }
    }

    return deduplicatedVulnerabilities;
  }

  /**
   * Generate deduplication key for vulnerability
   */
  generateDeduplicationKey(vuln) {
    const normalizedDesc = vuln.description.toLowerCase()
      .replace(/[^a-z0-9\s]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    
    // Create key from file, line range, and description keywords
    const lineRange = Math.floor(vuln.line / 5) * 5; // Group by 5-line ranges
    const descWords = normalizedDesc.split(' ').slice(0, 3).join(' ');
    
    return `${vuln.file}:${lineRange}:${descWords}`;
  }

  /**
   * Convert severity to numeric score for comparison
   */
  severityScore(severity) {
    switch (severity?.toLowerCase()) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 2;
    }
  }

  /**
   * Check if OpenAI API is available
   */
  async checkLLMAvailability() {
    if (!this.llmAvailable || !this.openai) {
      return false;
    }

    try {
      // Test API with minimal request
      await this.openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "test" }],
        max_tokens: 1
      });
      return true;
    } catch (error) {
      console.warn('⚠️ OpenAI API not available:', error.message);
      this.llmAvailable = false;
      return false;
    }
  }
}

module.exports = new LLMEnhancedSecurityScanner();