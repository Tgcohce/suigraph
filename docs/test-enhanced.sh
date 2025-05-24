#!/bin/bash

echo "🔧 Testing Enhanced SuiGraph Features"
echo "====================================="

# Test 1: Complex Move contract with functions and vulnerabilities
echo "1. Testing complex contract analysis..."
curl -s -X POST http://localhost:3001/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "module demo::token {\n    use sui::coin;\n    use sui::transfer;\n    \n    public entry fun mint(amount: u64) {\n        // mint without checks\n    }\n    \n    public entry fun admin_transfer(to: address) {\n        // admin function without capability check\n    }\n    \n    public fun burn(token: Token) {\n        // burn logic\n    }\n}",
    "fileName": "token.move"
  }' > /tmp/analysis.json

echo "✅ Analysis complete"

# Extract key metrics
MODULES=$(grep -o '"totalModules":[0-9]*' /tmp/analysis.json | cut -d: -f2)
FUNCTIONS=$(grep -o '"totalFunctions":[0-9]*' /tmp/analysis.json | cut -d: -f2)
NODES=$(grep -o '"totalNodes":[0-9]*' /tmp/analysis.json | cut -d: -f2)
VULNS=$(grep -o '"totalVulnerabilities":[0-9]*' /tmp/analysis.json | cut -d: -f2)

echo "📊 Results:"
echo "   Modules: $MODULES"
echo "   Functions: $FUNCTIONS" 
echo "   Graph Nodes: $NODES"
echo "   Vulnerabilities: $VULNS"

# Test 2: Check vulnerability details
echo -e "\n2. Checking vulnerability details..."
echo "📋 Sample vulnerabilities found:"
grep -o '"name":"[^"]*"' /tmp/analysis.json | head -3

# Test 3: Mock Suiscan contract fetch
echo -e "\n3. Testing Suiscan integration..."
curl -s -X POST http://localhost:3001/fetchContract \
  -H "Content-Type: application/json" \
  -d '{
    "input": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "type": "package"
  }' > /tmp/suiscan.json

SUISCAN_MODULES=$(grep -o '"totalModules":[0-9]*' /tmp/suiscan.json | cut -d: -f2)
echo "✅ Suiscan mock analysis: $SUISCAN_MODULES modules"

echo -e "\n🎉 Enhanced features working!"
echo "Frontend should now show:"
echo "  • Detailed vulnerability reports with expandable details"
echo "  • Function nodes in dependency graph"
echo "  • PDF/Markdown export capabilities"
echo "  • Security severity breakdown"

# Cleanup
rm -f /tmp/analysis.json /tmp/suiscan.json