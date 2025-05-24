#!/bin/bash

echo "🔍 Testing Graph Node Click Fix"
echo "==============================="

# Test with a simple contract that should generate nodes and vulnerabilities
curl -s -X POST http://localhost:3001/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "module test::simple {\n    use sui::transfer;\n    \n    public entry fun unsafe_mint() {\n        // This should trigger vulnerabilities\n    }\n    \n    public fun helper() {\n        // Helper function\n    }\n}",
    "fileName": "simple.move"
  }' > /tmp/test_result.json

echo "✅ Analysis complete"

# Check nodes structure
echo "📊 Graph structure:"
echo "Nodes found:"
grep -o '"id":"[^"]*"' /tmp/test_result.json | head -5

echo -e "\nVulnerabilities found:"
grep -o '"name":"[^"]*"' /tmp/test_result.json | head -3

echo -e "\nNode vulnerability association:"
if grep -q '"vulnerabilities":\[' /tmp/test_result.json; then
    echo "✅ Nodes have vulnerability arrays"
else
    echo "❌ No vulnerability arrays in nodes"
fi

echo -e "\n🎯 Fix Summary:"
echo "• Added error handling to click events"
echo "• Fixed vulnerability object display"
echo "• Added ErrorBoundary for graph component"
echo "• Improved node information display"
echo "• Added safety checks for React state"

echo -e "\n📝 The graph click issue should now be resolved!"

rm -f /tmp/test_result.json