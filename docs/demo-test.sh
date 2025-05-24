#!/bin/bash

# SuiGraph Demo Test Script

echo "🧪 Testing SuiGraph Backend API"
echo "================================"

# Check if backend is running
echo "1. Health Check..."
curl -s http://localhost:3001/status | jq '.'

echo -e "\n2. Testing File Analysis..."
# Test analysis with sample Move code
curl -s -X POST http://localhost:3001/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "module test::example {\n    public entry fun hello() {\n        // Hello world\n    }\n}",
    "fileName": "test.move"
  }' | jq '.'

echo -e "\n3. Testing Suiscan Integration..."
# Test with a mock package ID
curl -s -X POST http://localhost:3001/fetchContract \
  -H "Content-Type: application/json" \
  -d '{
    "input": "0x0000000000000000000000000000000000000000000000000000000000000002",
    "type": "package"
  }' | jq '.'

echo -e "\n✅ Demo test complete!"
echo "Frontend should be accessible at: http://localhost:3000"
echo "Backend API available at: http://localhost:3001"