#!/bin/bash

# Test script for the Fast HTTP Proxy with Plugin System

echo "🚀 Testing Fast HTTP Proxy with Plugin System"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROXY_URL="http://localhost:8070"

# Function to test endpoint
test_endpoint() {
    local method=$1
    local url=$2
    local headers=$3
    local description=$4
    
    echo -e "\n${BLUE}Testing: $description${NC}"
    echo "URL: $method $url"
    
    if [ -n "$headers" ]; then
        echo "Headers: $headers"
    fi
    
    # Make the request
    if [ -n "$headers" ]; then
        response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" -H "$headers" "$url")
    else
        response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" "$url")
    fi
    
    # Extract status code
    status_code=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
    body=$(echo "$response" | sed '/HTTP_STATUS:/d')
    
    # Color code the status
    if [ "$status_code" -ge 200 ] && [ "$status_code" -lt 300 ]; then
        echo -e "${GREEN}Status: $status_code${NC}"
    elif [ "$status_code" -ge 400 ] && [ "$status_code" -lt 500 ]; then
        echo -e "${YELLOW}Status: $status_code${NC}"
    else
        echo -e "${RED}Status: $status_code${NC}"
    fi
    
    if [ -n "$body" ]; then
        echo "Response: $body"
    fi
    echo "---"
}

# Check if proxy is running
echo -e "${YELLOW}Checking if proxy is running...${NC}"
if ! curl -s "$PROXY_URL" > /dev/null 2>&1; then
    echo -e "${RED}❌ Proxy is not running on $PROXY_URL${NC}"
    echo "Please start the proxy first:"
    echo "  go run main.go"
    echo "  # or"
    echo "  ./proxy"
    exit 1
fi

echo -e "${GREEN}✅ Proxy is running${NC}"

# Test 1: Public endpoint (should work)
test_endpoint "GET" "$PROXY_URL/public/health" "" "Public endpoint (no auth required)"

# Test 2: Secure endpoint without JWT (should fail)
test_endpoint "GET" "$PROXY_URL/secure/users" "" "Secure endpoint without JWT (should fail)"

# Test 3: Secure endpoint with invalid JWT (should fail)
test_endpoint "GET" "$PROXY_URL/secure/users" "Authorization: Bearer invalid-token" "Secure endpoint with invalid JWT (should fail)"

# Test 4: Admin endpoint without auth (should fail)
test_endpoint "GET" "$PROXY_URL/admin/config" "" "Admin endpoint without auth (should fail)"

# Test 5: Admin endpoint with basic auth (should work if IP is whitelisted)
test_endpoint "GET" "$PROXY_URL/admin/config" "Authorization: Basic YWRtaW46YWRtaW4xMjM=" "Admin endpoint with basic auth"

# Test 6: CORS preflight request
test_endpoint "OPTIONS" "$PROXY_URL/public/api" "Origin: https://example.com" "CORS preflight request"

# Test 7: Rate limiting test (make multiple requests)
echo -e "\n${BLUE}Testing rate limiting...${NC}"
echo "Making 5 requests to test rate limiting:"
for i in {1..5}; do
    echo -n "Request $i: "
    status=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/secure/health")
    if [ "$status" = "200" ]; then
        echo -e "${GREEN}$status${NC}"
    elif [ "$status" = "403" ]; then
        echo -e "${YELLOW}$status (rate limited)${NC}"
    else
        echo -e "${RED}$status${NC}"
    fi
    sleep 0.1
done

echo -e "\n${GREEN}✅ Testing completed!${NC}"
echo ""
echo "Note: Some tests may fail depending on your configuration:"
echo "- JWT tests need valid tokens"
echo "- IP whitelist tests depend on your client IP"
echo "- Rate limiting depends on your configuration"
echo ""
echo "Check the proxy logs for detailed information about plugin execution." 