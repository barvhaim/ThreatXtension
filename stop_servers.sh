#!/bin/bash

# ThreatXtension Server Stop Script
# This script stops all running ThreatXtension servers

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
API_PORT=8007
FRONTEND_PORT=5173
PROJECT_DIR="/Users/itzhakch/ThreatXtension"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Stopping ThreatXtension Servers${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to kill process on port
kill_port() {
    local port=$1
    local process_name=$2
    
    echo -e "${YELLOW}Stopping ${process_name} on port ${port}...${NC}"
    
    # Find process using the port
    local pid=$(lsof -ti:${port})
    
    if [ -n "$pid" ]; then
        echo -e "${YELLOW}Found process ${pid}${NC}"
        kill -9 $pid 2>/dev/null || true
        sleep 1
        echo -e "${GREEN}✓ ${process_name} stopped${NC}"
    else
        echo -e "${GREEN}✓ No process found on port ${port}${NC}"
    fi
    echo ""
}

# Check for tmux session
if command -v tmux &> /dev/null; then
    if tmux has-session -t threatxtension 2>/dev/null; then
        echo -e "${YELLOW}Killing tmux session 'threatxtension'...${NC}"
        tmux kill-session -t threatxtension
        echo -e "${GREEN}✓ Tmux session killed${NC}"
        echo ""
    fi
fi

# Kill processes on ports
kill_port $API_PORT "API Server"
kill_port $FRONTEND_PORT "Frontend Dev Server"

# Clean up PID files if they exist
cd "$PROJECT_DIR"
if [ -f .api_server.pid ]; then
    API_PID=$(cat .api_server.pid)
    kill -9 $API_PID 2>/dev/null || true
    rm .api_server.pid
    echo -e "${GREEN}✓ Cleaned up API server PID file${NC}"
fi

if [ -f .frontend_server.pid ]; then
    FRONTEND_PID=$(cat .frontend_server.pid)
    kill -9 $FRONTEND_PID 2>/dev/null || true
    rm .frontend_server.pid
    echo -e "${GREEN}✓ Cleaned up frontend server PID file${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All Servers Stopped${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}To start servers again:${NC}"
echo -e "  ./start_servers.sh"
echo ""

# Made with Bob
