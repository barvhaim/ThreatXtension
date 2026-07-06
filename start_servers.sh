#!/bin/bash

# ThreatXtension Server Startup Script
# This script kills any processes using the required ports and starts both servers

set -e  # Exit on error

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
echo -e "${BLUE}  ThreatXtension Server Startup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to kill process on port
kill_port() {
    local port=$1
    local process_name=$2
    
    echo -e "${YELLOW}Checking port ${port} for ${process_name}...${NC}"
    
    # Find process using the port
    local pid=$(lsof -ti:${port})
    
    if [ -n "$pid" ]; then
        echo -e "${RED}Found process ${pid} using port ${port}${NC}"
        echo -e "${YELLOW}Killing process...${NC}"
        kill -9 $pid 2>/dev/null || true
        sleep 1
        echo -e "${GREEN}✓ Port ${port} is now free${NC}"
    else
        echo -e "${GREEN}✓ Port ${port} is already free${NC}"
    fi
    echo ""
}

# Kill processes on required ports
kill_port $API_PORT "API Server"
kill_port $FRONTEND_PORT "Frontend Dev Server"

# Change to project directory
cd "$PROJECT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Starting Servers${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if tmux is available
if command -v tmux &> /dev/null; then
    echo -e "${GREEN}Using tmux for session management${NC}"
    
    # Kill existing tmux session if it exists
    tmux kill-session -t threatxtension 2>/dev/null || true
    
    # Create new tmux session
    tmux new-session -d -s threatxtension -n "ThreatXtension"
    
    # Split window horizontally
    tmux split-window -h -t threatxtension
    
    # Start API server in left pane
    tmux send-keys -t threatxtension:0.0 "cd $PROJECT_DIR && echo 'Starting API Server on port $API_PORT...' && uv run threatxtension serve --reload" C-m
    
    # Start frontend in right pane
    tmux send-keys -t threatxtension:0.1 "cd $PROJECT_DIR/frontend && echo 'Starting Frontend Dev Server on port $FRONTEND_PORT...' && npm run dev" C-m
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Servers Started Successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}API Server:${NC}      http://localhost:$API_PORT"
    echo -e "${BLUE}API Docs:${NC}        http://localhost:$API_PORT/docs"
    echo -e "${BLUE}Frontend:${NC}        http://localhost:$FRONTEND_PORT"
    echo ""
    echo -e "${YELLOW}To attach to the tmux session:${NC}"
    echo -e "  tmux attach -t threatxtension"
    echo ""
    echo -e "${YELLOW}To detach from tmux:${NC}"
    echo -e "  Press Ctrl+B, then D"
    echo ""
    echo -e "${YELLOW}To stop all servers:${NC}"
    echo -e "  ./stop_servers.sh"
    echo -e "  or: tmux kill-session -t threatxtension"
    echo ""
    
else
    echo -e "${YELLOW}tmux not found. Starting servers in background...${NC}"
    echo -e "${YELLOW}Note: Install tmux for better session management: brew install tmux${NC}"
    echo ""
    
    # Start API server in background
    echo -e "${BLUE}Starting API Server on port $API_PORT...${NC}"
    cd "$PROJECT_DIR"
    nohup uv run threatxtension serve > api_server.log 2>&1 &
    API_PID=$!
    echo $API_PID > .api_server.pid
    echo -e "${GREEN}✓ API Server started (PID: $API_PID)${NC}"
    
    # Start frontend in background
    echo -e "${BLUE}Starting Frontend Dev Server on port $FRONTEND_PORT...${NC}"
    cd "$PROJECT_DIR/frontend"
    nohup npm run dev > ../frontend_server.log 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > ../.frontend_server.pid
    echo -e "${GREEN}✓ Frontend Server started (PID: $FRONTEND_PID)${NC}"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Servers Started Successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}API Server:${NC}      http://localhost:$API_PORT"
    echo -e "${BLUE}API Docs:${NC}        http://localhost:$API_PORT/docs"
    echo -e "${BLUE}Frontend:${NC}        http://localhost:$FRONTEND_PORT"
    echo ""
    echo -e "${YELLOW}Logs:${NC}"
    echo -e "  API:      tail -f $PROJECT_DIR/api_server.log"
    echo -e "  Frontend: tail -f $PROJECT_DIR/frontend_server.log"
    echo ""
    echo -e "${YELLOW}To stop servers:${NC}"
    echo -e "  ./stop_servers.sh"
    echo ""
fi

# Wait a moment for servers to start
sleep 3

# Check if servers are running
echo -e "${BLUE}Checking server status...${NC}"
if curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API Server is responding${NC}"
else
    echo -e "${YELLOW}⚠ API Server may still be starting...${NC}"
fi

if curl -s http://localhost:$FRONTEND_PORT > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Frontend Server is responding${NC}"
else
    echo -e "${YELLOW}⚠ Frontend Server may still be starting...${NC}"
fi

echo ""
echo -e "${GREEN}🚀 ThreatXtension is ready!${NC}"

# Made with Bob
