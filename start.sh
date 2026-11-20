#!/usr/bin/env bash
# ==============================================================================
# AIPENT — Full System Unified Launcher
# Orchestrates the complete AIPENT stack with a single command:
#   1. MCP Tool Infrastructure (ZAP, ZAP MCP, Vulnify MCP, Curl MCP, Typst)
#   2. Docker MCP Gateway (SSE on port 8812)
#   3. AIPENT Backend API (FastAPI / Uvicorn on port 8010)
#   4. AIPENT Frontend Web Desk (React / Vite on port 5173)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

LOG_DIR="$ROOT_DIR/.logs"
mkdir -p "$LOG_DIR"

# Colors for terminal styling
BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

COMPOSE_FILE="$ROOT_DIR/mcp/compose.yaml"
WITH_LAB=false

# Port probe that does not require netcat: bash opens a TCP socket directly.
port_open() {
  local host="$1"
  local port="$2"
  if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
    return 0
  fi
  if command -v nc >/dev/null 2>&1; then
    nc -z "$host" "$port" 2>/dev/null
    return $?
  fi
  return 1
}

STOP_SERVICES=false
DOWN_SERVICES=false
STATUS_CHECK=false

print_banner() {
  echo -e "${CYAN}${BOLD}"
  cat << "EOF"
    ___    ____ ____  _______   ________
   /   |  /  _// __ \/ ____/ | / /_  __/
  / /| |  / / / /_/ / __/ /  |/ / / /   
 / ___ |_/ / / ____/ /___/ /|  / / /    
/_/  |_/___//_/   /_____/_/ |_/ /_/     
  AI-Powered Unified VAPT Agent
EOF
  echo -e "${NC}"
}

usage() {
  echo "Usage: ./start.sh [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --with-lab    Also start the OWASP Juice Shop lab container (port 3000)"
  echo "  --logs        Stream backend logs directly in the terminal"
  echo "  --status      Check the status of all stack components and exit"
  echo "  --stop        Stop background processes, MCP services, and the lab container"
  echo "  --down        Stop and tear down all Docker containers"
  echo "  -h, --help    Show this help message"
  echo ""
}

FOLLOW_LOGS=false

# Parse command line flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-lab)
      WITH_LAB=true
      shift
      ;;
    --logs|--follow-logs)
      FOLLOW_LOGS=true
      shift
      ;;
    --status)
      STATUS_CHECK=true
      shift
      ;;
    --stop)
      STOP_SERVICES=true
      shift
      ;;
    --down)
      DOWN_SERVICES=true
      shift
      ;;
    -h|--help)
      print_banner
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}[ERROR] Unknown option: $1${NC}"
      usage
      exit 1
      ;;
  esac
done

# Action: Check Status
if [ "$STATUS_CHECK" = true ]; then
  print_banner
  echo -e "${BOLD}Checking AIPENT Stack Status:${NC}"
  echo -n "  - Docker MCP Services: "
  if docker compose -f "$COMPOSE_FILE" ps --status running --services 2>/dev/null | grep -q "mcp-server"; then
    echo -e "${GREEN}Running${NC}"
  else
    echo -e "${YELLOW}Stopped${NC}"
  fi

  echo -n "  - Docker MCP Gateway (:8812): "
  if port_open 127.0.0.1 8812; then
    echo -e "${GREEN}Listening${NC}"
  else
    echo -e "${YELLOW}Not Listening${NC}"
  fi

  echo -n "  - Backend API (:8010): "
  if curl -fsS -m 2 http://127.0.0.1:8010/health >/dev/null 2>&1; then
    echo -e "${GREEN}Healthy${NC}"
  else
    echo -e "${YELLOW}Unreachable${NC}"
  fi

  echo -n "  - Frontend Desk (:5173): "
  if port_open 127.0.0.1 5173; then
    echo -e "${GREEN}Listening${NC}"
  else
    echo -e "${YELLOW}Not Listening${NC}"
  fi
  exit 0
fi

# Action: Stop
if [ "$STOP_SERVICES" = true ]; then
  print_banner
  echo -e "${YELLOW}[*] Stopping AIPENT processes and Docker services...${NC}"
  # Kill backend or gateway processes if running
  pkill -f "uvicorn app.main:app" 2>/dev/null || true
  pkill -f "docker mcp gateway run" 2>/dev/null || true
  docker compose -f "$COMPOSE_FILE" stop
  docker compose -f "$ROOT_DIR/docker-compose.yml" stop 2>/dev/null || true
  if [ -f "$ROOT_DIR/labs/lab.lvl1.yml" ]; then
    docker compose -f "$ROOT_DIR/labs/lab.lvl1.yml" stop 2>/dev/null || true
  elif [ -f "$ROOT_DIR/lab.lvl1.yml" ]; then
    docker compose -f "$ROOT_DIR/lab.lvl1.yml" stop 2>/dev/null || true
  fi
  echo -e "${GREEN}[+] Stopped successfully.${NC}"
  exit 0
fi

# Action: Down
if [ "$DOWN_SERVICES" = true ]; then
  print_banner
  echo -e "${YELLOW}[*] Tearing down AIPENT Docker containers...${NC}"
  pkill -f "uvicorn app.main:app" 2>/dev/null || true
  pkill -f "docker mcp gateway run" 2>/dev/null || true
  docker compose -f "$COMPOSE_FILE" down
  docker compose -f "$ROOT_DIR/docker-compose.yml" down 2>/dev/null || true
  if [ -f "$ROOT_DIR/labs/lab.lvl1.yml" ]; then
    docker compose -f "$ROOT_DIR/labs/lab.lvl1.yml" down 2>/dev/null || true
  elif [ -f "$ROOT_DIR/lab.lvl1.yml" ]; then
    docker compose -f "$ROOT_DIR/lab.lvl1.yml" down 2>/dev/null || true
  fi
  echo -e "${GREEN}[+] Stack torn down successfully.${NC}"
  exit 0
fi

print_banner

# ------------------------------------------------------------------------------
# 0. Pre-Flight Sanity Checks
# ------------------------------------------------------------------------------
echo -e "${BLUE}${BOLD}[0/4] Checking prerequisites...${NC}"

if ! docker info >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] Docker daemon is not running. Please start Docker first.${NC}"
  exit 1
fi

if ! command -v "docker" >/dev/null 2>&1 || ! docker mcp version >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] 'docker mcp' CLI plugin is required but not found.${NC}"
  exit 1
fi

# Ensure vulnify.db is available
if [[ ! -f "$ROOT_DIR/vulnify.db" || ! -s "$ROOT_DIR/vulnify.db" ]]; then
  echo -e "${YELLOW}[!] vulnify.db not detected. Running ./setup_vulnify.sh...${NC}"
  "$ROOT_DIR/setup_vulnify.sh"
fi

# Ensure environment files exist
if [[ ! -f "$ROOT_DIR/gateway/.env" && -f "$ROOT_DIR/gateway/.env.example" ]]; then
  cp "$ROOT_DIR/gateway/.env.example" "$ROOT_DIR/gateway/.env"
  echo -e "${YELLOW}[*] Created gateway/.env from template.${NC}"
fi

if [[ ! -f "$ROOT_DIR/backend/.env" && -f "$ROOT_DIR/backend/.env.example" ]]; then
  cp "$ROOT_DIR/backend/.env.example" "$ROOT_DIR/backend/.env"
  echo -e "${YELLOW}[*] Created backend/.env from template.${NC}"
fi

# Check Python environment
PYTHON_CMD="python3"
if [[ -f "$ROOT_DIR/backend/.venv/bin/python" ]]; then
  PYTHON_CMD="$ROOT_DIR/backend/.venv/bin/python"
fi

# Helper functions for polling readiness
wait_for_port() {
  local host="$1"
  local port="$2"
  local name="$3"
  local timeout="${4:-45}"
  local count=0
  printf "    Waiting for %s on %s:%s..." "$name" "$host" "$port"
  while ! port_open "$host" "$port"; do
    sleep 1
    count=$((count + 1))
    if [[ $count -ge $timeout ]]; then
      echo -e " ${RED}FAILED (timeout after ${timeout}s)${NC}"
      return 1
    fi
    printf "."
  done
  echo -e " ${GREEN}READY${NC}"
  return 0
}

wait_for_http() {
  local url="$1"
  local name="$2"
  local timeout="${3:-45}"
  local count=0
  printf "    Waiting for %s at %s..." "$name" "$url"
  while ! curl -fsS -m 2 "$url" >/dev/null 2>&1; do
    sleep 1
    count=$((count + 1))
    if [[ $count -ge $timeout ]]; then
      echo -e " ${RED}FAILED (timeout after ${timeout}s)${NC}"
      return 1
    fi
    printf "."
  done
  echo -e " ${GREEN}READY${NC}"
  return 0
}

# ------------------------------------------------------------------------------
# Process tracking & Cleanup Handler
# ------------------------------------------------------------------------------
GATEWAY_PID=""
BACKEND_PID=""
FRONTEND_PID=""
TAIL_PID=""

cleanup() {
  echo ""
  echo -e "${YELLOW}[*] Received shutdown signal. Terminating AIPENT host services...${NC}"
  
  if [[ -n "$TAIL_PID" ]] && kill -0 "$TAIL_PID" 2>/dev/null; then
    kill "$TAIL_PID" 2>/dev/null || true
  fi

  if [[ -n "$FRONTEND_PID" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  
  if [[ -n "$GATEWAY_PID" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
    kill "$GATEWAY_PID" 2>/dev/null || true
  fi

  # Fallback cleanup for any child processes spawned by uvicorn or vite
  pkill -P $$ 2>/dev/null || true
  
  echo -e "${GREEN}[+] Host services shut down cleanly.${NC}"
  echo -e "${CYAN}[TIP] Docker containers remain warm in background. Run './start.sh --stop' to stop them.${NC}"
  exit 0
}

trap cleanup INT TERM EXIT

# ------------------------------------------------------------------------------
# 1. Start Docker MCP Services
# ------------------------------------------------------------------------------
echo -e "${BLUE}${BOLD}[1/4] Starting MCP Tool Containers (ZAP, Vulnify, Curl, Typst)...${NC}"
docker compose --env-file "$ROOT_DIR/gateway/.env" -f "$COMPOSE_FILE" up -d

wait_for_port "127.0.0.1" 7458 "Curl MCP" 30
wait_for_port "127.0.0.1" 7457 "Vulnify MCP" 30
wait_for_port "127.0.0.1" 7456 "ZAP MCP Server" 60

# Optional Lab Container
if [ "$WITH_LAB" = true ]; then
  LAB_COMPOSE="$ROOT_DIR/labs/lab.lvl1.yml"
  if [ ! -f "$LAB_COMPOSE" ]; then
    LAB_COMPOSE="$ROOT_DIR/lab.lvl1.yml"
  fi
  echo -e "${CYAN}[*] Starting OWASP Juice Shop Lab Target...${NC}"
  docker compose -f "$LAB_COMPOSE" up -d
  wait_for_port "127.0.0.1" 3000 "Juice Shop Target" 30
fi

# ------------------------------------------------------------------------------
# 2. Start Docker MCP Gateway
# ------------------------------------------------------------------------------
echo -e "${BLUE}${BOLD}[2/4] Starting Docker MCP Gateway...${NC}"
if port_open 127.0.0.1 8812; then
  echo -e "    ${YELLOW}Port 8812 is already active; reusing existing gateway.${NC}"
else
  "$ROOT_DIR/gateway/start.sh" > "$LOG_DIR/gateway.log" 2>&1 &
  GATEWAY_PID=$!
  wait_for_port "127.0.0.1" 8812 "Docker MCP Gateway" 40
fi

# ------------------------------------------------------------------------------
# 3. Start Backend API
# ------------------------------------------------------------------------------
echo -e "${BLUE}${BOLD}[3/4] Starting AIPENT Backend API (FastAPI / Uvicorn)...${NC}"
if curl -fsS -m 2 http://127.0.0.1:8010/health >/dev/null 2>&1; then
  echo -e "    ${YELLOW}Backend is already running and healthy on port 8010.${NC}"
else
  (cd "$ROOT_DIR/backend" && PYTHONUNBUFFERED=1 "$PYTHON_CMD" -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8010 \
    --reload \
    --reload-dir src) \
    > "$LOG_DIR/backend.log" 2>&1 &
  BACKEND_PID=$!
  wait_for_http "http://127.0.0.1:8010/health" "Backend API" 35
fi

# If log streaming is enabled, tail backend.log in background
if [ "$FOLLOW_LOGS" = true ]; then
  tail -n 20 -f "$LOG_DIR/backend.log" &
  TAIL_PID=$!
fi

# ------------------------------------------------------------------------------
# 4. Start Frontend Web Desk
# ------------------------------------------------------------------------------
echo -e "${BLUE}${BOLD}[4/4] Starting AIPENT Frontend Web Desk...${NC}"

echo -e "\n${GREEN}${BOLD}==================================================================${NC}"
echo -e "${GREEN}${BOLD}          AIPENT STACK IS FULLY ONLINE & OPERATIONAL             ${NC}"
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "  ${BOLD}Web Mission Desk:${NC}  ${CYAN}http://localhost:5173${NC}"
echo -e "  ${BOLD}Backend API:${NC}       ${CYAN}http://127.0.0.1:8010${NC}"
echo -e "  ${BOLD}API Docs (Swagger):${NC}${CYAN}http://127.0.0.1:8010/docs${NC}"
echo -e "  ${BOLD}MCP Gateway SSE:${NC}   ${CYAN}http://127.0.0.1:8812/sse${NC}"
echo -e "  ${BOLD}Logs Directory:${NC}    ${CYAN}$LOG_DIR/${NC}"
echo -e "  ${BOLD}Live Backend Log:${NC}  ${YELLOW}tail -f .logs/backend.log${NC}"
echo -e "  ${BOLD}Agent Run Log:${NC}     ${YELLOW}tail -f backend/data/aipent.log${NC}"
echo -e "  ${BOLD}Stream in console:${NC} ${YELLOW}./start.sh --logs${NC}"
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "${YELLOW}Press [Ctrl+C] at any time to shut down the stack.${NC}\n"

cd "$ROOT_DIR/frontend"
# Run Vite directly so interactive developer logs appear in terminal.
# Keep this shell alive so the cleanup trap still stops backend and gateway.
npm run dev:web &
FRONTEND_PID=$!
wait "$FRONTEND_PID"
