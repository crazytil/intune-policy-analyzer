#!/bin/bash
# Start both backend and frontend servers

set -u

BACKEND_PID=""
FRONTEND_PID=""
SHUTTING_DOWN=0

kill_tree() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0

  local children
  children=$(pgrep -P "$pid" 2>/dev/null || true)
  for child in $children; do
    kill_tree "$child"
  done

  kill "$pid" 2>/dev/null || true
}

wait_for_exit() {
  local pid="$1"
  [ -n "$pid" ] || return 0

  local attempt=0
  while kill -0 "$pid" 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 20 ]; then
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.2
  done
}

cleanup() {
  if [ "$SHUTTING_DOWN" -eq 1 ]; then
    return
  fi
  SHUTTING_DOWN=1

  echo ""
  echo "Shutting down..."

  kill_tree "${BACKEND_PID:-}"
  kill_tree "${FRONTEND_PID:-}"

  wait_for_exit "${BACKEND_PID:-}"
  wait_for_exit "${FRONTEND_PID:-}"

  wait "${BACKEND_PID:-}" 2>/dev/null || true
  wait "${FRONTEND_PID:-}" 2>/dev/null || true
}

echo "Starting Intune Policy Analyzer..."
echo ""

# Start backend
echo "[Backend] Starting FastAPI on port 8099..."
cd backend
source venv/bin/activate 2>/dev/null || { echo "Error: Run 'python3 -m venv venv && pip install -r requirements.txt' in backend/ first"; exit 1; }
uvicorn main:app --reload --port 8099 &
BACKEND_PID=$!
cd ..

# Start frontend
echo "[Frontend] Starting Vite dev server on port 5173..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "Intune Policy Analyzer is running!"
echo "  Frontend: http://localhost:5173"
echo "  Backend:  http://localhost:8099"
echo ""
echo "Press Ctrl+C to stop both servers."

# Trap Ctrl+C to kill both processes and any child processes they spawned
trap 'cleanup; exit 0' SIGINT SIGTERM
trap 'cleanup' EXIT

# Wait until either process exits, then stop the other one too.
wait "$BACKEND_PID" "$FRONTEND_PID"
