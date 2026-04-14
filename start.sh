#!/bin/bash
# Start both backend and frontend servers

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

# Trap Ctrl+C to kill both processes
trap "echo ''; echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for either process to exit
wait
