#!/bin/bash

echo "🚀 Starting Frontend..."

# Kill any existing frontend
pkill -f "http.server 3000" 2>/dev/null

# Start frontend
cd ~/Workplace/pii-redaction-service/frontend
python3 -m http.server 3000 &

# Wait for server to start
sleep 2

# Open browser
xdg-open http://localhost:3000

echo "✅ Frontend running at http://localhost:3000"
echo "Press Ctrl+C to stop the server"
wait
