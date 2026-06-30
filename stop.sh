#!/bin/bash

echo "🛑 Stopping all services..."

# Kill FastAPI
pkill -f uvicorn 2>/dev/null
echo "✅ FastAPI stopped"

# Kill Celery
pkill -f celery 2>/dev/null
echo "✅ Celery stopped"

# Kill Frontend
pkill -f "http.server 3000" 2>/dev/null
echo "✅ Frontend stopped"

echo "All services stopped!"
