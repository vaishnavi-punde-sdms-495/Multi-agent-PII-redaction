#!/bin/bash

echo "🚀 Starting Backend Services..."

cd ~/Workplace/pii-redaction-service

# Activate virtual environment
source venv/bin/activate

# Start Redis if not running
if ! redis-cli ping &> /dev/null; then
    echo "Starting Redis..."
    sudo systemctl start redis-server
fi

# Start PostgreSQL if not running
if ! pg_isready &> /dev/null; then
    echo "Starting PostgreSQL..."
    sudo systemctl start postgresql
fi

# Start FastAPI
cd backend
echo "Starting FastAPI..."
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &

# Wait for FastAPI to start
sleep 5

# Start Celery
echo "Starting Celery worker..."
celery -A tasks.celery_app worker --loglevel=info --concurrency=1 &

echo ""
echo "✅ Backend Services Running:"
echo "  - FastAPI: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - Celery Worker: Running"
echo ""
echo "Press Ctrl+C to stop all services"
wait
