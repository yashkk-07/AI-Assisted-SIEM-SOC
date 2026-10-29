@echo off
title SentinelAI Development Launcher
echo =====================================================================
echo         SENTINEL-AI // DEVELOPMENT ENVIRONMENT LAUNCHER
echo =====================================================================
echo.
echo 1. Launching FastAPI Backend on http://localhost:8000 ...
start "SentinelAI Backend" cmd /k "cd /d "%~dp0backend" && python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload"

echo 2. Launching Vite Frontend on http://localhost:5173 ...
start "SentinelAI Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo Both services launched! 
echo Frontend Dev Server: http://localhost:5173
echo Backend API Docs:    http://localhost:8000/docs
echo.
pause
