@echo off
title SentinelAI SIEM & Mini-SOC Platform
echo =====================================================================
echo           SENTINEL-AI // AUTONOMOUS MINI-SOC PLATFORM
echo =====================================================================
echo.
echo Starting SentinelAI SIEM Engine & Mini-SOC Dashboard on http://localhost:8000 ...
echo Real-time Ingestion, Correlation, Deduplication, and AI Copilot Online!
echo.

cd /d "%~dp0backend"
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
