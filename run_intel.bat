@echo off
title SOC Threat Intel Automator
cls

echo ============================================================
echo           STARTING THREAT INTEL ADVISORY TOOL
echo ============================================================
echo.

:: Change directory to where this batch file is located
cd /d "%~dp0"

:: Run the script using the 'py' launcher
py -u advisory_gen.py

echo.
echo ============================================================
echo ANALYSIS COMPLETE. PRESS ANY KEY TO CLOSE THIS WINDOW.
echo ============================================================
pause >nul