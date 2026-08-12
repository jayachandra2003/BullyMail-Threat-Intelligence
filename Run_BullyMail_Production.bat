@echo off
title BullyMail V2 - Production Threat Intelligence Platform (Waitress WSGI)

cd /d "%~dp0"

if not exist venv (
    echo.
    echo ERROR: Virtual environment not found.
    echo Please run Install_Dependencies.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate

echo.
echo ==================================================================
echo   🛡️  Starting BullyMail V2 in Production Mode (Waitress WSGI)...
echo ==================================================================
echo.

python wsgi.py

pause
