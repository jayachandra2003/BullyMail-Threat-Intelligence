@echo off
title BullyMail V2 - Intelligent Threat Detection Platform

cd /d "%~dp0"

if not exist venv (
    echo.
    echo ERROR: Virtual environment not found.
    echo Please run Install_Dependencies.bat first.
    pause
    exit
)

call venv\Scripts\activate

echo.
echo ==================================================================
echo         Starting BullyMail V2 Threat Detection System...
echo ==================================================================
echo.

python run.py

pause