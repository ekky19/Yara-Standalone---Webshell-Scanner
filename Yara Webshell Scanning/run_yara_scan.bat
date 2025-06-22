@echo off
cls
title YARA Webroot Scanner

echo ****************************************
echo        Running YARA Webroot Scanner
echo ****************************************

:: Run the EXE from the modules directory
modules\yara_scanner.exe

echo.
echo =========================================
echo         Scan Complete.
echo =========================================
pause >nul
