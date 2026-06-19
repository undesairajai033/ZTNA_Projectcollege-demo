@echo off
title ZTNA College Portal Launcher

echo Starting ZTNA College Portal...
echo Please wait...

cd /d "%~dp0"

:: Start server in new window
start cmd /k node server.js

:: Wait for server to boot
timeout /t 3 >nul

:: Open browser
start http://localhost:3000/login

echo ---------------------------------
echo Portal Started Successfully 🚀
echo ---------------------------------

pause
