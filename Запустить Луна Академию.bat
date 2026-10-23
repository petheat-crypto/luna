@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js 20 or newer, then run this file again.
  pause
  exit /b 1
)
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start "" http://127.0.0.1:4173"
echo Starting Luna Academy at http://127.0.0.1:4173
echo Close this window to stop the local server.
node server.js
