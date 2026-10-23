@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js 20 or newer, then try again.
  pause
  exit /b 1
)
start "Luna Academy - My Affairs" /min cmd /c "node planner-server.js"
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:4174"
echo Планировщик открыт: http://127.0.0.1:4174
echo Чтобы остановить сервер, закройте окно процесса Node.js.
pause
