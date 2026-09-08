@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 war2_extended_map_lab.py --restore --no-monitor
) else (
  python war2_extended_map_lab.py --restore --no-monitor
)
echo.
pause
