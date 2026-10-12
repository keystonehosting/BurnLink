@echo off
setlocal
chcp 65001 >nul 2>&1
title BurnLink - keep this window open
if not exist "%~dp0runtime\python.exe" (
  echo BurnLink was not fully extracted.
  echo.
  echo Extract the entire ZIP to a folder, then run Start-BurnLink.cmd again.
  pause
  exit /b 1
)
"%~dp0runtime\python.exe" -B -I "%~dp0burnlink.py" %*
if errorlevel 1 (
  echo.
  echo BurnLink could not start. The error is shown above.
  pause
)
endlocal
