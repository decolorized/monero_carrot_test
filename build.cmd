@echo off
rem Double-click or run: build.cmd [-Port COM5] [-Usb hwcdc] [-Psram qspi]
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
if errorlevel 1 pause
