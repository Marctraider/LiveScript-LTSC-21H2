@echo off
pushd %~dp0
set "dir=%CD%"
rem /// Unrestricted script execution
powershell.exe -Command set-ExecutionPolicy Unrestricted -Force
rem /// Execute elevated script with SYSTEM privileges
.\PsExec.exe -accepteula -i -s -w "%cd%" PowerShell.exe -windowstyle maximized -command "&'%dir%\Elevated.ps1'
rem /// Execute unelevated script with Administrator privileges
PowerShell.exe -command "&'%dir%\Unelevated.ps1'