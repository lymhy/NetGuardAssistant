@echo off
setlocal
cd /d "%~dp0"
title NetGuardAssistant Publish
rem NOTE: messages are ASCII-only on purpose. cmd.exe parses .bat files in the
rem legacy ANSI codepage; Chinese text in a UTF-8 .bat gets garbled and breaks
rem the script. The app UI itself is Chinese and unaffected.

tasklist /FI "IMAGENAME eq NetGuardAssistant.exe" 2>nul | find /I "NetGuardAssistant.exe" >nul
if not errorlevel 1 goto running

echo [1/3] Cleaning old build artifacts...
del /f /q NetGuardAssistant.new.exe 2>nul
del /f /q NetGuardAssistant.pdb 2>nul
del /f /q *.tmp 2>nul
del /f /q *.bak 2>nul

echo [2/3] Compiling...
set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" goto nocsc

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /win32manifest:app.manifest /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:Microsoft.CSharp.dll /out:NetGuardAssistant.new.exe NetGuard.cs
if errorlevel 1 goto compilefail

if exist NetGuardAssistant.exe del /f /q NetGuardAssistant.exe
ren NetGuardAssistant.new.exe NetGuardAssistant.exe
if errorlevel 1 goto swapfail

echo [3/3] Publish OK. Files in this folder:
dir /b
echo.
echo Folder: %cd%
pause
exit /b 0

:running
echo [HINT] NetGuardAssistant is running. Exit it from the tray icon, then publish again.
pause
exit /b 1

:nocsc
echo [ERROR] .NET Framework C# compiler not found.
pause
exit /b 1

:compilefail
echo [ERROR] Compile failed. Old NetGuardAssistant.exe kept untouched.
if exist NetGuardAssistant.new.exe del /f /q NetGuardAssistant.new.exe
pause
exit /b 1

:swapfail
echo [ERROR] Failed to replace old exe (locked?). New build kept as NetGuardAssistant.new.exe
pause
exit /b 1
