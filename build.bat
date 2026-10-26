@echo off
setlocal
cd /d "%~dp0"

set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [ERROR] .NET Framework C# compiler not found.
  pause
  exit /b 1
)

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 ^
 /win32manifest:app.manifest ^
 /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:Microsoft.CSharp.dll ^
 /out:NetGuardAssistant.exe NetGuard.cs

if errorlevel 1 (
  echo [ERROR] build failed.
  pause
  exit /b 1
)
echo [OK] NetGuardAssistant.exe
pause
