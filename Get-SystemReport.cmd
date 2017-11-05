powershell -ExecutionPolicy Bypass -File "%~d0%~p0%~n0.ps1"
@if not "%errorlevel%"=="0" (
echo command failed
echo 
pause
) else (
echo command success
echo 
exit /B %errorlevel%)
