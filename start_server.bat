@echo off
title May chu P-Sieve Anti-Scam Server
set PORT=8001
if not "%~1"=="" set PORT=%~1
echo ================================================================
echo   DANG KHOI DONG MAY CHU P-SIEVE (API V1 & WEB SHIELD)
echo   Dia chi truy cap: http://127.0.0.1:%PORT%
echo   (Extension da duoc cai dat tu dong ho tro ca cong 8001 va 8000)
echo   De dung may chu: Nhan to hop phim Ctrl + C
echo ================================================================
python -m uvicorn app.main:app --host 127.0.0.1 --port %PORT% --reload
pause
