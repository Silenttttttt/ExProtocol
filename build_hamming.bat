@echo off
REM Build script for Windows - tries MinGW first, falls back to MSVC/clang

setlocal

set SCRIPT_DIR=%~dp0
set HAMMING_DIR=%SCRIPT_DIR%c_hamming

cd /d "%HAMMING_DIR%"

echo Building Hamming binary for Windows...

REM Try MinGW gcc first
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using MinGW gcc...
    gcc -Wall -Wextra -std=c99 -O3 -o hamming.exe hamming.c
    if %ERRORLEVEL% EQU 0 (
        if exist hamming.exe (
            echo Successfully built hamming.exe with MinGW
            goto :success
        )
    )
)

REM Try cl (MSVC)
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using MSVC cl...
    cl /W3 /O2 /TC hamming.c /Fe:hamming.exe /link
    if %ERRORLEVEL% EQU 0 (
        if exist hamming.exe (
            echo Successfully built hamming.exe with MSVC
            goto :success
        )
    )
)

REM Try clang
where clang >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using clang...
    clang -Wall -Wextra -std=c99 -O3 -o hamming.exe hamming.c
    if %ERRORLEVEL% EQU 0 (
        if exist hamming.exe (
            echo Successfully built hamming.exe with clang
            goto :success
        )
    )
)

echo Error: No suitable C compiler found.
echo Please install one of:
echo   - MinGW-w64 (gcc)
echo   - Microsoft Visual C++ (cl)
echo   - LLVM/Clang (clang)
exit /b 1

:success
endlocal

