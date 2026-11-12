@echo off
setlocal
pushd "%~dp0" || exit /b 1

set "CGO_ENABLED=0"
set "GOAMD64=v1"
set "GOARM64=v8.0"
if not exist "dist\" (
    mkdir "dist"
    if errorlevel 1 goto :failed
)

call :build windows amd64 goproxy-windows-amd64.exe
if errorlevel 1 goto :failed
call :build linux amd64 goproxy-linux-amd64
if errorlevel 1 goto :failed
call :build linux arm64 goproxy-linux-arm64
if errorlevel 1 goto :failed

popd
exit /b 0

:build
set "GOOS=%~1"
set "GOARCH=%~2"
echo Building %GOOS%_%GOARCH% ...
go build -trimpath -o "dist\%~3" .
exit /b %errorlevel%

:failed
set "build_error=%errorlevel%"
popd
exit /b %build_error%
