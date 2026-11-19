@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "ROOT=%CD%"
set "CARGO_TARGET_DIR=%ROOT%\target"
set "INSTALLER=%CARGO_TARGET_DIR%\release\bundle\nsis\Keybridge_1.3.1_x64-setup.exe"
set "PATH=%USERPROFILE%\.cargo\bin;C:\Program Files\nodejs;%PATH%"
set "CMAKE_GENERATOR=Visual Studio 17 2022"
set "CMAKE_GENERATOR_PLATFORM=x64"
set "BINDGEN_EXTRA_CLANG_ARGS=-D_MSVC_STL_USE_ABORT_AS_DOOM_FUNCTION"
set "LIBCLANG_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin"

echo.
echo Keybridge — gerar instalador NSIS
echo.

for /d %%D in ("%ROOT%\target\release\build\btls-sys\*") do (
  if exist "%%D\out\build\CMakeCache.txt" (
    findstr /C:"CMAKE_GENERATOR:INTERNAL=Visual Studio 18 2026" "%%D\out\build\CMakeCache.txt" >nul && rmdir /s /q "%%D\out\build"
  )
)

cd /d "%ROOT%\apps\desktop"
call npm.cmd run tauri:build -- --bundles nsis --config "%ROOT%\target\tmp\local-bundle.json"
if errorlevel 1 goto :fail

if not exist "%INSTALLER%" (
  echo Nao encontrei o instalador:
  echo %INSTALLER%
  goto :fail
)

echo.
echo Instalador pronto:
echo %INSTALLER%
echo.
echo Feche o Keybridge e rode o instalador.
start "" explorer.exe /select,"%INSTALLER%"
exit /b 0

:fail
echo.
echo A geracao do instalador falhou.
exit /b 1
