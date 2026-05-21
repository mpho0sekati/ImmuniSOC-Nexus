@echo off
where docker >nul 2>&1
if %ERRORLEVEL%==0 (
  docker compose up --build %*
  exit /b %ERRORLEVEL%
)
where podman >nul 2>&1
if %ERRORLEVEL%==0 (
  podman compose up --build %*
  exit /b %ERRORLEVEL%
)
echo ERROR: No supported container CLI found. Install Docker or Podman and rerun this script.
exit /b 1
