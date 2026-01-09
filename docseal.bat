@echo off
REM Windows batch script to run DocSeal CLI

setlocal
set "SCRIPT_DIR=%~dp0"
set "PYTHONPATH=%SCRIPT_DIR%src;%PYTHONPATH%"

python -m docseal.cli.main %*
