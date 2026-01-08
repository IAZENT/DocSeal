#!/usr/bin/env pwsh
# PowerShell script to run DocSeal CLI

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = "$ScriptDir\src;$env:PYTHONPATH"

python -m docseal.cli.main $args
