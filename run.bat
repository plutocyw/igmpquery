@echo off
CLS
CALL igmpquery.exe
TIMEOUT 125

:BEGIN
CALL igmpquery.exe -q
TIMEOUT 125
goto :BEGIN
