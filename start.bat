@echo off
color 0B
title Setup and Run

echo update pip
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo Error: fail to update pip, please check python install
    pause
    exit /b 1
)

echo Installing lib
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies. Please ensure Python and pip are correctly set up.
    pause
    exit /b 1
)

echo run gen.py
python gen.py

pause
exit /b 0