@echo off
echo ============================================================
echo  SOC SYSTEM - SETUP SCRIPT
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download Python from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found.

:: Install dependencies
echo.
echo [STEP 1/3] Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Check your internet connection.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

:: Check Npcap
echo.
echo [STEP 2/3] Checking Npcap (required for network sniffing)...
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Npcap not detected!
    echo           Download and install Npcap from: https://npcap.com/#download
    echo           Make sure to check "Install Npcap in WinPcap API-compatible Mode" during install.
    echo.
)

:: Check for ML models
echo [STEP 3/3] Checking ML Models...
if not exist "ml\models\attack_model.pkl" (
    echo [WARNING] ML Models not found!
    echo           You need to train the models first. Run:
    echo             python scripts/train_attack_model.py
    echo             python scripts/train_ids_model.py
    echo           OR download pre-trained models from the GitHub Releases page.
    echo.
) else (
    echo [OK] ML Models found.
)

echo.
echo ============================================================
echo  Setup complete! To start the SOC system, run:
echo    python scripts/run_soc.py
echo  (Run as Administrator for network sniffing)
echo ============================================================
pause
