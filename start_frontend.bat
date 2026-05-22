@echo off
echo Starting SIEM Frontend Dashboard...
cd siem_frontend
call npm install
npm run dev
.\start_frontend.bat
python scripts/simulate_attack.py --attack full_chain
