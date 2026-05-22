@echo off
echo Starting AI-Powered SIEM Backend...
cd backend
pip install -r requirements.txt
cd ..
python -m ml_model.train_multi_dataset
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
