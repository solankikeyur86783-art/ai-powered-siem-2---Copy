#!/bin/bash
echo "Starting AI-Powered SIEM Backend..."
cd backend
pip install -r requirements.txt
cd ..
python -m ml_model.train_model
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
 .\start_backend.bat 
 