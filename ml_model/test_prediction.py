import pandas as pd
import os
import sys

# Add current dir to path to import predictor
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from predictor import predict_attack

def run_tests():
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "UNSW_NB15_testing-set.csv")
    print(f"Loading dataset from: {dataset_path}")
    normal_row = None
    attack_row = None
    
    # Read in chunks to save memory and quickly find both labels
    for chunk in pd.read_csv(dataset_path, chunksize=5000):
        chunk.columns = chunk.columns.str.strip().str.replace('\ufeff', '')
        if normal_row is None and not chunk[chunk['label'] == 0].empty:
            normal_row = chunk[chunk['label'] == 0].iloc[0].to_dict()
        if attack_row is None and not chunk[chunk['label'] == 1].empty:
            attack_row = chunk[chunk['label'] == 1].iloc[0].to_dict()
        if normal_row is not None and attack_row is not None:
            break
            
    print("\n" + "="*50)
    print(" 🛡️ TEST 1: Normal Network Traffic")
    print("="*50)
    print(f"Sample Input (subset): protocol={normal_row.get('proto')}, service={normal_row.get('service')}, state={normal_row.get('state')}")
    res_normal = predict_attack(normal_row)
    for k, v in res_normal.items():
        print(f"  {k}: {v}")

    print("\n" + "="*50)
    print(" ⚠️ TEST 2: Malicious Attack Traffic")
    print("="*50)
    print(f"Actual Attack Category in Dataset: {attack_row.get('attack_cat')}")
    print(f"Sample Input (subset): protocol={attack_row.get('proto')}, service={attack_row.get('service')}, state={attack_row.get('state')}")
    res_attack = predict_attack(attack_row)
    for k, v in res_attack.items():
        print(f"  {k}: {v}")

    print("\n✅ Testing completed.")

if __name__ == "__main__":
    run_tests()
