"""Verify the fix: check the previously-broken records."""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))

from app.database.db import col, connect_db

async def main():
    await connect_db()
    
    print("--- Previously broken simulated records (now fixed) ---")
    cursor = col("agent_actions").find({"simulated": True}).sort("timestamp", -1)
    async for doc in cursor:
        r = str(doc.get('result', '')).encode('ascii', 'replace').decode()
        print(f"  agent_type={doc.get('agent_type'):<20} action={doc.get('action'):<18} success={doc.get('success')}")

asyncio.run(main())
