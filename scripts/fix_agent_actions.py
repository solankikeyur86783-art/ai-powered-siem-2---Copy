"""Fix existing agent_actions that are missing success/agent_type fields."""
import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))

from app.database.db import col, connect_db

async def main():
    await connect_db()
    
    # 1. Fix records missing 'success' field — set based on 'status'
    result1 = await col("agent_actions").update_many(
        {"success": {"$exists": False}},
        [{"$set": {"success": {"$eq": ["$status", "completed"]}}}]
    )
    print(f"Fixed {result1.modified_count} records missing 'success' field")
    
    # 2. Fix records missing 'agent_type' — copy from 'agent' field
    result2 = await col("agent_actions").update_many(
        {"agent_type": {"$exists": False}, "agent": {"$exists": True}},
        [{"$set": {"agent_type": "$agent"}}]
    )
    print(f"Fixed {result2.modified_count} records missing 'agent_type' field")
    
    # 3. Fix records where success is None
    result3 = await col("agent_actions").update_many(
        {"success": None},
        {"$set": {"success": True}}
    )
    print(f"Fixed {result3.modified_count} records with success=None")
    
    # Verify
    total = await col("agent_actions").count_documents({})
    no_success = await col("agent_actions").count_documents({"success": {"$exists": False}})
    false_count = await col("agent_actions").count_documents({"success": False})
    true_count = await col("agent_actions").count_documents({"success": True})
    print(f"\nVerification: total={total}, success=True: {true_count}, success=False: {false_count}, no field: {no_success}")

asyncio.run(main())
