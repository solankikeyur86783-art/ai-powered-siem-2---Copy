import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.database.db import col, connect_db # type:ignore
from datetime import datetime

async def reset_agents():
    await connect_db()
    
    # 1. Clear existing agents
    r = await col('agents').delete_many({})
    print(f"Deleted {r.deleted_count} agents")
    
    # 2. Add correct defaults
    defaults = [
        {
            "name": "soc_agent", 
            "type": "ai_agent", 
            "status": "operational",
            "description": "Initial triage and severity assessment of security alerts.",
            "icon": "Shield",
            "category": "Core",
            "created_at": datetime.utcnow(),
            "last_active": datetime.utcnow()
        },
        {
            "name": "analyst_agent", 
            "type": "ai_agent", 
            "status": "operational",
            "description": "Deep investigation and correlation of related security events.",
            "icon": "Search",
            "category": "Investigation",
            "created_at": datetime.utcnow(),
            "last_active": datetime.utcnow()
        },
        {
            "name": "responder_agent", 
            "type": "ai_agent", 
            "status": "operational",
            "description": "Automated containment and remediation for confirmed threats.",
            "icon": "Zap",
            "category": "Response",
            "created_at": datetime.utcnow(),
            "last_active": datetime.utcnow()
        },
        {
            "name": "hunter_agent", 
            "type": "hunter_agent", 
            "status": "operational",
            "description": "Proactive searching for indicators of compromise (IoC).",
            "icon": "Crosshair",
            "category": "Proactive",
            "created_at": datetime.utcnow(),
            "last_active": datetime.utcnow()
        },
        {
            "name": "forensics_agent", 
            "type": "forensics_agent", 
            "status": "operational",
            "description": "Deep-dive evidence collection and digital forensic analysis.",
            "icon": "Archive",
            "category": "Investigation",
            "created_at": datetime.utcnow(),
            "last_active": datetime.utcnow()
        }
    ]
    
    for d in defaults:
        await col("agents").insert_one(d)
        print(f"Inserted agent: {d['name']}")

if __name__ == "__main__":
    asyncio.run(reset_agents())
