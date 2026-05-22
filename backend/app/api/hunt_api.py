"""
Threat Hunt API — Templates, queries, saved hunts
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from app.services.threat_hunt_service import threat_hunt_service
from app.core.auth_middleware import get_current_user

router = APIRouter(prefix="/api/hunt", tags=["Threat Hunt"])


@router.get("/templates")
async def get_templates(user: dict = Depends(get_current_user)):
    return {"templates": threat_hunt_service.get_templates()}


@router.post("/execute")
async def execute_hunt(data: dict, user: dict = Depends(get_current_user)):
    """Execute a threat hunt"""
    template_id = data.get("template_id")
    custom_query = data.get("custom_query")
    hours = data.get("hours", 24)

    result = await threat_hunt_service.execute_hunt(
        template_id=template_id,
        custom_query=custom_query,
        hours=hours
    )
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result


@router.post("/nl-query")
async def natural_language_query(data: dict, user: dict = Depends(get_current_user)):
    """Convert natural language to query and execute"""
    nl = data.get("query", "")
    if not nl:
        raise HTTPException(400, "Query text required")

    # Translate to MongoDB query
    translated = await threat_hunt_service.nl_to_query(nl)

    # Execute the translated query
    result = await threat_hunt_service.execute_hunt(
        custom_query=translated,
        hours=data.get("hours", 24)
    )

    return {
        "natural_language": nl,
        "translated_query": translated,
        "results": result,
    }


@router.get("/saved")
async def list_saved(user: dict = Depends(get_current_user)):
    queries = await threat_hunt_service.list_saved_queries()
    return {"queries": queries}


@router.post("/saved")
async def save_query(data: dict, user: dict = Depends(get_current_user)):
    name = data.get("name", "Untitled Query")
    query = data.get("query", {})
    query_id = await threat_hunt_service.save_query(name, query, user.get("username", "unknown"))
    return {"success": True, "id": query_id}


@router.delete("/saved/{query_id}")
async def delete_saved(query_id: str, user: dict = Depends(get_current_user)):
    await threat_hunt_service.delete_saved_query(query_id)
    return {"success": True}
