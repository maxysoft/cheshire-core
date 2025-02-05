from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from cat.env import get_env

router = APIRouter()

class ShopifyUserRequest(BaseModel):
    shopify_user_id: str
    shopify_store_id: str

@router.post("/token")
async def create_shopify_token(request: Request, user_data: ShopifyUserRequest):
    """Create a temporary token for a Shopify user"""
    payload = {
        "sub": f"shopify_{user_data.shopify_user_id}",
        "username": f"shopify_user_{user_data.shopify_user_id}",
        "exp": datetime.utcnow() + timedelta(hours=24),
        "store_id": user_data.shopify_store_id
    }
    
    token = jwt.encode(
        payload,
        get_env("CCAT_JWT_SECRET"),
        algorithm=get_env("CCAT_JWT_ALGORITHM")
    )
    
    return {
        "access_token": token,
        "token_type": "bearer"
    }
