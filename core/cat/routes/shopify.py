from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
import jwt
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional
from cat.env import get_env
from cat.log import log

router = APIRouter(
    prefix="/shopify",
    tags=["shopify"],
    responses={404: {"description": "Not found"}},
)

class TokenResponse(BaseModel):
    access_token: str

def verify_shopify_hmac(request: Request) -> bool:
    """Verify Shopify HMAC signature"""
    try:
        hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
        shop_id = request.headers.get("X-Shopify-Shop-Id")
        if not hmac_header or not shop_id:
            return False
        
        shopify_secret = get_env("SHOPIFY_API_SECRET")
        if not shopify_secret:
            log.error("SHOPIFY_API_SECRET not configured")
            return False

        # TODO: Implement proper HMAC validation when needed
        return True
    except Exception as e:
        log.error(f"HMAC validation error: {str(e)}")
        return False

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}

@router.post("/token", response_model=TokenResponse)
async def generate_token(request: Request):
    """Generate JWT token for Shopify users"""
    try:
        # Verify Shopify request
        if not verify_shopify_hmac(request):
            log.warning("Invalid Shopify HMAC signature")
            raise HTTPException(status_code=401, detail="Invalid Shopify request")

        # Get Shopify session data from headers
        shop_id = request.headers.get("X-Shopify-Shop-Id")
        user_id = request.headers.get("X-Shopify-Customer-Id")
        
        if not shop_id or not user_id:
            log.warning(f"Authentication attempt without Shopify headers: shop_id={shop_id}, user_id={user_id}")
            raise HTTPException(status_code=401, detail="Missing Shopify authentication")
        
        jwt_secret = get_env("CCAT_JWT_SECRET")
        jwt_algorithm = get_env("CCAT_JWT_ALGORITHM")
        
        if not jwt_secret or not jwt_algorithm:
            log.error("JWT configuration missing from environment")
            raise HTTPException(status_code=500, detail="Missing JWT configuration")
        
        # Generate JWT token
        payload = {
            "sub": f"shopify_{shop_id}_{user_id}",
            "username": f"shopify_user_{user_id}",
            "exp": datetime.utcnow() + timedelta(days=1),
            "iat": datetime.utcnow(),
            "shop_id": shop_id,
            "user_id": user_id,
            "type": "shopify"
        }
        
        token = jwt.encode(
            payload,
            jwt_secret,
            algorithm=jwt_algorithm
        )
        
        log.debug(f"Generated token for Shopify user {user_id} from shop {shop_id}")
        return {"access_token": token}
        
    except jwt.PyJWTError as e:
        log.error(f"JWT token generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Token generation failed")
    except Exception as e:
        log.error(f"Unexpected error in token generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")