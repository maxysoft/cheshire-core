from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import jwt
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

class TokenResponse(BaseModel):
    access_token: str

async def verify_shopify_hmac(request: Request) -> bool:
    """Verify Shopify HMAC signature"""
    try:
        hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
        shop_id = request.headers.get("X-Shopify-Shop-Id")
        if not hmac_header or not shop_id:
            return False
        
        shopify_secret = os.getenv("SHOPIFY_API_SECRET")
        if not shopify_secret:
            return False

        body = await request.body()
        
        digest = hmac.new(
            shopify_secret.encode('utf-8'), 
            body, 
            hashlib.sha256
        ).digest()
        
        calculated_hmac = base64.b64encode(digest).decode('utf-8')
        return hmac.compare_digest(calculated_hmac, hmac_header)
        
    except Exception as e:
        return False

@app.post("/shopify/token", response_model=TokenResponse)
async def generate_token(request: Request):
    """Generate JWT token for Shopify users"""
    try:
        if not await verify_shopify_hmac(request):
            raise HTTPException(status_code=401, detail="Invalid Shopify request")

        shop_id = request.headers.get("X-Shopify-Shop-Id")
        user_id = request.headers.get("X-Shopify-Customer-Id")
        
        if not shop_id or not user_id:
            raise HTTPException(status_code=401, detail="Missing Shopify authentication")
        
        jwt_secret = os.getenv("CCAT_JWT_SECRET")
        jwt_algorithm = os.getenv("CCAT_JWT_ALGORITHM")
        
        if not jwt_secret or not jwt_algorithm:
            raise HTTPException(status_code=500, detail="Missing JWT configuration")
        
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
        
        return {"access_token": token}
        
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=500, detail="Token generation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")