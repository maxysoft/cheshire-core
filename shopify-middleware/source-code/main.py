import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
import hmac
import hashlib
import base64
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import requests

load_dotenv()

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

class TokenResponse(BaseModel):
    access_token: str

async def verify_shopify_hmac(request: Request) -> bool:
    """Verify Shopify HMAC signature"""
    try:
        hmac_header = request.headers.get("X-Shopify-Hmac-Sha256")
        shop_id = request.headers.get("X-Shopify-Shop-Id")
        logger.debug(f"Received HMAC header: {hmac_header}")
        logger.debug(f"Received Shop ID: {shop_id}")
        
        if not hmac_header or not shop_id:
            logger.warning("Missing HMAC header or Shop ID")
            return False
        
        shopify_secret = os.getenv("SHOPIFY_API_SECRET")
        if not shopify_secret:
            logger.error("SHOPIFY_API_SECRET not configured")
            return False

        body = await request.body()
        logger.debug(f"Request body: {body}")
        
        digest = hmac.new(
            shopify_secret.encode('utf-8'), 
            body, 
            hashlib.sha256
        ).digest()
        
        calculated_hmac = base64.b64encode(digest).decode('utf-8')
        logger.debug(f"Calculated HMAC: {calculated_hmac}")
        
        return hmac.compare_digest(calculated_hmac, hmac_header)
        
    except Exception as e:
        logger.error(f"HMAC validation error: {str(e)}")
        return False

@app.post("/shopify/token", response_model=TokenResponse)
async def generate_token(request: Request):
    """Generate JWT token for Shopify users"""
    try:
        if not await verify_shopify_hmac(request):
            logger.warning("Invalid Shopify HMAC signature")
            raise HTTPException(status_code=401, detail="Invalid Shopify request")

        shop_id = request.headers.get("X-Shopify-Shop-Id")
        user_id = request.headers.get("X-Shopify-Customer-Id")
        logger.debug(f"Shop ID: {shop_id}, User ID: {user_id}")
        
        if not shop_id or not user_id:
            logger.warning("Missing Shopify authentication headers")
            raise HTTPException(status_code=401, detail="Missing Shopify authentication")
        
        jwt_secret = os.getenv("CCAT_JWT_SECRET")
        jwt_algorithm = os.getenv("CCAT_JWT_ALGORITHM")
        logger.debug(f"JWT Secret: {jwt_secret}")
        logger.debug(f"JWT Algorithm: {jwt_algorithm}")

        if not jwt_secret or not jwt_algorithm:
            logger.error("JWT configuration missing from environment")
            raise HTTPException(status_code=500, detail="Missing JWT configuration")
        
        # Authenticate with Cheshire Cat to get a token
        cheshire_cat_token = authenticate_with_cheshire_cat()
        if not cheshire_cat_token:
            logger.error("Failed to authenticate with Cheshire Cat")
            raise HTTPException(status_code=500, detail="Failed to authenticate with Cheshire Cat")

        # Add temporary user to the database via Cheshire Cat API
        temp_user_id = f"shopify_{shop_id}_{user_id}"
        user_data = {
            "username": f"shopify_user_{user_id}",
            "password": "temporary_password",  # Use a temporary password
            "permissions": {
                "STATUS": ["READ"],
                "MEMORY": ["READ", "LIST"],
                "CONVERSATION": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
                "STATIC": ["READ"],
            }
        }
        add_user_response = add_user_to_cheshire_cat(user_data, cheshire_cat_token)
        if not add_user_response:
            logger.error("Failed to add temporary user to Cheshire Cat")
            raise HTTPException(status_code=500, detail="Failed to add temporary user")

        payload = {
            "sub": temp_user_id,
            "username": f"shopify_user_{user_id}",
            "exp": datetime.utcnow() + timedelta(days=1),
            "iat": datetime.utcnow(),
            "shop_id": shop_id,
            "user_id": user_id,
            "type": "shopify",
            "permissions": {
                "STATUS": ["READ"],
                "MEMORY": ["READ", "LIST"],
                "CONVERSATION": ["WRITE", "EDIT", "LIST", "READ", "DELETE"],
                "STATIC": ["READ"],
            }
        }
        
        token = jwt.encode(
            payload,
            jwt_secret,
            algorithm=jwt_algorithm
        )
        
        logger.debug(f"Generated token for Shopify user {user_id} from shop {shop_id}")
        return {"access_token": token}
        
    except jwt.PyJWTError as e:
        logger.error(f"JWT token generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Token generation failed")
    except Exception as e:
        logger.error(f"Unexpected error in token generation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

def authenticate_with_cheshire_cat():
    """Authenticate with Cheshire Cat to get a token"""
    try:
        cheshire_cat_api_url = os.getenv("CHESHIRE_CAT_API_URL")
        cheshire_cat_username = os.getenv("CHESHIRE_CAT_USERNAME")
        cheshire_cat_password = os.getenv("CHESHIRE_CAT_PASSWORD")
        response = requests.post(
            f"{cheshire_cat_api_url}/auth/token",
            json={"username": cheshire_cat_username, "password": cheshire_cat_password}
        )
        if response.status_code == 200:
            token = response.json().get("access_token")
            logger.debug(f"Authenticated with Cheshire Cat: {token}")
            return token
        else:
            logger.error(f"Failed to authenticate with Cheshire Cat: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error authenticating with Cheshire Cat: {str(e)}")
        return None

def add_user_to_cheshire_cat(user_data, token):
    """Add a user to Cheshire Cat via API"""
    try:
        cheshire_cat_api_url = os.getenv("CHESHIRE_CAT_API_URL")
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(f"{cheshire_cat_api_url}/users", json=user_data, headers=headers)
        if response.status_code == 201:
            logger.debug(f"User added to Cheshire Cat: {user_data}")
            return True
        else:
            logger.error(f"Failed to add user to Cheshire Cat: {response.status_code}, {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error adding user to Cheshire Cat: {str(e)}")
        return False
