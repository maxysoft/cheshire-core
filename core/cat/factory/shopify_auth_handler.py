from typing import Literal
from cat.factory.custom_auth_handler import BaseAuthHandler
from cat.auth.permissions import AuthUserInfo, AuthResource, AuthPermission, get_base_permissions
from cat.env import get_env
from cat.log import log
import jwt
from datetime import datetime, timedelta

class ShopifyAuthHandler(BaseAuthHandler):
    def __init__(self):
        self.jwt_secret = get_env("CCAT_JWT_SECRET")
        self.jwt_algorithm = get_env("CCAT_JWT_ALGORITHM")

    def authorize_user_from_jwt(
        self,
        token: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm]
            )

            if payload["sub"].startswith("shopify_"):
                return AuthUserInfo(
                    id=payload["sub"],
                    name=payload["username"],
                    permissions=get_base_permissions(),
                    extra={"shopify_user": True}
                )

        except Exception as e:
            log.error(f"Could not auth Shopify user from JWT: {e}")

        return None

    def authorize_user_from_key(
        self,
        protocol: Literal["http", "websocket"],
        user_id: str,
        api_key: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        return None  # Shopify users don't use API keys
