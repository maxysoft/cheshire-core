from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Literal
from pytz import utc
import jwt

from cat.db.crud import get_users
from cat.auth.permissions import (
    AuthPermission, AuthResource, AuthUserInfo, get_base_permissions, get_full_permissions
)
from cat.auth.auth_utils import is_jwt, check_password
from cat.env import get_env
from cat.log import log


class BaseAuthHandler(ABC):  # TODOAUTH: pydantic model?
    """
    Base class to build custom Auth systems that will live alongside core auth.
    Methods `authorize_user_from_credential`
    MUST be implemented by subclasses.
    """

    def authorize_user_from_credential(
        self,
        protocol: Literal["http", "websocket"],
        credential: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission,
        # when there is no JWT, user id is passed via `user_id: xxx` header or via websocket path
        # with JWT, the user id is in the token ad has priority
        user_id: str = "user",
    ) -> AuthUserInfo | None:
        if is_jwt(credential):
            # JSON Web Token auth
            return self.authorize_user_from_jwt(
                credential, auth_resource, auth_permission
            )
        else:
            # API_KEY auth
            return self.authorize_user_from_key(
                protocol, user_id, credential, auth_resource, auth_permission
            )

    @abstractmethod
    def authorize_user_from_jwt(
        self,
        token: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        # will raise: NotImplementedError
        pass

    @abstractmethod
    def authorize_user_from_key(
        self,
        protocol: Literal["http", "websocket"],
        user_id: str,
        api_key: str,
        auth_resource: AuthResource,
        auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        # will raise: NotImplementedError
        pass


# Core auth handler, verify token on local idp
class CoreAuthHandler(BaseAuthHandler):

    def authorize_user_from_jwt(self, token: str, auth_resource: AuthResource, auth_permission: AuthPermission) -> AuthUserInfo | None:
        try:
            payload = jwt.decode(
                token,
                get_env("CCAT_JWT_SECRET"),
                algorithms=[get_env("CCAT_JWT_ALGORITHM")],
            )

            users = get_users()
            if payload["sub"] in users:
                user = users[payload["sub"]]
                if auth_resource in user["permissions"].keys() and \
                        auth_permission in user["permissions"][auth_resource]:
                    return AuthUserInfo(
                        id=payload["sub"],
                        name=payload["username"],
                        permissions=user["permissions"],
                        extra=user,
                    )

        except Exception as e:
            log.error(f"Could not auth user from JWT: {e}")

        return None

    def authorize_user_from_key(self, protocol: Literal["http", "websocket"], api_key: str, auth_resource: AuthResource, auth_permission: AuthPermission) -> AuthUserInfo | None:
        http_key = get_env("CCAT_API_KEY")
        ws_key = get_env("CCAT_API_KEY_WS")

        if not http_key and not ws_key:
            return AuthUserInfo(
                id="unknown",
                name="unknown",
                permissions=get_full_permissions()
            )

        if protocol == "websocket":
            return self._authorize_websocket_key(api_key, ws_key)
        else:
            return self._authorize_http_key(api_key, http_key)

    def _authorize_http_key(self, api_key: str, http_key: str) -> AuthUserInfo | None:
        if api_key == http_key:
            return AuthUserInfo(
                id="unknown",
                name="unknown",
                permissions=get_full_permissions()
            )
        return None

    def _authorize_websocket_key(self, api_key: str, ws_key: str) -> AuthUserInfo | None:
        if api_key == ws_key:
            return AuthUserInfo(
                id="unknown",
                name="unknown",
                permissions=get_base_permissions()
            )
        return None

    def issue_jwt(self, username: str, password: str) -> str | None:
        users = get_users()
        for user_id, user in users.items():
            if user["username"] == username and check_password(password, user["password"]):
                expire_delta_in_seconds = float(get_env("CCAT_JWT_EXPIRE_MINUTES")) * 60
                expires = datetime.now(utc) + timedelta(seconds=expire_delta_in_seconds)

                jwt_content = {
                    "sub": user_id,
                    "username": username,
                    "permissions": user["permissions"],
                    "exp": expires
                }
                return jwt.encode(
                    jwt_content,
                    get_env("CCAT_JWT_SECRET"),
                    algorithm=get_env("CCAT_JWT_ALGORITHM"),
                )
        return None


# Default Auth, always deny auth by default (only core auth decides).
class CoreOnlyAuthHandler(BaseAuthHandler):
    def authorize_user_from_jwt(*args, **kwargs) -> AuthUserInfo | None:
        return None

    def authorize_user_from_key(*args, **kwargs) -> AuthUserInfo | None:
        return None


