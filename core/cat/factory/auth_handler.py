from typing import Type
from pydantic import BaseModel, ConfigDict
import jwt
from datetime import datetime, timedelta
from cat.env import get_env
from cat.log import log
from cat.auth.permissions import AuthUserInfo, AuthResource, AuthPermission

from cat.mad_hatter.mad_hatter import MadHatter
from cat.factory.custom_auth_handler import (
    BaseAuthHandler,
    CoreOnlyAuthHandler,
)

class AuthHandlerConfig(BaseModel):
    _pyclass: Type[BaseAuthHandler] = None

    @classmethod
    def get_auth_handler_from_config(cls, config):
        if (
            cls._pyclass is None
            or issubclass(cls._pyclass.default, BaseAuthHandler) is False
        ):
            raise Exception(
                "AuthHandler configuration class has self._pyclass==None. Should be a valid AuthHandler class"
            )
        return cls._pyclass.default(**config)

class CoreOnlyAuthConfig(AuthHandlerConfig):
    _pyclass: Type = CoreOnlyAuthHandler

    model_config = ConfigDict(
        json_schema_extra={
            "humanReadableName": "Standalone Core Auth Handler",
            "description": "Delegate auth to Cat core, without any additional auth systems. "
            "Do not change this if you don't know what you are doing!",
            "link": "",  # TODO link to auth docs
        }
    )

def get_allowed_auth_handler_strategies():
    list_auth_handler_default = [
        CoreOnlyAuthConfig,
    ]

    mad_hatter_instance = MadHatter()
    list_auth_handler = mad_hatter_instance.execute_hook(
        "factory_allowed_auth_handlers", list_auth_handler_default, cat=None
    )

    return list_auth_handler

def get_auth_handlers_schemas():
    AUTH_HANDLER_SCHEMAS = {}
    for config_class in get_allowed_auth_handler_strategies():
        AUTH_HANDLER_SCHEMAS[config_class.__name__] = config_class.schema()

    return AUTH_HANDLER_SCHEMAS

def get_auth_handler_from_name(name):
    list_auth_handler = get_allowed_auth_handler_strategies()
    for auth_handler in list_auth_handler:
        if auth_handler.__name__ == name:
            return auth_handler
    return None

class CoreAuthHandler(BaseAuthHandler):
    def authorize_user_from_jwt(
        self, token: str, auth_resource: AuthResource, auth_permission: AuthPermission
    ) -> AuthUserInfo | None:
        try:
            log.debug(f"Decoding token: {token}")
            # decode token
            payload = jwt.decode(
                token,
                get_env("CCAT_JWT_SECRET"),
                algorithms=[get_env("CCAT_JWT_ALGORITHM")],
            )
            log.debug(f"Decoded payload: {payload}")

            # get user from DB
            users = get_users()
            log.debug(f"Users from DB: {users}")
            if payload["sub"] in users:
                user = users[payload["sub"]]
                log.debug(f"User found: {user}")
                # TODOAUTH: permissions check should be done in a method
                if auth_resource in user["permissions"].keys() and \
                        auth_permission in user["permissions"][auth_resource]:
                    log.debug(f"User has required permissions: {auth_resource}, {auth_permission}")
                    return AuthUserInfo(
                        id=payload["sub"],
                        name=payload["username"],
                        permissions=user["permissions"],
                        extra=user,
                    )
                else:
                    log.warning(f"User does not have required permissions: {auth_resource}, {auth_permission}")
            else:
                log.warning(f"User not found in DB: {payload['sub']}")

        except Exception as e:
            log.error(f"Could not auth user from JWT: {e}")

        # do not pass
        return None