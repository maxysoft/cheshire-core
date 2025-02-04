# Helper classes for connection handling
# Credential extraction from ws / http connections is not delegated to the custom auth handlers,
#  to have a standard auth interface.

from abc import ABC, abstractmethod
from typing import Tuple
import asyncio
from urllib.parse import urlencode

from fastapi import (
    Request,
    WebSocket,
    HTTPException,
    WebSocketException,
)
from fastapi.requests import HTTPConnection

from cat.auth.permissions import (
    AuthPermission,
    AuthResource,
    AuthUserInfo,
)
from cat.looking_glass.stray_cat import StrayCat
from cat.log import log

class ConnectionAuth(ABC):

    def __init__(self, resource: AuthResource, permission: AuthPermission):
        self.resource = resource
        self.permission = permission

    async def __call__(self, connection: HTTPConnection) -> StrayCat:
        protocol = connection.scope.get('type')
        credential = self.extract_credentials(connection)
        
        if not credential:
            self.not_allowed(connection)

        auth_handlers = [
            connection.app.state.ccat.core_auth_handler,
            connection.app.state.ccat.custom_auth_handler,
        ]
        for ah in auth_handlers:
            user: AuthUserInfo = ah.authorize_user_from_credential(
                protocol, credential, self.resource, self.permission
            )
            if user:
                return await self.get_user_stray(user, connection)

        self.not_allowed(connection)

    @abstractmethod
    def extract_credentials(self, connection: Request | WebSocket) -> str | None:
        pass

    @abstractmethod
    async def get_user_stray(self, user: AuthUserInfo, connection: Request | WebSocket) -> StrayCat:
        pass

    @abstractmethod
    def not_allowed(self, connection: Request | WebSocket):
        pass

class HTTPAuth(ConnectionAuth):

    def extract_credentials(self, connection: Request) -> str | None:
        token = connection.headers.get("Authorization", None)
        if token and ("Bearer " in token):
            token = token.replace("Bearer ", "")

        if not token:
            token = connection.headers.get("access_token", None)
            if token:
                log.warning(
                    "Deprecation Warning: `access_token` header will not be supported in v2."
                    "Pass your token/key using the `Authorization: Bearer <token>` format."
                )

        if token == "":
            token = None

        return token

    async def get_user_stray(self, user: AuthUserInfo, connection: Request) -> StrayCat:
        strays = connection.app.state.strays
        event_loop = connection.app.state.event_loop

        if user.id not in strays.keys():
            strays[user.id] = StrayCat(
                user_id=user.id, user_data=user, main_loop=event_loop
            )
        return strays[user.id]

    def not_allowed(self, connection: Request):
        raise HTTPException(status_code=403, detail={"error": "Invalid Credentials"})
    

class WebSocketAuth(ConnectionAuth):

    def extract_credentials(self, connection: WebSocket) -> Tuple[None, str] | None:
        """
        Extract session token from WebSocket query string
        """
        # TODOAUTH: is there a more secure way to pass the token over websocket?
        # Headers do not work from the browser
        token = connection.query_params.get("token", None)
        
        return None, token
    

    async def get_user_stray(self, user: AuthUserInfo, connection: WebSocket) -> StrayCat:
        strays = connection.app.state.strays

        if user.id in strays.keys():
            stray = strays[user.id]
            await stray.close_connection()

            # Set new ws connection
            stray.reset_connection(connection)
            log.info(
                f"New websocket connection for user '{user.id}', the old one has been closed."
            )
            return stray

        else:
            stray = StrayCat(
                ws=connection,
                user_id=user.name, # TODOV2: user_id should be the user.id
                user_data=user,
                main_loop=asyncio.get_running_loop(),
            )
            strays[user.id] = stray
            return stray
        
    def not_allowed(self, connection: WebSocket):
        raise WebSocketException(code=1004, reason="Invalid Credentials")



class CoreFrontendAuth(HTTPAuth):

    def extract_credentials(self, connection: Request) -> str | None:
        token = connection.cookies.get("ccat_user_token", None)

        if token is None or token == "":
            self.not_allowed(connection)

        return token

    def not_allowed(self, connection: Request):
        referer_query = urlencode({"referer": connection.url.path})
        raise HTTPException(
            status_code=307,
            headers={
                "Location": f"/auth/login?{referer_query}"
            }
        )
