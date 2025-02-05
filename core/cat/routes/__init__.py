# Import all routers
from cat.routes.base import router as base_router
from cat.routes.auth import router as auth_router 
from cat.routes.users import router as users_router
from cat.routes.settings import router as settings_router
from cat.routes.llm import router as llm_router
from cat.routes.embedder import router as embedder_router
from cat.routes.plugins import router as plugins_router
from cat.routes.memory.memory_router import memory_router
from cat.routes.upload import router as upload_router
from cat.routes.auth_handler import router as auth_handler_router
from cat.routes.websocket import router as websocket_router
from cat.routes.shopify import router as shopify_router