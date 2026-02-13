import uvicorn
from config import Config

if __name__ == "__main__":
    uvicorn.run(
        "app:asgi_app",
        host=Config.HOST,
        port=Config.PORT,
        reload=True,
        log_level="info",
    )
