import logging
import sys
from app.config.settings import settings


def setup_logging() -> None:
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Prevent logs duplication
    logger = logging.getLogger("trustinel")
    logger.setLevel(log_level)
    logger.info(f"Logging initialized with level: {settings.LOG_LEVEL}")
