__version__ = "2.0a1"

import logging

logger = logging.getLogger("crypt")
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    '[%(asctime)s] %(name)s | %(levelname)s - %(message)s'
)

# File Handler
handler = logging.FileHandler("crypt.log", encoding="utf-8")
handler.setFormatter(formatter)

# Only add if not already added
if not logger.hasHandlers():
    logger.addHandler(handler)


logger.info("Initializing Crypt")

if __name__ == "__main__":
    from .main import main
    main()
