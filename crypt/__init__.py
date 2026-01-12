__version__ = "2.0a2"

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
existing_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler) and h.baseFilename.endswith("crypt.log")]
if not existing_handlers:
    logger.addHandler(handler)


if logger.isEnabledFor(logging.DEBUG):
    logger.debug("Initializing Crypt")
