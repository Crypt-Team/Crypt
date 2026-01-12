import logging
from .ui import CryptApp

logger = logging.getLogger("crypt")


def main():
    logger.info("Starting Crypt Application")
    app = CryptApp()
    app.mainloop()


if __name__ == "__main__":
    main()
