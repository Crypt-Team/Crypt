import logging
from ui import CryptApp

logger = logging.getLogger("crypt")

logger.info("Starting Crypt Application")


def main():
    app = CryptApp()
    app.mainloop()


if __name__ == "__main__":
    main()
