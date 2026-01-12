import logging
import customtkinter as ctk

logger = logging.getLogger("crypt.ui.screens.inbox")


class InboxScreen(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        header = ctk.CTkFrame(self)
        header.pack(fill="x")

        ctk.CTkLabel(
            self, text="Inbox (placeholder)"
        ).pack(pady=50)
