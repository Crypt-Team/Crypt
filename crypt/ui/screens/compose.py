import logging
import customtkinter as ctk

logger = logging.getLogger("crypt.ui.screens.compose")


class ComposeScreen(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        ctk.CTkLabel(self, text="Compose Message").pack(pady=10)

        self.recipients = ctk.CTkEntry(
            self, placeholder_text="Recipients (comma separated)"
        )
        self.recipients.pack(fill="x", padx=20, pady=10)

        self.message = ctk.CTkTextbox(self)
        self.message.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkButton(
            self, text="Encrypt & Copy"
        ).pack(pady=10)

        ctk.CTkButton(
            self, text="Back",
            command=lambda: app.show_screen("inbox")
        ).pack(pady=5)
