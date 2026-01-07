import logging
import customtkinter as ctk

logger = logging.getLogger("crypt.ui.screens.decrypt")


class DecryptScreen(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        ctk.CTkLabel(self, text="Paste Encrypted Message").pack(pady=10)

        self.input_box = ctk.CTkTextbox(self)
        self.input_box.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkButton(
            self, text="Decrypt"
        ).pack(pady=10)
