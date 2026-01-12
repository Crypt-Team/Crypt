import logging
import customtkinter as ctk
from tkinter import messagebox as msgbox
from ...crypto import encrypt_message

logger = logging.getLogger("crypt.ui.screens.compose")


class ComposeScreen(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.recipients = ctk.CTkEntry(
            self, placeholder_text="Recipients (comma separated)"
        )
        self.recipients.pack(fill="x", padx=20, pady=10)

        self.message = ctk.CTkTextbox(self)
        self.message.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkButton(
            self, text="Encrypt", command=self.encrypt
        ).pack(pady=5)

    def encrypt(self):
        message = self.message.get("1.0", "end-1c")
        recipients = self.recipients.get().split(",")
        logger.info(f"Encrypting message for {recipients}: {message}")
        try:
            encrypted_message = encrypt_message(self.app.user_keys, recipients,
                                                message)
        except Exception as e:
            msgbox.showerror("Encryption Failed", str(e))
            return
        
        self.message.delete("1.0", "end")
        self.message.insert("1.0", encrypted_message)
        logger.info("Message encrypted and displayed in textbox.")
        ctk.CTkLabel(self, text="Message encrypted!").pack(pady=5)
