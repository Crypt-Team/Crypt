import logging
import customtkinter as ctk
from ...crypto import decrypt_message

logger = logging.getLogger("crypt.ui.screens.decrypt")


class DecryptScreen(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        ctk.CTkLabel(self, text="Paste Encrypted Message").pack(pady=10)

        self.input_box = ctk.CTkTextbox(self)
        self.input_box.pack(fill="both", expand=True, padx=20, pady=10)

        ctk.CTkButton(
            self, text="Decrypt", command=self.decrypt
        ).pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.pack(pady=5)

    def decrypt(self):
        content = self.input_box.get("1.0", "end-1c")
        if not content.strip():
            self.status_label.configure(text="Input is empty")
            return
        logger.info("Attempting to decrypt message")
        try:
            decrypted_message = decrypt_message(self.app.user_keys, content)
        except Exception:
            self.status_label.configure(text="Decryption failed")
            logger.exception("Decryption failed", exc_info=True)
            return
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", decrypted_message["message"])
        self.status_label.configure(text="Message decrypted!")