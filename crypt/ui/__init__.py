import logging
import customtkinter as ctk
from .. import __version__
from .screens.login import LoginScreen
from .screens.inbox import InboxScreen
from .screens.compose import ComposeScreen
from .screens.decrypt import DecryptScreen

logger = logging.getLogger("crypt.ui")


class Topbar(ctk.CTkFrame):
    def __init__(self, parent, fg_color="#0f0121"):
        from PIL import Image
        import os
        super().__init__(parent, fg_color=fg_color)

        self.pack(side="top")
        logo_path = os.path.join("assets", "logo.png")
        self.logo = ctk.CTkImage(Image.open(logo_path), size=(101, 34))
        logo_label = ctk.CTkLabel(self, image=self.logo, text="")
        logo_label.pack(pady=5)


class CryptApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        logger.info("Starting Crypt UI")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("Crypt")
        self.geometry("600x600")

        topbar = Topbar(self)
        self.connection_status_label = ctk.CTkLabel(topbar, text="Idle")
        self.connection_status_label.pack(padx=10)
        self.connection_status = ctk.CTkProgressBar(topbar, mode="indeterminate")
        self.connection_status.pack(pady=5)

        tabview = ctk.CTkTabview(self, width=200)
        tabview.pack(fill="both", expand=True)
        InboxTab = tabview.add("Inbox")
        ComposeTab = tabview.add("Compose")
        DecryptTab = tabview.add("Decrypt")

        InboxScreen(InboxTab, self).pack(fill="both", expand=True)
        ComposeScreen(ComposeTab, self).pack(fill="both", expand=True)
        DecryptScreen(DecryptTab, self).pack(fill="both", expand=True)

        ctk.CTkLabel(self, text=f"Version {__version__}").pack(side="bottom",
                                                               pady=5)

        self.withdraw()
        self.loginscreen = LoginScreen(self, self)
