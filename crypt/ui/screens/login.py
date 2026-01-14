import logging
import customtkinter as ctk
from ...crypto import api
from tkinter import messagebox as msgbox

logger = logging.getLogger("crypt.ui.screens.login")


class LoginScreen(ctk.CTkToplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.protocol("WM_DELETE_WINDOW", self.iconify)

        self.title("Login to Crypt")
        self.geometry("400x400")

        from .. import Topbar
        Topbar(self)

        self.usernameentry = ctk.CTkEntry(self, placeholder_text="Username")
        self.usernameentry.pack(pady=10)

        self.passwordentry = ctk.CTkEntry(self, placeholder_text="Password",
                                          show="*")
        self.passwordentry.pack(pady=20)

        ctk.CTkButton(
            self,
            text="Login",
            command=self.login
        ).pack(pady=10)

        ctk.CTkButton(
            self,
            text="Signup",
            command=self.signup
        ).pack(pady=10)

        ctk.CTkButton(
            self,
            fg_color="darkred",
            text="Quit",
            command=self.app.destroy
        ).pack(pady=10)

    def login(self):
        self.app.username = self.usernameentry.get()
        self.password = self.passwordentry.get()
        try:
            self.app.user_keys = api.login(self.app.username, self.password)
        except Exception as e:
            logger.exception("Login failed", exc_info=True)
            msgbox.showerror("Login Failed", str(e))
            return
        self.destroy()
        self.app.deiconify()

    def signup(self):
        msgbox.showinfo("Signup", api.signup(self.usernameentry.get(),
                                             ctk.CTkInputDialog(
                                                 text="Enter your email:",
                                                 title="Signup").get_input(),
                                             self.passwordentry.get()))
