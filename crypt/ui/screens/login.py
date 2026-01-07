import time
import logging
import customtkinter as ctk
from tkinter import messagebox as msgbox

logger = logging.getLogger("crypt.ui.screens.login")


class LoginScreen(ctk.CTkToplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.title("Login to Crypt")
        self.geometry("400x400")

        ctk.CTkLabel(
            self,
            text="Crypt",
            font=("Segoe UI", 32, "bold")
        ).pack(pady=40)

        self.usernameentry = ctk.CTkEntry(self, placeholder_text="Username")
        self.usernameentry.pack(pady=10)

        self.passwordentry = ctk.CTkEntry(self, placeholder_text="Password",
                                          show="*")
        self.passwordentry.pack(pady=10)

        ctk.CTkButton(
            self,
            text="Login",
            command=self.login
        ).pack(pady=20)

        ctk.CTkButton(
            self,
            text="Signup",
            command=self.signup
        ).pack(pady=10)

    def login(self):
        self.username = self.usernameentry.get()
        self.password = self.passwordentry.get()
        # TODO: login placeholder — crypto + API later
        time.sleep(1)
        self.destroy()
        self.app.deiconify()

    def signup(self):
        self.username = self.usernameentry.get()
        self.password = self.passwordentry.get()
        # TODO: signup placeholder — crypto + API later
        time.sleep(1)
        msgbox.showinfo("Signup", "Signup successful! You can now log in.")
