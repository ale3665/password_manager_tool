import os
import json
import base64
import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

VAULT_FILE = "vault.bin"
SALT_FILE = "salt.bin"
HASH_FILE = "master.hash"

def get_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_vault(data: dict, fernet: Fernet):
    with open(VAULT_FILE, "wb") as f:
        f.write(fernet.encrypt(json.dumps(data).encode()))

def decrypt_vault(fernet: Fernet):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        return json.loads(fernet.decrypt(f.read()).decode())

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.fernet = None
        self.vault = {}
        self.row_ids = {}
        self.last_shown_id = None
        self.build_login()

    def build_login(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Enter Master Password:")
        self.label.pack(pady=10)
        self.entry = tk.Entry(self.root, show="*", width=30)
        self.entry.pack(pady=5)
        self.button = tk.Button(self.root, text="Login", command=self.login)
        self.button.pack()

    def login(self):
        password = self.entry.get()
        if not os.path.exists(HASH_FILE):
            self.create_master(password)
        else:
            with open(SALT_FILE, "rb") as f:
                salt = f.read()
            with open(HASH_FILE, "r") as f:
                stored_hash = f.read().strip()

            if hashlib.sha256(password.encode()).hexdigest() != stored_hash:
                messagebox.showerror("Error", "Incorrect password.")
                return

        self.key = get_key_from_password(password, salt)
        self.fernet = Fernet(self.key)
        self.vault = decrypt_vault(self.fernet)
        self.build_main_ui()

    def create_master(self, password):
        confirm = simpledialog.askstring("Confirm", "Confirm Master Password:", show="*")
        if confirm != password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        with open(HASH_FILE, "w") as f:
            f.write(hashlib.sha256(password.encode()).hexdigest())

        self.key = get_key_from_password(password, salt)
        self.fernet = Fernet(self.key)
        self.vault = {}
        encrypt_vault(self.vault, self.fernet)
        messagebox.showinfo("Success", "Master password set.")
        self.build_main_ui()

    def build_main_ui(self):
        self.clear_frame()

        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=5)
        tk.Label(search_frame, text="🔍 Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind("<KeyRelease>", self.update_search)

        tree_frame = tk.Frame(self.root)
        tree_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(tree_frame, columns=("Account", "Username", "Password"), show="headings", yscrollcommand=scrollbar.set)
        self.tree.heading("Account", text="Account")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        self.tree.bind("<<TreeviewSelect>>", self.clear_password_display)
        self.load_tree()

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="➕ Add", command=self.add_entry).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="🗑️ Delete", command=self.delete_entry).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="👁️ Show Password", command=self.show_selected_password).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Exit", command=self.root.quit).grid(row=0, column=3, padx=5)

    def load_tree(self, search_term=""):
        self.tree.delete(*self.tree.get_children())
        self.row_ids.clear()
        for idx, (account, creds) in enumerate(self.vault.items()):
            if search_term.lower() in account.lower() or \
               search_term.lower() in creds["username"].lower() or \
               search_term.lower() in creds["password"].lower():
                iid = f"row{idx}"
                self.tree.insert("", "end", iid=iid, values=(account, creds["username"], "********"))
                self.row_ids[iid] = account
        self.auto_resize_columns()

    def update_search(self, event=None):
        self.load_tree(self.search_var.get())

    def add_entry(self):
        name = simpledialog.askstring("Account Name", "Enter account/service name:")
        if not name: return
        user = simpledialog.askstring("Username", f"Enter username for {name}:")
        pw = simpledialog.askstring("Password", f"Enter password for {name}:", show="*")
        if user and pw:
            self.vault[name] = {"username": user, "password": pw}
            encrypt_vault(self.vault, self.fernet)
            self.load_tree(self.search_var.get())

    def delete_entry(self):
        selected = self.tree.selection()
        for item in selected:
            account = self.row_ids.get(item)
            if account in self.vault:
                del self.vault[account]
        encrypt_vault(self.vault, self.fernet)
        self.load_tree(self.search_var.get())

    def show_selected_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an account first.")
            return
        if self.last_shown_id and self.last_shown_id != selected[0]:
            self.clear_password_display()
        row_id = selected[0]
        account = self.row_ids.get(row_id)
        creds = self.vault.get(account)
        if creds:
            self.tree.item(row_id, values=(account, creds["username"], creds["password"]))
            self.last_shown_id = row_id

    def clear_password_display(self, event=None):
        for row_id, account in self.row_ids.items():
            creds = self.vault.get(account)
            if creds:
                self.tree.item(row_id, values=(account, creds["username"], "********"))
        self.last_shown_id = None

    def auto_resize_columns(self):
        for col in ("Account", "Username", "Password"):
            max_len = max(
                [len(str(self.tree.set(item, col))) for item in self.tree.get_children()] + [len(col)]
            )
            self.tree.column(col, width=(max_len * 8))

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("650x500")
    app = PasswordManagerGUI(root)
    root.mainloop()
