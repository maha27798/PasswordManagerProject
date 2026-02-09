import json
import os
import string
import secrets
import base64
import pyperclip
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ----- Encryption Helpers -----
def derive_key(master_password, salt):
    return PBKDF2(master_password, salt, dkLen=32, count=100000)

def encrypt(text, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(enc_text, key):
    try:
        raw = base64.b64decode(enc_text.encode())
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(AES.MODE_GCM, key=key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except:
        return None

def load_data(filename, key):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            encrypted_json = f.read()
            if encrypted_json:
                decrypted = decrypt(encrypted_json, key)
                if decrypted:
                    return json.loads(decrypted)
    return {"entries": []}

def save_data(filename, data, key):
    json_str = json.dumps(data)
    encrypted_json = encrypt(json_str, key)
    with open(filename, 'w') as f:
        f.write(encrypted_json)

# ----- Password Generation & Strength -----
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    score = sum([has_upper, has_lower, has_digit, has_symbol])
    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Medium"
    else:
        return "Weak"

# ----- GUI App -----
class UltimatePasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Ultimate Dark Password Manager")
        self.master.configure(bg="#2E2E2E")
        self.filename = "passwords.dat"
        self.salt_file = "salt.dat"
        self.setup_key()
        self.data = load_data(self.filename, self.key)
        self.create_widgets()
        self.refresh_table()

    def setup_key(self):
        master_password = tk.simpledialog.askstring("Master Password", "Enter master password:", show='*')
        if os.path.exists(self.salt_file):
            with open(self.salt_file, "rb") as f:
                salt = f.read()
        else:
            salt = get_random_bytes(16)
            with open(self.salt_file, "wb") as f:
                f.write(salt)
        self.key = derive_key(master_password, salt)

    def create_widgets(self):
        # Buttons
        frame = tk.Frame(self.master, bg="#2E2E2E")
        frame.pack(pady=5, fill='x')
        btn_config = {"bg":"#444","fg":"white","activebackground":"#666","activeforeground":"white"}
        tk.Button(frame,text="Add Entry",command=self.add_entry,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Update Entry",command=self.update_entry,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Delete Entry",command=self.delete_entry,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Generate Password",command=self.auto_generate,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Export Backup",command=self.export_backup,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Import Backup",command=self.import_backup,**btn_config).pack(side='left', padx=3)
        tk.Button(frame,text="Exit",command=self.exit_app,**btn_config).pack(side='right', padx=3)

        # Search bar
        search_frame = tk.Frame(self.master, bg="#2E2E2E")
        search_frame.pack(pady=5, fill='x')
        tk.Label(search_frame,text="Search:",bg="#2E2E2E",fg="white").pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.search_table())
        tk.Entry(search_frame,textvariable=self.search_var,bg="#444",fg="white",insertbackground='white').pack(side='left',fill='x',expand=True,padx=5)

        # Table
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#3C3C3C", foreground="white", fieldbackground="#3C3C3C", rowheight=25)
        style.configure("Treeview.Heading", background="#555", foreground="white")
        style.map("Treeview", background=[('selected','#666')], foreground=[('selected','white')])
        self.tree = ttk.Treeview(self.master, columns=("Website","Username","Strength"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Strength", text="Password Strength")
        self.tree.pack(pady=10, fill='both', expand=True)
        self.tree.bind("<Double-1>", self.copy_password)

    # ----- Table Methods -----
    def refresh_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for entry in self.data["entries"]:
            password = decrypt(entry["password"], self.key)
            strength = password_strength(password)
            self.tree.insert("", "end", values=(entry["website"], entry["username"], strength))

    def search_table(self):
        keyword = self.search_var.get().lower()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for entry in self.data["entries"]:
            if keyword in entry["website"].lower() or keyword in entry["username"].lower():
                password = decrypt(entry["password"], self.key)
                strength = password_strength(password)
                self.tree.insert("", "end", values=(entry["website"], entry["username"], strength))

    # ----- Entry Methods -----
    def add_entry(self):
        website = tk.simpledialog.askstring("Website","Enter website:")
        username = tk.simpledialog.askstring("Username","Enter username:")
        choice = messagebox.askyesno("Password","Auto-generate password?")
        if choice:
            password = generate_password()
            pyperclip.copy(password)
            messagebox.showinfo("Generated Password",f"Password: {password}\nCopied to clipboard!")
        else:
            password = tk.simpledialog.askstring("Password","Enter password:",show='*')
        self.data["entries"].append({"website":website,"username":username,"password":encrypt(password,self.key)})
        save_data(self.filename,self.data,self.key)
        self.refresh_table()

    def update_entry(self):
        selected = self.tree.selection()
        if not selected: messagebox.showwarning("Select","Select entry to update."); return
        item = self.tree.item(selected[0])
        website = item['values'][0]
        for entry in self.data["entries"]:
            if entry["website"]==website:
                new_user = tk.simpledialog.askstring("Update","New username (leave blank to keep):")
                if new_user: entry["username"]=new_user
                choice = messagebox.askyesno("Password","Auto-generate new password?")
                if choice:
                    password = generate_password()
                    pyperclip.copy(password)
                    messagebox.showinfo("Generated Password",f"Password: {password}\nCopied to clipboard!")
                else:
                    password = tk.simpledialog.askstring("Password","New password (leave blank to keep):",show='*')
                if password: entry["password"]=encrypt(password,self.key)
                save_data(self.filename,self.data,self.key)
                self.refresh_table()
                return

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected: messagebox.showwarning("Select","Select entry to delete."); return
        item = self.tree.item(selected[0])
        website = item['values'][0]
        self.data["entries"]=[e for e in self.data["entries"] if e["website"]!=website]
        save_data(self.filename,self.data,self.key)
        self.refresh_table()

    def auto_generate(self):
        password = generate_password()
        pyperclip.copy(password)
        messagebox.showinfo("Generated Password",f"Password: {password}\nCopied to clipboard!")

    def copy_password(self,event):
        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            website = item['values'][0]
            for entry in self.data["entries"]:
                if entry["website"]==website:
                    password = decrypt(entry["password"],self.key)
                    pyperclip.copy(password)
                    messagebox.showinfo("Copied",f"Password for {website} copied to clipboard!")

    # ----- Backup Methods -----
    def export_backup(self):
        path = filedialog.asksaveasfilename(defaultextension=".bak",filetypes=[("Backup Files","*.bak")])
        if path:
            save_data(path,self.data,self.key)
            messagebox.showinfo("Backup","Backup exported successfully!")

    def import_backup(self):
        path = filedialog.askopenfilename(filetypes=[("Backup Files","*.bak")])
        if path:
            backup_data = load_data(path,self.key)
            if backup_data and "entries" in backup_data:
                self.data = backup_data
                save_data(self.filename,self.data,self.key)
                self.refresh_table()
                messagebox.showinfo("Import","Backup imported successfully!")

    def exit_app(self):
        save_data(self.filename,self.data,self.key)
        self.master.destroy()

# ----- Run App -----
if __name__=="__main__":
    root=tk.Tk()
    app=UltimatePasswordManager(root)
    root.mainloop()
