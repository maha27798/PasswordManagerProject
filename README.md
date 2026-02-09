<img width="1920" height="1200" alt="Screenshot 2026-02-09 193004" src="https://github.com/user-attachments/assets/f8d2b3cc-53b6-4a70-9c4a-6ae71bb8e534" />
# **Ultimate Dark Mode Password Manager**

## **Project Description**

The **Ultimate Dark Mode Password Manager** is a secure, local desktop application built with Python. It allows users to **store, manage, and protect passwords** with AES encryption and a master password. The application supports **add, update, delete, search, auto-generate passwords, clipboard copy, password strength, and backup/import functionality**, all with a **modern dark-themed GUI**.

This project is designed for **personal/local use**, providing the convenience and security of professional password managers.

---

## **Features**

* **AES-256 Encryption**: All passwords are encrypted locally using AES with a master password.
* **Master Password**: Required to access and decrypt all stored credentials.
* **Add / Update / Delete Entries**: Easily manage login credentials for websites or apps.
* **Password Auto-Generation**: Generate strong, random passwords with a single click.
* **Clipboard Copy**: Double-click an entry to copy the password securely to clipboard.
* **Password Strength Indicator**: Displays Weak, Medium, or Strong for each password.
* **Search / Filter**: Live search bar filters entries by website or username.
* **Backup / Import**: Securely export and import encrypted backups (`.bak`).
* **Dark Mode GUI**: Modern, professional interface with styled table and buttons.



## **Setup Instructions**


1. **Install Dependencies:**

```bash
pip install -r requirements.txt
```

2. **Run the Application:**

```bash
python src/ultimate_password_manager.py
```

---

## **Usage Guide**

1. **Master Password**

   * The first prompt asks for a master password.
   * This password is used to derive the encryption key and **cannot be recovered if lost**.

2. **Add Entry**

   * Click **“Add Entry”**.
   * Enter website, username, and password (or auto-generate).
   * The password is automatically encrypted and saved.

3. **Update Entry**

   * Select an entry in the table and click **“Update Entry”**.
   * Change username or password (optional). Password strength is updated automatically.

4. **Delete Entry**

   * Select an entry in the table and click **“Delete Entry”**.

5. **Search**

   * Use the **search bar** to filter entries by website or username.

6. **Copy Password**

   * Double-click a table row to copy its password to clipboard.

7. **Generate Password**

   * Click **“Generate Password”** to create a strong random password and copy it to clipboard.

8. **Backup / Import**

   * **Export Backup**: Save an encrypted `.bak` backup file.
   * **Import Backup**: Load an encrypted `.bak` backup file to restore entries.

---

## **Security Notes**

* All data is **stored locally** and encrypted with AES-256.
* Never share your master password; it is required to decrypt all entries.
* Backups are **encrypted** but should still be stored securely.
* Avoid committing `data/passwords.dat`, `data/salt.dat`, or any `.bak` files to public repositories.

---

## **Dependencies**

* Python 3.x
* pycryptodome (`pip install pycryptodome`)
* pyperclip (`pip install pyperclip`)

Contents of `requirements.txt`:

```
pycryptodome
pyperclip
```

---

## **Future Improvements**

* Add **dark/light mode toggle** in GUI.
* Implement **auto-lock** after a period of inactivity.
* Multi-user support for shared machines (with separate master passwords).
* Optional cloud-synced encrypted backups.

---
<img width="1920" height="1200" alt="Screenshot 2026-02-09 193031" src="https://github.com/user-attachments/assets/5c7ba23f-de90-41ae-914b-6eeea8130cc7" />

<img width="1920" height="1200" alt="Screenshot 2026-02-09 193046" src="https://github.com/user-attachments/assets/265b7494-00dc-46ef-bd1e-619d7d53c46f" />

<img width="1920" height="1200" alt="Screenshot 2026-02-09 193004" src="https://github.com/user-attachments/assets/03150f89-4864-45ba-aedd-436ea6c11be4" />

<img width="1920" height="1200" alt="Screenshot 2026-02-09 193015" src="https://github.com/user-attachments/assets/53ecb9e8-4d29-4214-8216-3f89258b74a5" />

<img width="1917" height="1144" alt="Screenshot 2026-02-09 194250" src="https://github.com/user-attachments/assets/1127e97d-9c13-4640-939d-a9488511616d" />


## **License**

This project is **open-source** and licensed under **MIT License**. You are free to use, modify, and distribute it for personal and educational purposes.

