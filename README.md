# PasswordPorter

🚨WARNING: This is mostly vibe-coded slop, **User Beware**. I haven't reviewed the code that closely... it seems overengineered... 🚨

This is a .NET library (plus a terminal front-end) that moves saved passwords around between different web browsers and password managers. Currently it supports Firefox, KeePass KDBX files, and CSV files, but I might add more sources in the future.

It targets modern .NET (.NET 10).

## Chrome / Edge

PasswordPorter does **not** read Chrome's or Edge's password database directly. Current versions
(Chrome 127+ and matching Edge) protect each saved password with **App-Bound Encryption**: the data
can only be decrypted by the browser itself, and the only ways around that are the same tricks
password-stealing malware uses, which this tool won't do.

Instead, export from the browser — it decrypts your passwords for you after asking for your Windows
password — then import the CSV:

- **Chrome:** Settings → Autofill and passwords → Google Password Manager → Settings → Export passwords.
- **Edge:** Settings → Profiles → Passwords → `...` (top right of the Saved passwords list) → Export passwords.

```bash
pwport export csv keepass -i file="Chrome Passwords.csv" -o file=Passwords.kdbx -o group=Browsers/Chrome
```

The CSV holds your passwords in clear text, so delete it securely once the import is done. Other
Chromium browsers (Brave, Vivaldi, Opera, …) export the same CSV format and import the same way.
