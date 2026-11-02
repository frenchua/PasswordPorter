<div align="center">

# 🔐 PasswordPorter

**Move your saved passwords between browsers and password managers — from one command line.**

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational)](#building)
[![Tests](https://img.shields.io/badge/tests-38%20passing-success)](tests/)

</div>

---

PasswordPorter is a small .NET library and terminal app (`pwport`) that reads your saved logins from
one place and writes them to another. It speaks to each browser or password manager through a
**provider**, and converts everything through one neutral `Credential` shape, so any source can feed
any target.

```
┌───────────┐        ┌──────────────┐        ┌───────────┐
│  Firefox  │─ read ─▶│  Credential  │─ write ▶│  KeePass  │
│  KeePass  │        │   (neutral   │        │    CSV    │
│    CSV    │        │    model)    │        │           │
└───────────┘        └──────────────┘        └───────────┘
```

## What it supports

| Provider  | Read | Write | Notes |
|-----------|:----:|:-----:|-------|
| **Firefox** | ✅ | — | Decrypts `logins.json` with Firefox's own NSS library. Handles a primary password. |
| **KeePass** | ✅ | ✅ | KDBX 3.1 and 4.x. Creates a new `.kdbx` or merges into an existing one, dependency-free. |
| **CSV** | ✅ | ✅ | Reads exports from Firefox, Chrome, Edge, Bitwarden, KeePass and similar; writes a generic layout. |
| **Chrome / Edge** | via CSV | — | Export from the browser to CSV, then import that — see [below](#chrome--edge). |

## Building

Needs the [.NET 10 SDK](https://dotnet.microsoft.com/download). Everything is managed code, so it builds
and runs on Windows, macOS and Linux — though it's developed and tested on Windows, and the Firefox
provider needs Firefox (and its NSS library) installed on the machine.

```bash
dotnet build PasswordPorter.sln
dotnet test  PasswordPorter.sln
```

Run the CLI straight from the repo:

```bash
dotnet run --project src/PasswordPorter.Cli -- <command>
```

The examples below use `pwport` as shorthand for that.

## Quick start

**Firefox → a new KeePass database:**

```bash
pwport export firefox keepass -o file=Passwords.kdbx
```

It reads your default Firefox profile, prompts for a new KeePass master password, and writes
`Passwords.kdbx` with the logins under an `Imported` group.

**See what would be read, without writing anything:**

```bash
pwport list firefox                 # passwords stay masked
pwport export firefox keepass -o file=Passwords.kdbx --dry-run
```

**Merge one database into another, into a chosen group:**

```bash
pwport export keepass keepass \
  -i file=Old.kdbx -o file=Passwords.kdbx -o group=Imported/Old
```

Entries already present (same URL, username and password) are skipped by default.

## Usage

```
pwport providers [<provider>]          List providers, or show one provider's options
pwport profiles  <provider>            List the profiles a provider finds on this machine
pwport list      <source> [-i k=v]...  Show credentials (passwords masked)
pwport export    <source> <target> [-i k=v]... [-o k=v]... [--dry-run]
```

- `-i key=value` sets a **source** option, `-o key=value` a **target** option (both repeatable).
- `--show-passwords` reveals passwords in `list`; `--dry-run` reads and reports but writes nothing.
- Run `pwport providers <name>` to see every option a provider accepts.

### Passwords and secrets

Master/primary passwords are **prompted for** and never echoed. For scripting, point an option at an
environment variable instead of putting the secret in your shell history:

```bash
$env:KDBX_PW = "..."                       # PowerShell
pwport export firefox keepass -o file=Passwords.kdbx -o password-env=KDBX_PW
```

## Chrome / Edge

PasswordPorter does **not** read Chrome's or Edge's password database directly. Chrome 127+ and current
Edge protect every saved password with **App-Bound Encryption** — the data can only be decrypted by the
browser itself, and the only ways around that are the techniques password-stealing malware uses, which
this tool won't do.

Instead, let the browser export for you (it decrypts your passwords after asking for your Windows
password), then import the CSV:

- **Chrome** — Settings → Autofill and passwords → Google Password Manager → Settings → **Export passwords**
- **Edge** — Settings → Profiles → Passwords → `⋯` → **Export passwords**

```bash
pwport export csv keepass -i file="Chrome Passwords.csv" -o file=Passwords.kdbx -o group=Browsers/Chrome
```

> [!WARNING]
> A browser CSV export holds your passwords in **clear text**. Delete it securely once the import is
> done. Other Chromium browsers (Brave, Vivaldi, Opera, …) export the same format and import the same way.

## Security notes

- Secrets are prompted without echo and zeroed in memory after use where practical.
- KeePass saves are written to a temporary file, verified to re-open with the given key, and only then
  swapped in — keeping a `.bak` of the previous version by default.
- Tests never touch your real profiles or databases; they build throwaway fixtures in a temp folder.
- Treat any plaintext CSV as sensitive and delete it when you're done.

## How it works

| Project | Responsibility |
|---------|----------------|
| `PasswordPorter.Core` | The `Credential` model, provider interfaces, option/secret handling, and the CSV provider. |
| `PasswordPorter.Firefox` | Reads `logins.json` and decrypts via Firefox's `nss3`, loaded through `NativeLibrary`. |
| `PasswordPorter.KeePass` | Dependency-free KDBX 3.1/4.x read/write, including the crypto .NET lacks (BLAKE2b, Argon2, ChaCha20, Salsa20). |
| `PasswordPorter.Cli` | The `pwport` front end; providers are registered in `Program.CreateRegistry`. |

Adding a browser or password manager means writing one new provider — see [`AGENTS.md`](AGENTS.md) for
the walkthrough and project conventions.

## Status & license

A personal project that handles sensitive data. It has a solid test suite (including cross-checks of the
KDBX output against real KeePass), but it hasn't been independently audited — review it yourself before
trusting it with your passwords. No license has been chosen yet, so default copyright applies.
