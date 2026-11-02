# PasswordPorter

Library + CLI (`pwport`) that moves saved passwords between browsers, password managers and files.

## Build & test

```
dotnet build PasswordPorter.sln
dotnet test PasswordPorter.sln
```

- Everything targets `net10.0` (set once in `Directory.Build.props`), with implicit usings and
  nullable reference types on. Prefer BCL APIs (`System.Text.Json`, `BinaryPrimitives`,
  `RandomNumberGenerator`, `CryptographicOperations`, `Convert.FromHexString`...) over hand-rolled helpers.
- Write current C#: file-scoped namespaces, primary constructors, records for data, collection
  expressions (`[]`, spreads), switch expressions and patterns (`is null`, list/property patterns),
  raw string literals, and spans for byte manipulation. Zero secrets with `CryptographicOperations.ZeroMemory`.
- `tests/KeePassCheck` is the one exception: a test-only `net48` console app that wraps KeePassLib
  from `KeePass-2.61.1/KeePass.exe` (git-ignored, optional). KeePassLib needs .NET Framework APIs,
  so `KeePassLibInteropTests` run the helper as a separate process to cross-check our KDBX files
  against real KeePass. Without KeePass.exe those tests are compiled out (`HAVE_KEEPASSCHECK`).
- `FirefoxNssTests` use the installed Firefox's NSS on a throwaway profile; they no-op if Firefox
  is absent. Never point tests at a real profile.

## Layout

- `src/PasswordPorter.Core` – `Credential` model, provider interfaces (`Providers/Abstractions.cs`),
  `ProviderContext` (options + secret resolution), `ProviderRegistry`, CSV provider and helpers.
- `src/PasswordPorter.Firefox` – reads `logins.json` (System.Text.Json source generator) and decrypts
  with Firefox's own `nss3`, loaded via `NativeLibrary` and called through unmanaged function pointers.
- `src/PasswordPorter.KeePass` – dependency-free KDBX 3.1/4.x read/write (`Kdbx/`) and the
  primitives .NET has no API for (`Crypto/`: BLAKE2b, Argon2, raw ChaCha20 and Salsa20 streams).
- `src/PasswordPorter.Cli` – `pwport` front end; providers are registered in `Program.CreateRegistry`.
- `archive/first-attempt` – the original pre-rewrite P/Invoke experiment, not built.

## Chrome / Edge

There is deliberately no Chromium provider. Chrome 127+ and current Edge protect every saved password
with App-Bound Encryption (the `v20` prefix in `Login Data`), decryptable only by the browser itself;
the only bypasses are the browser-impersonation techniques infostealer malware uses, which this project
won't implement. (Verified on this machine: a read-only probe of real `Login Data` found all `v20`, no
`v10`.) The supported route is the browser's own CSV export read through the `csv` provider — see README.
`CsvProvider`'s column aliases already map Chrome/Edge's `name,url,username,password,note` header.

## Adding a provider (e.g. Chrome, Bitwarden)

1. New project `src/PasswordPorter.<Name>` referencing Core (copy an existing csproj).
2. Implement `ICredentialSourceProvider` and/or `ICredentialTargetProvider`
   (+ `IProfileDiscovery` if it can find stores on the machine). Declare options with
   `ProviderOption`; get secrets through `ProviderContext.GetSecret` so prompting stays in the front end.
3. Throw `ProviderException` for user-facing errors.
4. Register it in `Program.CreateRegistry` and add tests.
