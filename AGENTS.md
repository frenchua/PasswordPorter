# PasswordPorter

Library + CLI (`pwport`) that moves saved passwords between browsers, password managers and files.

## Build & test

```
dotnet build PasswordPorter.sln
dotnet test PasswordPorter.sln
```

- Every project targets `net48` (the .NET Framework shipped with Windows) and `net10.0`.
  Code must compile for both: no `Span`, `System.Text.Json`, `init`/records, `^`/`..` ranges,
  `SHA256.HashData`, `Convert.ToHexString`, etc. Use the helpers in `KeePass/Crypto/CryptoUtil.cs`
  and `Core/Text/SimpleJson.cs` instead. Nullable warnings are only analysed on net10.0.
- The net48 test run also references `KeePass-2.61.1/KeePass.exe` (git-ignored, optional) and
  cross-checks our KDBX output against real KeePassLib (`KeePassLibInteropTests`, `HAVE_KEEPASSLIB`).
- `FirefoxNssTests` use the installed Firefox's NSS on a throwaway profile; they no-op if Firefox
  is absent. Never point tests at a real profile.

## Layout

- `src/PasswordPorter.Core` – `Credential` model, provider interfaces (`Providers/Abstractions.cs`),
  `ProviderContext` (options + secret resolution), `ProviderRegistry`, CSV provider, JSON/CSV helpers.
- `src/PasswordPorter.Firefox` – reads `logins.json` and decrypts with Firefox's own `nss3`
  (bound at runtime via function pointers; works on both TFMs).
- `src/PasswordPorter.KeePass` – dependency-free KDBX 3.1/4.x read/write (`Kdbx/`) and the
  primitives net48 lacks (`Crypto/`: BLAKE2b, Argon2, ChaCha20, Salsa20).
- `src/PasswordPorter.Cli` – `pwport` front end; providers are registered in `Program.CreateRegistry`.
- `archive/first-attempt` – the original pre-rewrite P/Invoke experiment, not built.

## Adding a provider (e.g. Chrome, Bitwarden)

1. New project `src/PasswordPorter.<Name>` referencing Core (copy an existing csproj).
2. Implement `ICredentialSourceProvider` and/or `ICredentialTargetProvider`
   (+ `IProfileDiscovery` if it can find stores on the machine). Declare options with
   `ProviderOption`; get secrets through `ProviderContext.GetSecret` so prompting stays in the front end.
3. Throw `ProviderException` for user-facing errors.
4. Register it in `Program.CreateRegistry` and add tests.
