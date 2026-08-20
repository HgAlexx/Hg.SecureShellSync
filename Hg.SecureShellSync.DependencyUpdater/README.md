# Hg.SecureShellSync.DependencyUpdater

A small maintenance tool that keeps `Hg.SecureShellSync\lib\` in sync with NuGet.

## Why this project exists

KeePass compiles this plugin into a **PLGX** at load time. That compilation happens on the end
user's machine and **cannot restore NuGet packages**, so every dependency has to be a real DLL
committed to the repository under `Hg.SecureShellSync\lib\` and referenced through a `HintPath`.

Maintaining those files by hand is error prone: it is easy to miss a new transitive dependency,
or to leave a `Reference Include` version that no longer matches the DLL actually shipped. A PLGX
has no `App.config`, which means **no binding redirects are available** and a mismatched assembly
identity becomes a runtime `FileLoadException` for the user.

This project solves that by being the single place where the dependency versions are declared.
NuGet resolves the full transitive closure into this project's output folder, and the tool then
mirrors that folder into the plugin's `lib\`.

This project is **not** part of the plugin and is never shipped. KeePass only compiles the
`Hg.SecureShellSync` folder, so having this extra project in the solution is harmless.

## How to update the dependencies

Two helper scripts at the solution root wrap the whole tool:

| Script | What it does |
| --- | --- |
| `.\diff.ps1` | Builds the tool and reports what would change, including the `Reference` items. Read-only. |
| `.\update.ps1` | Builds the tool, copies the updated DLLs into `Hg.SecureShellSync\lib\` and rewrites the plugin's `Reference` items. |

Both scripts build in `Release` first, so you never have to run `dotnet build` by hand.

### 1. Declare the version you want

Edit `Hg.SecureShellSync.DependencyUpdater.csproj` and set the version on the `PackageReference`:

```xml
<ItemGroup>
  <PackageReference Include="SSH.NET" Version="2026.0.0" />
</ItemGroup>
```

Only top-level packages belong here. Transitive dependencies such as `BouncyCastle.Cryptography`
or `Microsoft.Extensions.Logging.Abstractions` are resolved automatically and must **not** be
listed, otherwise you risk pinning a version the top-level package did not ask for.

To discover the latest available version:

```powershell
dotnet list Hg.SecureShellSync.DependencyUpdater\Hg.SecureShellSync.DependencyUpdater.csproj package --outdated
```

### 2. Review the differences

From the solution root, run:

```powershell
.\diff.ps1
```

This builds the project in Release (which triggers the NuGet restore and copies the entire
resolved closure into the output folder) and then reports the differences. Nothing is written
to disk in this mode.

Example output:

```
  BouncyCastle.Cryptography    2.0.0.0 (file 2.4.0.33771) -> 2.0.0.0 (file 2.7.0.16391)
  Microsoft.Bcl.Cryptography   MISSING  -> 10.0.0.10 (file 10.0.1026.32716)
  Renci.SshNet                 up to date  2026.0.0.1 (file 2026.0.0.1)
```

The comparison uses both the assembly version and the file version, because some packages
(BouncyCastle in particular) keep a frozen assembly version across releases.

### 3. Apply the changes

```powershell
.\update.ps1
```

This copies every new or changed assembly into `Hg.SecureShellSync\lib\` **and** rewrites the
matching `Reference` items in `Hg.SecureShellSync\Hg.SecureShellSync.csproj` so their assembly
identities line up with the DLLs that were just copied. There is nothing to paste by hand.

Only references pointing into `lib\` are touched. The `KeePass` reference and the plain framework
references (`System`, `System.Windows.Forms`, ...) are left exactly as they are. Running the
command twice is safe: if the references are already correct the file is not written at all.

### 4. Build and test

```powershell
dotnet build Hg.SecureShellSync.sln
```

A successful build only proves the API surface still matches. Because a major version bump can
change runtime behaviour, load the plugin in KeePass and perform a real sync before committing.

### 5. Commit

Commit the changed DLLs in `Hg.SecureShellSync\lib\` together with the `.csproj` changes and the
updated `PackageReference`. They must always move together.

## Removed dependencies

When a package leaves the dependency graph, its DLL stays behind in `lib\`. The tool lists these
files under *"No longer part of the dependency graph"* but never deletes them, since the plugin
may reference an assembly directly rather than through a package. Delete them manually after
confirming nothing in the plugin uses them, then remove the matching `Reference` from the csproj.

## Framework facades and MSB3277

Some assemblies are already shipped with .NET Framework 4.8 as facades, `System.ValueTuple` being
the notable one. Keeping a copy in `lib\` produces an unresolvable `MSB3277` warning:

```
warning MSB3277: Found conflicts between different versions of "System.ValueTuple"
```

The framework facade is version `4.0.2.0` and wins because it is a primary reference, while
SSH.NET and its dependencies bind to `4.0.5.0`. On a normal project a binding redirect would
paper over the gap, but a PLGX has no `App.config`, so the conflict has to be avoided instead
of redirected. The fix is simply to not ship the assembly and let the framework provide it.

The tool knows about these facades: it excludes them from `lib\` and from the generated
references, and flags any leftover copy in the orphan list. If you ever see `MSB3277` for a new
assembly, check whether .NET Framework provides it and, if so, add its name to the
`FrameworkFacades` set in `Program.cs`.

## Adding a new dependency

1. Add the `PackageReference` to this project.
2. Run steps 2 to 5 above.
3. Confirm the new assembly appears in `lib\` and in the generated `Reference` block.

Keep the number of dependencies low. Every DLL added here ends up inside the PLGX shipped to
users.

## Notes

- Only assemblies valid for `net48` are usable. If a package drops .NET Framework support, the
  restore will warn or fail and the version cannot be adopted.
- The tool skips its own assembly, so it never pollutes the plugin's `lib\` folder.
- Native files and non-managed DLLs are ignored automatically.
