# Win32 Client — Native Win32 C++ Client Port (`gclient-win32`)

Native Win32 C++17 client for **Win32 Client** (`com.app.client`) built on **Cocos2d-x 2.2.6 (Win32 x86)** + Lua.

---

## 1. Where to Put Game Assets (Required Before Running)

On Android, Win32 Client loads assets in **3 priority layers** (highest priority first):
1. **Hotfix overlay** (new patches downloaded at runtime)
2. **Hot-updated `Resources/`** (from `/data/data/com.app.client/files/Resources/`)
3. **Base APK `assets/`** (unzipped from `base_client.apk`)

Put your extracted files into this folder layout anywhere on Windows (for example `C:\GCLIENT\`):

```text
C:\GCLIENT\
├── GCLIENT.exe                       # Built Win32 executable (+ required .dlls)
├── base_assets\                    # Unzipped "assets/" folder from the .apk
│   ├── platform\
│   │   ├── config.json             # DES-encrypted platform config (BTPRIKEY)
│   │   └── game_config.json        # DES-encrypted game config (BTPRIKEY)
│   ├── res\                        # Base .plistb, .xmlb, .pb, .pvr.ccz, .png, .mp3
│   │   └── database\               # Base plaintext SQLite 3 .db files
│   └── scripts\                    # Base Lua scripts (main.lua, etc.)
├── Resources\                      # Extracted from /data/data/com.app.client/files/Resources/
│   ├── database\                   # Hot-updated SQLite 3 .db files (171 tables)
│   ├── res\                        # Hot-updated UI (.pb), armatures (.xmlb), sprites (.plistb/.pvr.ccz)
│   └── scripts\                    # Hot-updated Lua scripts (including version.lua)
└── profiles\                       # Per-instance writable state (created automatically)
    └── acc1\
        ├── hotfix\                 # Atomic hot-update overlay
        ├── writable\               # CCUserDefault & save data
        ├── logs\                   # PID-isolated rotating logs
        └── dumps\                  # Win32 crash minidumps (.dmp)
```

### What Does NOT Need to Be Copied
* Do **not** copy `lib/*.so`, `classes*.dex`, `META-INF/`, `AndroidManifest.xml`, `app_webview/`, `cache/`, or `code_cache/`.
* You do **not** need to manually decrypt `0xFEFEFEFE` files — `src/assets/07_bt_decrypt_keys.inc` (all 16 keys) is already compiled into `GCLIENT.exe`.

### Pre-Flight Asset Check
Before launching `GCLIENT.exe`, verify your `Resources/` folder:
```bat
python tools\validate_resources.py "C:\GCLIENT\Resources"
```

---

## 2. Launching the Native Win32 Client

Pass `--resources-dir` (hot-updated `Resources/`) and `--base-assets-dir` (APK `assets/`):

```bat
GCLIENT.exe ^
  --resources-dir "C:\GCLIENT\Resources" ^
  --base-assets-dir "C:\GCLIENT\base_assets" ^
  --profile-dir "C:\GCLIENT\profiles\acc1"
```

### Supported CLI Flags
| Flag | Description |
| :--- | :--- |
| `--resources-dir <path>` | Hot-updated `Resources/` directory (searched before base APK assets). |
| `--base-assets-dir <path>` | Unzipped APK `assets/` directory (fallback layer + `platform/*.json`). |
| `--profile-dir <path>` | Isolated writable directory per account/instance (prevents SQLite/log locks). |
| `--width <px> --height <px>` | Initial window size (default `1136x640`). |
| `--mute` | Start with music and SFX muted. |
| `--validate-assets` | Run startup asset integrity check before booting Lua. |

### Desktop Controls
* **Esc** — Android Back button (`Platform::onPressBack`)
* **F11** — Toggle borderless fullscreen
* **Ctrl + M** — Toggle audio mute

---

## 3. Building from Source (Windows + Visual Studio 2022)

1. Clone stock **Cocos2d-x 2.2.6** into `external/cocos2d-x-2.2.6` and apply the `CCFileUtils` decrypt hook:
   ```bat
   git clone --branch cocos2d-x-2.2.6 --depth 1 https://github.com/cocos2d/cocos2d-x.git external/cocos2d-x-2.2.6
   python tools\patch_cocos2dx.py external\cocos2d-x-2.2.6
   ```
2. Build Cocos2d-x 2.2.6 Win32 libraries (`libcocos2d`, `libCocosDenshion`, `libExtensions`, `liblua`) for **Win32 (x86)**.
3. Install Win32 dependencies via `vcpkg`:
   ```bat
   vcpkg install sqlite3:x86-windows protobuf:x86-windows curl:x86-windows openssl:x86-windows zlib:x86-windows
   ```
4. Configure and build `GCLIENT.exe`:
   ```bat
   cmake -B build -G "Visual Studio 17 2022" -A Win32 ^
     -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
     -DVCPKG_TARGET_TRIPLET=x86-windows ^
     -DGCLIENT_COCOS2DX_ROOT="%CD%\external\cocos2d-x-2.2.6" ^
     -DGCLIENT_COCOS2DX_LIB_DIR="%CD%\external\cocos2d-x-2.2.6\Release.win32"
   cmake --build build --config Release
   ```
