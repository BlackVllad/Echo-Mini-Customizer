# Echo Mini Customizer

Credits to the creator of the flame-ocean-website repository, link "https://github.com/losses/flame-ocean-website#https://github.com/losses/flame-ocean-website#"

### [⬇ Download EchoMiniCustomizer.exe](https://github.com/BlackVllad/Echo-Mini-Customizer/releases/latest)
This link is because im idiot and i dont remember where I put the downloader of the .EXE

A PyQt5 desktop application for customizing **Snowsky Echo Mini** firmware themes. View, edit, and replace boot animations, menu screens, music player UI, and other firmware resources directly from `.IMG` firmware files.

## Features

- **Theme Preview** — View how your themes seems before adding it to your Echo Mini 
- **Boot/Shutdown/Charging Animations** — Play and replace frame-by-frame boot, shutdown, and charging animations
- **MP4 Import** — Import video files and automatically distribute frames across animation slots
- **Image Replacement** — Replace any firmware resource image (menus, icons, backgrounds) with custom PNG/JPG/BMP files
- **Theme Export/Import** — Export complete themes as PNG folders, import them back into different firmware slots
- **Theme Renaming** — Edit theme names stored in the firmware String Table (applied across all 21 languages)
- **Firmware Patching** — One-click patch to enable per-theme boot/charge animations (originally shared across all themes)
- **DAC/USB Player** — Preview and edit DAC mode screens and USB player animations
- **Resource Browser** — Browse all firmware resources with category filtering
- **Dark UI** — Modern dark-themed interface

## Requirements

- Python 3.10+
- PyQt5
- opencv-python-headless (for MP4 import)
- Pillow

## Installation

```bash
git clone https://github.com/BlackVllad/Echo-Mini-Customizer.git
cd Echo-Mini-Customizer
pip install -r requirements.txt
python echo_mini_customizer.py
```

## Building an Executable

```bash
pip install pyinstaller
pyinstaller --onefile --name EchoMiniCustomizer echo_mini_customizer.py
```

The `.exe` will be in the `dist/` folder.

## Usage

1. **Open Firmware** — Click "📂 Open Firmware" and select a `.IMG` file (e.g., `HIFIEC20.IMG`)
2. **Browse Themes** — Use the theme dropdown to switch between available themes
3. **Edit Resources** — Navigate tabs (Boot, Shutdown, Charging, Main Menu, Player, Folders, DAC, USB) and click "Replace" on any image
4. **Patch Firmware** — Click "🔧 Patch Firmware" to enable per-theme boot animations (only needed once per firmware)
5. **Import Theme** — Click "📥 Import Theme" to import a folder of PNG images as a new theme
6. **Save** — Click "💾 Save Firmware" or "💾 Save As..." to write changes

## How to Transfer a Theme Between Firmware Files

To apply a theme from one `.IMG` to a different `.IMG`:

1. **Open the source firmware** — Open the `.IMG` that already has the theme you want
2. **Export the theme** — Click **"📤 Export Themes"**, select the theme you want, and choose a folder to save it
3. **Open the target firmware** — Open the `.IMG` you want to apply the theme to
4. **Import the theme** — Click **"📥 Import Theme"**, select the exported folder, choose which theme slot to place it in, and confirm

> The exported folder contains all the PNG images for that theme. You can also edit those images externally before importing them back.

## Firmware Patching Details **REALLY IMPORTANT**

The Echo Mini firmware shares boot/charge animations across all themes by default. The built-in patcher modifies the ARM Thumb2 theme dispatch function to:

- Change `CMP R0, #0x43` → `CMP R0, #0x00` (include all resource indices in theme dispatch)
- Adjust `ADDW` offset instructions for expanded theme blocks (307 → 374 entries per theme)
- Expand ROCK26 and metadata tables with per-theme copies of shared boot resources
- Recalculate Rockchip CRC32 integrity checksum

The patch is auto-detected and works across firmware versions.

## Firmware Structure

The Echo Mini uses Rockchip RKnano firmware with:
- **ROCK26** image resource table (16 bytes/entry)
- **Metadata** table (108 bytes/entry) with resource names, dimensions, offsets
- **RGB565** bitmap data (big-endian byte-swapped)
- **StrTbl** string table for theme names (21 languages, UTF-16LE)

See `docs/echo_mini_resource_map.html` for a detailed firmware resource diagram.

## License

MIT
