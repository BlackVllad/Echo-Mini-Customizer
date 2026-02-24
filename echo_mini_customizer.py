#!/usr/bin/env python3
"""
Echo Mini Firmware Customizer
Interactive preview of boot/shutdown screens, main menu, music player,
file browser, and other firmware resources with real-time editing.
"""

import sys
import os
import struct
import array
from pathlib import Path
from collections import OrderedDict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QScrollArea, QGridLayout,
    QFileDialog, QGroupBox, QComboBox, QFrame, QSplitter,
    QMessageBox, QProgressBar, QStatusBar, QListWidget, QListWidgetItem,
    QSizePolicy, QToolBar, QAction, QSlider, QStyle,
    QDialog, QDialogButtonBox, QRadioButton, QButtonGroup, QLineEdit
)
from PyQt5.QtCore import Qt, QTimer, QSize, QByteArray, QBuffer
from PyQt5.QtGui import QPixmap, QImage, QPainter, QColor, QFont, QIcon, QPen


def get_app_dir():
    """Get directory where the executable/script lives."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent

# ============================================================================
# Firmware Parsing Engine
# ============================================================================

class FirmwareParser:
    """Parse Rockchip RKnano firmware and extract/replace RGB565 bitmap resources."""

    METADATA_ENTRY_SIZE = 108

    # StrTbl theme name constants
    STRTBL_THEME_NAME_OFFSET = 0x157E4   # within each language section
    STRTBL_THEME_ENTRY_SIZE  = 0x102     # 258 bytes between names
    STRTBL_NAME_FIELD_SIZE   = 0xC8      # 200 bytes max per name (100 chars)

    def __init__(self, img_path):
        self.img_path = Path(img_path)
        self.img_data = bytearray(self.img_path.read_bytes())
        self.part5_offset = 0
        self.part5_size = 0
        self.entries = []
        self.misalignment = 0
        self.theme_names = []       # list of English theme names
        self._strtbl_info = None    # (strtbl_off, nr_lang, lang_offsets)
        self._parse()

    def _parse(self):
        info = struct.unpack('<IIII', self.img_data[0x14C:0x15C])
        self.part5_offset = info[0]
        self.part5_size = info[1]
        part5 = self.img_data[self.part5_offset:self.part5_offset + self.part5_size]

        rock26_off = part5.find(b'ROCK26IMAGERES')
        if rock26_off == -1:
            raise ValueError("ROCK26 table not found in firmware")

        rock26_count = struct.unpack('<I', part5[rock26_off + 16:rock26_off + 20])[0]
        rock26_start = rock26_off + 32
        self.rock26_off_in_part5 = rock26_off
        self.rock26_start_in_part5 = rock26_start
        self.rock26_count = rock26_count

        # Find metadata table via anchor
        anchor = struct.unpack('<I', part5[rock26_start + 12:rock26_start + 16])[0]
        first_match = None
        for pos in range(0, len(part5) - self.METADATA_ENTRY_SIZE, 4):
            eoff = struct.unpack('<I', part5[pos + 20:pos + 24])[0]
            if eoff == anchor:
                nm = part5[pos + 32:pos + 96].split(b'\x00')[0].decode('ascii', errors='ignore')
                if nm.endswith('.BMP') and len(nm) >= 5:
                    first_match = pos
                    break

        if first_match is None:
            raise ValueError("Metadata table not found")

        table_start = first_match
        while table_start >= self.METADATA_ENTRY_SIZE:
            tp = table_start - self.METADATA_ENTRY_SIZE
            tn = part5[tp + 32:tp + 96].split(b'\x00')[0].decode('ascii', errors='ignore')
            if tn and tn.endswith('.BMP') and len(tn) >= 3:
                table_start = tp
            else:
                break

        # Parse entries
        self.entries = []
        pos = table_start
        while pos + self.METADATA_ENTRY_SIZE <= len(part5):
            nm = part5[pos + 32:pos + 96].split(b'\x00')[0].decode('ascii', errors='ignore')
            if not nm or len(nm) < 3:
                break
            off = struct.unpack('<I', part5[pos + 20:pos + 24])[0]
            w = struct.unpack('<I', part5[pos + 24:pos + 28])[0]
            h = struct.unpack('<I', part5[pos + 28:pos + 32])[0]
            self.entries.append({
                'name': nm, 'offset': off, 'width': w, 'height': h,
                'table_pos': pos
            })
            pos += self.METADATA_ENTRY_SIZE

        self.table_start = table_start

        # Detect misalignment
        rock26_offsets = []
        for i in range(min(20, rock26_count)):
            eo = rock26_start + i * 16
            rock26_offsets.append(struct.unpack('<I', part5[eo + 12:eo + 16])[0])

        votes = {}
        for ri in range(len(rock26_offsets)):
            for shift in range(-3, 4):
                mi = ri + shift
                if 0 <= mi < len(self.entries):
                    if self.entries[mi]['offset'] == rock26_offsets[ri]:
                        votes[shift] = votes.get(shift, 0) + 1

        self.misalignment = max(votes.items(), key=lambda x: x[1])[0] if votes else 0

        # Repair corrupted metadata entries using R26 as source of truth
        self._repair_metadata(part5)
        self._parse_theme_names()

    def _repair_metadata(self, part5):
        """Fix metadata entries with clearly invalid offsets by using R26 data."""
        repaired = 0
        for i in range(min(self.rock26_count, len(self.entries))):
            meta_idx = i + self.misalignment
            if not (0 <= meta_idx < len(self.entries)):
                continue
            meta_off = self.entries[meta_idx]['offset']
            if meta_off != 0 and meta_off < len(part5):
                continue  # looks valid
            r26_pos = self.rock26_start_in_part5 + i * 16
            if r26_pos + 16 > len(part5):
                continue
            r26_vals = struct.unpack('<IIII', part5[r26_pos:r26_pos + 16])
            r26_off = r26_vals[3]
            if r26_off == 0 or r26_off >= len(part5):
                continue
            # Extract dimensions from R26 id field: low16=width, high16=height
            r26_w = r26_vals[0] & 0xFFFF
            r26_h = (r26_vals[0] >> 16) & 0xFFFF
            # Fix metadata entry
            tp = self.entries[meta_idx]['table_pos']
            abs_tp = self.part5_offset + tp
            struct.pack_into('<I', self.img_data, abs_tp + 20, r26_off)
            struct.pack_into('<I', self.img_data, abs_tp + 24, r26_w)
            struct.pack_into('<I', self.img_data, abs_tp + 28, r26_h)
            self.entries[meta_idx]['offset'] = r26_off
            self.entries[meta_idx]['width'] = r26_w
            self.entries[meta_idx]['height'] = r26_h
            repaired += 1
        if repaired:
            # Re-read part5 since we modified img_data
            pass  # part5 variable is stale but we already updated entries dict

    def _parse_theme_names(self):
        """Parse theme names from the StrTbl section."""
        self.theme_names = []
        self._strtbl_info = None
        strtbl_off = struct.unpack_from('<I', self.img_data, 0xF8)[0]
        strtbl_sz = struct.unpack_from('<I', self.img_data, 0xFC)[0]
        if strtbl_off == 0 or strtbl_sz == 0:
            return
        nr_lang = struct.unpack_from('<H', self.img_data, strtbl_off)[0]
        if nr_lang == 0 or nr_lang > 30:
            return
        lang_offsets = []
        for i in range(nr_lang):
            off = struct.unpack_from('<I', self.img_data, strtbl_off + 2 + i * 4)[0]
            lang_offsets.append(off)
        self._strtbl_info = (strtbl_off, nr_lang, lang_offsets)
        # Read English names (Lang 2) or first available
        eng_idx = 2 if nr_lang > 2 else 0
        section_abs = strtbl_off + lang_offsets[eng_idx]
        HEADER_SIZE = 0x3A  # bytes from entry header to name text
        THEME_PARENT_ID = 0x0154  # parent_id marker for theme name entries
        for ti in range(20):
            name_addr = section_abs + self.STRTBL_THEME_NAME_OFFSET + ti * self.STRTBL_THEME_ENTRY_SIZE
            hdr_addr = name_addr - HEADER_SIZE
            if hdr_addr < 0 or name_addr + 4 > len(self.img_data):
                break
            # Verify this is a theme entry by checking parent_id at header[2:4]
            parent_id = struct.unpack_from('<H', self.img_data, hdr_addr + 2)[0]
            if parent_id != THEME_PARENT_ID:
                break
            name = self._read_utf16le(name_addr)
            if not name:
                break
            self.theme_names.append(name)

    def _read_utf16le(self, addr, max_chars=100):
        """Read a null-terminated UTF-16LE string from img_data."""
        chars = []
        for i in range(max_chars):
            if addr + i * 2 + 1 >= len(self.img_data):
                break
            c = struct.unpack_from('<H', self.img_data, addr + i * 2)[0]
            if c == 0:
                break
            chars.append(chr(c))
        return ''.join(chars)

    def set_theme_name(self, theme_index, new_name):
        """Write a theme name to all language sections in the StrTbl."""
        if not self._strtbl_info or theme_index < 0:
            return False
        if theme_index >= len(self.theme_names):
            return False
        strtbl_off, nr_lang, lang_offsets = self._strtbl_info
        new_name = new_name[:99]  # max 99 chars
        encoded = new_name.encode('utf-16-le') + b'\x00\x00'
        for lang_idx in range(nr_lang):
            section_abs = strtbl_off + lang_offsets[lang_idx]
            addr = section_abs + self.STRTBL_THEME_NAME_OFFSET + theme_index * self.STRTBL_THEME_ENTRY_SIZE
            if addr + self.STRTBL_NAME_FIELD_SIZE > len(self.img_data):
                continue
            # Clear name field, then write new name
            self.img_data[addr:addr + self.STRTBL_NAME_FIELD_SIZE] = b'\x00' * self.STRTBL_NAME_FIELD_SIZE
            self.img_data[addr:addr + len(encoded)] = encoded
        self.theme_names[theme_index] = new_name
        return True

    def get_part5(self):
        return self.img_data[self.part5_offset:self.part5_offset + self.part5_size]

    def get_resource_list(self):
        """Return list of extractable resource dicts with resolved dimensions."""
        part5 = self.get_part5()
        resources = []
        end = len(self.entries) - (1 if self.misalignment > 0 else 0)

        for i in range(end):
            e = self.entries[i]
            if self.misalignment > 0:
                ti = i + self.misalignment
                if ti >= len(self.entries):
                    continue
                offset = self.entries[ti]['offset']
            elif self.misalignment < 0:
                ti = i + self.misalignment
                if ti < 0:
                    continue
                offset = self.entries[ti]['offset']
            else:
                offset = e['offset']

            if i + 1 < len(self.entries):
                w = self.entries[i + 1]['width']
                h = self.entries[i + 1]['height']
            else:
                w, h = e['width'], e['height']

            if offset == 0 or offset >= len(part5):
                continue
            if w <= 0 or h <= 0 or w > 10000 or h > 10000:
                continue
            raw_size = w * h * 2
            if offset + raw_size > len(part5):
                continue

            resources.append({
                'index': i, 'name': e['name'],
                'offset': offset, 'width': w, 'height': h,
                'raw_size': raw_size
            })
        return resources

    def extract_image(self, res):
        """Extract a resource as QImage (RGBA)."""
        part5 = self.get_part5()
        raw = part5[res['offset']:res['offset'] + res['raw_size']]
        return rgb565_to_qimage(raw, res['width'], res['height'])

    def _allocate_part5_space(self, size):
        """Allocate new space at the end of Part5, returns offset within Part5."""
        new_offset = self.part5_size
        self.part5_size += size
        struct.pack_into('<I', self.img_data, 0x150, self.part5_size)
        needed = self.part5_offset + self.part5_size
        if needed > len(self.img_data):
            self.img_data.extend(b'\x00' * (needed - len(self.img_data)))
        return new_offset

    def _update_resource_offset(self, res, new_offset):
        """Update both R26 and metadata tables to point to new_offset."""
        idx = res['index']
        # Update R26 table entry
        r26_abs = self.part5_offset + self.rock26_start_in_part5 + idx * 16
        if r26_abs + 16 <= len(self.img_data):
            struct.pack_into('<I', self.img_data, r26_abs + 12, new_offset)
        # Update metadata table entry
        meta_idx = idx + self.misalignment
        if 0 <= meta_idx < len(self.entries):
            meta_abs = self.part5_offset + self.entries[meta_idx]['table_pos']
            struct.pack_into('<I', self.img_data, meta_abs + 20, new_offset)
            self.entries[meta_idx]['offset'] = new_offset

    def replace_image(self, res, qimage):
        """Replace a resource in the firmware with a new QImage.
        Uses copy-on-write: if the resource's data offset is shared with
        other resources, allocates new space to avoid overwriting them."""
        w, h = res['width'], res['height']
        if qimage.width() != w or qimage.height() != h:
            qimage = qimage.scaled(w, h, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

        raw = qimage_to_rgb565(qimage, w, h)
        target_offset = res['offset']

        # Check if this data offset is shared with other metadata entries
        shared_count = sum(1 for e in self.entries if e['offset'] == target_offset)
        if shared_count > 1:
            # Copy-on-write: allocate new space so we don't overwrite other themes
            new_offset = self._allocate_part5_space(len(raw))
            abs_new = self.part5_offset + new_offset
            self.img_data[abs_new:abs_new + len(raw)] = raw
            self._update_resource_offset(res, new_offset)
            res['offset'] = new_offset
        else:
            abs_offset = self.part5_offset + target_offset
            self.img_data[abs_offset:abs_offset + len(raw)] = raw

    def save(self, path=None):
        p = Path(path) if path else self.img_path
        self._fix_integrity()
        p.write_bytes(bytes(self.img_data))

    # ── ARM Thumb2 helpers ──────────────────────────────────────────

    @staticmethod
    def _decode_addw(hw1, hw2):
        """Decode a Thumb2 ADDW Rd, Rn, #imm12 instruction."""
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        imm8 = hw2 & 0xFF
        return (i << 11) | (imm3 << 8) | imm8

    @staticmethod
    def _encode_addw(imm12, rd=0, rn=0):
        """Encode ADDW Rd, Rn, #imm12 as bytes (4 bytes, little-endian)."""
        assert 0 <= imm12 < 4096, f"imm12 out of range: {imm12}"
        i = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 0x7
        imm8 = imm12 & 0xFF
        hw1 = 0xF200 | (i << 10) | rn
        hw2 = (imm3 << 12) | (rd << 8) | imm8
        return struct.pack('<HH', hw1, hw2)

    # ── Firmware patching ────────────────────────────────────────────

    def detect_patch_info(self):
        """Auto-detect CMP and ADDW locations in the firmware.
        Returns a dict with detection results, or raises ValueError."""
        data = self.img_data

        # Scan for CMP R0, #0x43 (0x2843) or already-patched CMP R0, #0x00 (0x2800)
        # within the Loader section (starts at 0x200)
        cmp_offset = None
        for off in range(0x200, min(len(data), 0x400000), 2):
            val = struct.unpack_from('<H', data, off)[0]
            if val == 0x2843 or val == 0x2800:
                # Check if 4 ADDW instructions follow within ~60 bytes
                addw_offsets = []
                for scan in range(off + 2, off + 80, 2):
                    if scan + 4 > len(data):
                        break
                    hw1, hw2 = struct.unpack_from('<HH', data, scan)
                    if (hw1 & 0xFBE0) == 0xF200 and (hw2 & 0x8F00) == 0x0000:
                        imm = self._decode_addw(hw1, hw2)
                        if imm > 100:
                            addw_offsets.append((scan, imm))
                if len(addw_offsets) >= 4:
                    cmp_offset = off
                    break

        if cmp_offset is None:
            raise ValueError("Could not find theme dispatch CMP instruction in firmware")

        # Collect the first 4 ADDW instructions after CMP
        addw_list = []
        for scan in range(cmp_offset + 2, cmp_offset + 80, 2):
            if scan + 4 > len(data):
                break
            hw1, hw2 = struct.unpack_from('<HH', data, scan)
            if (hw1 & 0xFBE0) == 0xF200 and (hw2 & 0x8F00) == 0x0000:
                imm = self._decode_addw(hw1, hw2)
                if imm > 100:
                    addw_list.append((scan, imm))
                    if len(addw_list) == 4:
                        break

        if len(addw_list) < 4:
            raise ValueError(f"Found CMP but only {len(addw_list)} ADDW instructions (need 4)")

        # Determine current state
        cmp_val = struct.unpack_from('<H', data, cmp_offset)[0]
        is_patched = (cmp_val == 0x2800)
        addw_values = [v for _, v in addw_list]

        # Detect block size: first ADDW value = old block size
        if is_patched:
            block_size = addw_values[0]
            shared_count = 67  # known constant
            old_block_size = block_size - shared_count
        else:
            old_block_size = addw_values[0]
            shared_count = 67
            block_size = old_block_size

        return {
            'cmp_offset': cmp_offset,
            'cmp_value': cmp_val,
            'is_patched': is_patched,
            'addw_list': addw_list,
            'addw_values': addw_values,
            'old_block_size': old_block_size,
            'shared_count': shared_count,
            'new_block_size': old_block_size + shared_count,
            'resource_count': self.rock26_count,
        }

    def patch_for_themed_boots(self, progress_callback=None):
        """Apply the themed-boot patch: expand resource tables, patch CMP + ADDWs, fix integrity.
        Returns a summary string."""
        info = self.detect_patch_info()
        if info['is_patched']:
            return "Firmware is already patched (CMP R0,#0x00 detected)."

        data = self.img_data
        SHARED = info['shared_count']         # 67
        OLD_BLK = info['old_block_size']      # 307
        NEW_BLK = info['new_block_size']       # 374
        cmp_off = info['cmp_offset']
        addw_list = info['addw_list']

        # ── 1. Expand ROCK26 + metadata tables ──
        part5 = self.get_part5()
        r26_start = self.rock26_start_in_part5
        old_count = self.rock26_count

        # Read shared resources (first 67)
        shared_r26 = []
        for i in range(SHARED):
            eo = r26_start + i * 16
            shared_r26.append(bytes(part5[eo:eo + 16]))

        shared_meta_raw = []
        for i in range(SHARED):
            tp = self.entries[i]['table_pos']
            shared_meta_raw.append(bytes(part5[tp:tp + self.METADATA_ENTRY_SIZE]))

        # Build new tables: 5 blocks × NEW_BLK entries each
        new_r26 = []
        new_meta = []
        theme_letters = ['A', 'B', 'C', 'D', 'E']

        for t_idx in range(5):
            letter = theme_letters[t_idx]
            # 67 shared copies
            for i in range(SHARED):
                new_r26.append(shared_r26[i])
                meta_raw = bytearray(shared_meta_raw[i])
                if t_idx > 0:
                    orig_name = self.entries[i]['name']
                    new_name = f"T_{letter}_{orig_name}"
                    name_bytes = new_name.encode('ascii')[:63]
                    name_padded = name_bytes + b'\x00' * (64 - len(name_bytes))
                    meta_raw[32:96] = name_padded
                new_meta.append(bytes(meta_raw))

            # OLD_BLK themed resources
            old_start = SHARED + t_idx * OLD_BLK
            for i in range(OLD_BLK):
                src_idx = old_start + i
                if src_idx < old_count:
                    eo = r26_start + src_idx * 16
                    new_r26.append(bytes(part5[eo:eo + 16]))
                else:
                    new_r26.append(shared_r26[0])
                if src_idx < len(self.entries):
                    tp = self.entries[src_idx]['table_pos']
                    new_meta.append(bytes(part5[tp:tp + self.METADATA_ENTRY_SIZE]))
                else:
                    new_meta.append(shared_meta_raw[0])

            if progress_callback:
                progress_callback(int((t_idx + 1) * 20))

        new_count = len(new_r26)

        # ── 2. Write expanded ROCK26 table ──
        r26_abs = self.part5_offset + self.rock26_off_in_part5
        count_abs = r26_abs + 16
        struct.pack_into('<I', data, count_abs, new_count)
        entries_abs = self.part5_offset + r26_start
        for i, entry_raw in enumerate(new_r26):
            pos = entries_abs + i * 16
            if pos + 16 > len(data):
                data.extend(b'\x00' * (pos + 16 - len(data)))
            data[pos:pos + 16] = entry_raw

        # ── 3. Write expanded metadata table ──
        meta_abs = self.part5_offset + self.table_start
        for i, meta_raw in enumerate(new_meta):
            pos = meta_abs + i * self.METADATA_ENTRY_SIZE
            if pos + self.METADATA_ENTRY_SIZE > len(data):
                data.extend(b'\x00' * (pos + self.METADATA_ENTRY_SIZE - len(data)))
            data[pos:pos + self.METADATA_ENTRY_SIZE] = meta_raw

        if progress_callback:
            progress_callback(50)

        # ── 4. Update Part5 size ──
        new_p5_end = (meta_abs + len(new_meta) * self.METADATA_ENTRY_SIZE) - self.part5_offset
        self.part5_size = new_p5_end
        struct.pack_into('<I', data, 0x150, new_p5_end)

        # ── 5. Patch CMP R0, #0x43 → CMP R0, #0x00 ──
        data[cmp_off:cmp_off + 2] = struct.pack('<H', 0x2800)

        # ── 6. Patch ADDW values ──
        new_addw_vals = [NEW_BLK * (i + 1) for i in range(4)]
        for i, (foff, _old_val) in enumerate(addw_list):
            data[foff:foff + 4] = self._encode_addw(new_addw_vals[i], rd=0, rn=0)

        if progress_callback:
            progress_callback(70)

        # ── 7. Fix integrity ──
        self._fix_integrity()

        if progress_callback:
            progress_callback(90)

        # ── 8. Re-parse so the GUI reflects the new table ──
        self.rock26_count = new_count
        self._parse()

        if progress_callback:
            progress_callback(100)

        return (
            f"Patch applied successfully!\n\n"
            f"• CMP R0,#0x43 → CMP R0,#0x00 at 0x{cmp_off:X}\n"
            f"• ADDW values: {[v for _, v in addw_list]} → {new_addw_vals}\n"
            f"• Resource table: {old_count} → {new_count} entries\n"
            f"• Block size: {OLD_BLK} → {NEW_BLK} per theme\n\n"
            f"Boot/charge animations are now per-theme.\n"
            f"Use the Customizer to replace boot images for each theme."
        )

    def _fix_integrity(self):
        """Fix RKnano firmware integrity: header copy + file size + CRC."""
        data = self.img_data
        if data[0x1F8:0x200] != b'RKnanoFW':
            return

        fw_end = struct.unpack_from('<I', data, 0x1F4)[0]
        ir_off = struct.unpack_from('<I', data, 0x14C)[0]
        ir_sz = struct.unpack_from('<I', data, 0x150)[0]
        p5_end = ir_off + ir_sz

        if p5_end > fw_end:
            fw_end = ((p5_end + 0xFFFF) // 0x10000) * 0x10000
            struct.pack_into('<I', data, 0x1F4, fw_end)

        ALIGN = 0x100000
        fw_size = ((fw_end + 16384 + ALIGN) // ALIGN) * ALIGN
        needed = fw_size + 4

        if len(data) < needed:
            data.extend(b'\x00' * (needed - len(data)))
        elif len(data) > needed:
            del data[needed:]

        data[fw_end:fw_end + 0x200] = data[0:0x200]

        CRC_T = [
            0x00000000,0x04C10DB7,0x09821B6E,0x0D4316D9,
            0x130436DC,0x17C53B6B,0x1A862DB2,0x1E472005,
            0x26086DB8,0x22C9600F,0x2F8A76D6,0x2B4B7B61,
            0x350C5B64,0x31CD56D3,0x3C8E400A,0x384F4DBD,
            0x4C10DB70,0x48D1D6C7,0x4592C01E,0x4153CDA9,
            0x5F14EDAC,0x5BD5E01B,0x5696F6C2,0x5257FB75,
            0x6A18B6C8,0x6ED9BB7F,0x639AADA6,0x675BA011,
            0x791C8014,0x7DDD8DA3,0x709E9B7A,0x745F96CD,
            0x9821B6E0,0x9CE0BB57,0x91A3AD8E,0x9562A039,
            0x8B25803C,0x8FE48D8B,0x82A79B52,0x866696E5,
            0xBE29DB58,0xBAE8D6EF,0xB7ABC036,0xB36ACD81,
            0xAD2DED84,0xA9ECE033,0xA4AFF6EA,0xA06EFB5D,
            0xD4316D90,0xD0F06027,0xDDB376FE,0xD9727B49,
            0xC7355B4C,0xC3F456FB,0xCEB74022,0xCA764D95,
            0xF2390028,0xF6F80D9F,0xFBBB1B46,0xFF7A16F1,
            0xE13D36F4,0xE5FC3B43,0xE8BF2D9A,0xEC7E202D,
            0x34826077,0x30436DC0,0x3D007B19,0x39C176AE,
            0x278656AB,0x23475B1C,0x2E044DC5,0x2AC54072,
            0x128A0DCF,0x164B0078,0x1B0816A1,0x1FC91B16,
            0x018E3B13,0x054F36A4,0x080C207D,0x0CCD2DCA,
            0x7892BB07,0x7C53B6B0,0x7110A069,0x75D1ADDE,
            0x6B968DDB,0x6F57806C,0x621496B5,0x66D59B02,
            0x5E9AD6BF,0x5A5BDB08,0x5718CDD1,0x53D9C066,
            0x4D9EE063,0x495FEDD4,0x441CFB0D,0x40DDF6BA,
            0xACA3D697,0xA862DB20,0xA521CDF9,0xA1E0C04E,
            0xBFA7E04B,0xBB66EDFC,0xB625FB25,0xB2E4F692,
            0x8AABBB2F,0x8E6AB698,0x8329A041,0x87E8ADF6,
            0x99AF8DF3,0x9D6E8044,0x902D969D,0x94EC9B2A,
            0xE0B30DE7,0xE4720050,0xE9311689,0xEDF01B3E,
            0xF3B73B3B,0xF776368C,0xFA352055,0xFEF42DE2,
            0xC6BB605F,0xC27A6DE8,0xCF397B31,0xCBF87686,
            0xD5BF5683,0xD17E5B34,0xDC3D4DED,0xD8FC405A,
            0x6904C0EE,0x6DC5CD59,0x6086DB80,0x6447D637,
            0x7A00F632,0x7EC1FB85,0x7382ED5C,0x7743E0EB,
            0x4F0CAD56,0x4BCDA0E1,0x468EB638,0x424FBB8F,
            0x5C089B8A,0x58C9963D,0x558A80E4,0x514B8D53,
            0x25141B9E,0x21D51629,0x2C9600F0,0x28570D47,
            0x36102D42,0x32D120F5,0x3F92362C,0x3B533B9B,
            0x031C7626,0x07DD7B91,0x0A9E6D48,0x0E5F60FF,
            0x101840FA,0x14D94D4D,0x199A5B94,0x1D5B5623,
            0xF125760E,0xF5E47BB9,0xF8A76D60,0xFC6660D7,
            0xE22140D2,0xE6E04D65,0xEBA35BBC,0xEF62560B,
            0xD72D1BB6,0xD3EC1601,0xDEAF00D8,0xDA6E0D6F,
            0xC4292D6A,0xC0E820DD,0xCDAB3604,0xC96A3BB3,
            0xBD35AD7E,0xB9F4A0C9,0xB4B7B610,0xB076BBA7,
            0xAE319BA2,0xAAF09615,0xA7B380CC,0xA3728D7B,
            0x9B3DC0C6,0x9FFCCD71,0x92BFDBA8,0x967ED61F,
            0x8839F61A,0x8CF8FBAD,0x81BBED74,0x857AE0C3,
            0x5D86A099,0x5947AD2E,0x5404BBF7,0x50C5B640,
            0x4E829645,0x4A439BF2,0x47008D2B,0x43C1809C,
            0x7B8ECD21,0x7F4FC096,0x720CD64F,0x76CDDBF8,
            0x688AFBFD,0x6C4BF64A,0x6108E093,0x65C9ED24,
            0x11967BE9,0x1557765E,0x18146087,0x1CD56D30,
            0x02924D35,0x06534082,0x0B10565B,0x0FD15BEC,
            0x379E1651,0x335F1BE6,0x3E1C0D3F,0x3ADD0088,
            0x249A208D,0x205B2D3A,0x2D183BE3,0x29D93654,
            0xC5A71679,0xC1661BCE,0xCC250D17,0xC8E400A0,
            0xD6A320A5,0xD2622D12,0xDF213BCB,0xDBE0367C,
            0xE3AF7BC1,0xE76E7676,0xEA2D60AF,0xEEEC6D18,
            0xF0AB4D1D,0xF46A40AA,0xF9295673,0xFDE85BC4,
            0x89B7CD09,0x8D76C0BE,0x8035D667,0x84F4DBD0,
            0x9AB3FBD5,0x9E72F662,0x9331E0BB,0x97F0ED0C,
            0xAFBFA0B1,0xAB7EAD06,0xA63DBBDF,0xA2FCB668,
            0xBCBB966D,0xB87A9BDA,0xB5398D03,0xB1F880B4,
        ]
        acc = 0
        for b in bytes(data[:fw_size]):
            acc = ((acc << 8) & 0xFFFFFFFF) ^ CRC_T[(acc >> 24) ^ b]
        struct.pack_into('<I', data, len(data) - 4, acc)


def swap_bytes_16bit(data):
    arr = bytearray(data)
    if len(arr) % 2 != 0:
        arr = arr[:-1]
    arr[0::2], arr[1::2] = arr[1::2], arr[0::2]
    return bytes(arr)


def rgb565_to_qimage(raw, w, h):
    """Fast RGB565 to QImage conversion using array operations."""
    n = w * h
    raw_bytes = raw[:n * 2]
    if len(raw_bytes) < n * 2:
        raw_bytes = raw_bytes + b'\x00' * (n * 2 - len(raw_bytes))

    # Byte-swap and unpack as 16-bit LE words
    swapped = bytearray(raw_bytes)
    swapped[0::2], swapped[1::2] = swapped[1::2], swapped[0::2]
    pixels = array.array('H')
    pixels.frombytes(bytes(swapped))

    # Build RGBA buffer
    rgba = bytearray(n * 4)
    for i in range(n):
        p = pixels[i]
        rgba[i * 4]     = ((p >> 11) & 0x1F) * 255 // 31  # R
        rgba[i * 4 + 1] = ((p >> 5) & 0x3F) * 255 // 63   # G
        rgba[i * 4 + 2] = (p & 0x1F) * 255 // 31          # B
        rgba[i * 4 + 3] = 255                              # A

    img = QImage(bytes(rgba), w, h, w * 4, QImage.Format_RGBA8888)
    return img.copy()  # Detach from buffer


def qimage_to_rgb565(qimg, w, h):
    """Fast QImage to RGB565 conversion."""
    qimg = qimg.convertToFormat(QImage.Format_RGBA8888)
    ptr = qimg.bits()
    ptr.setsize(w * h * 4)
    rgba = bytes(ptr)

    data = bytearray(w * h * 2)
    for i in range(w * h):
        r = rgba[i * 4]
        g = rgba[i * 4 + 1]
        b = rgba[i * 4 + 2]
        pixel = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        # Big-endian storage (byte-swapped format in firmware)
        data[i * 2] = (pixel >> 8) & 0xFF
        data[i * 2 + 1] = pixel & 0xFF
    return bytes(data)


# ============================================================================
# Device Screen Widget - renders like a real Echo Mini
# ============================================================================

class DeviceScreen(QLabel):
    """Simulated 320x170 Echo Mini screen with device frame."""

    SCREEN_W = 320
    SCREEN_H = 170
    SCALE = 2

    def __init__(self, parent=None):
        super().__init__(parent)
        self.display_w = self.SCREEN_W * self.SCALE
        self.display_h = self.SCREEN_H * self.SCALE
        self.setFixedSize(self.display_w + 40, self.display_h + 40)
        self.setAlignment(Qt.AlignCenter)
        self.current_image = None
        self._draw_off_screen()

    def _draw_off_screen(self):
        pm = QPixmap(self.display_w + 40, self.display_h + 40)
        pm.fill(QColor(30, 30, 30))
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.Antialiasing)
        # Device bezel
        painter.setBrush(QColor(50, 50, 55))
        painter.setPen(QPen(QColor(80, 80, 85), 2))
        painter.drawRoundedRect(5, 5, self.display_w + 30, self.display_h + 30, 12, 12)
        # Screen area (black)
        painter.setBrush(QColor(0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.drawRect(20, 20, self.display_w, self.display_h)
        painter.end()
        self.setPixmap(pm)

    def set_image(self, qimage):
        self.current_image = qimage
        self._redraw()

    def _redraw(self):
        pm = QPixmap(self.display_w + 40, self.display_h + 40)
        pm.fill(QColor(30, 30, 30))
        painter = QPainter(pm)
        painter.setRenderHint(QPainter.Antialiasing)
        # Bezel
        painter.setBrush(QColor(50, 50, 55))
        painter.setPen(QPen(QColor(80, 80, 85), 2))
        painter.drawRoundedRect(5, 5, self.display_w + 30, self.display_h + 30, 12, 12)
        # Screen
        painter.setPen(Qt.NoPen)
        if self.current_image:
            scaled = QPixmap.fromImage(self.current_image).scaled(
                self.display_w, self.display_h,
                Qt.IgnoreAspectRatio, Qt.SmoothTransformation
            )
            painter.drawPixmap(20, 20, scaled)
        else:
            painter.setBrush(QColor(0, 0, 0))
            painter.drawRect(20, 20, self.display_w, self.display_h)
        painter.end()
        self.setPixmap(pm)

    def clear_screen(self):
        self.current_image = None
        self._draw_off_screen()


# ============================================================================
# Animation Player for boot/shutdown sequences
# ============================================================================

class AnimationPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.frames = []
        self.current_frame = 0
        self.playing = False
        self.timer = QTimer()
        self.timer.timeout.connect(self._next_frame)

        layout = QVBoxLayout(self)
        self.screen = DeviceScreen()
        layout.addWidget(self.screen, alignment=Qt.AlignCenter)

        controls = QHBoxLayout()
        self.btn_prev = QPushButton("⏮ Previous")
        self.btn_play = QPushButton("▶ Play")
        self.btn_next = QPushButton("Next ⏭")
        self.btn_replace = QPushButton("🖼 Replace Frame")
        self.slider = QSlider(Qt.Horizontal)
        self.lbl_frame = QLabel("Frame: 0/0")

        self.btn_prev.clicked.connect(self._prev)
        self.btn_play.clicked.connect(self._toggle_play)
        self.btn_next.clicked.connect(self._next)
        self.btn_replace.clicked.connect(self._replace_frame)
        self.slider.valueChanged.connect(self._slider_changed)

        controls.addWidget(self.btn_prev)
        controls.addWidget(self.btn_play)
        controls.addWidget(self.btn_next)
        layout.addLayout(controls)
        layout.addWidget(self.slider)

        info_row = QHBoxLayout()
        info_row.addWidget(self.lbl_frame)
        info_row.addStretch()
        info_row.addWidget(self.btn_replace)
        self.btn_import_mp4 = QPushButton("🎬 Import MP4")
        self.btn_import_mp4.clicked.connect(self._import_mp4)
        info_row.addWidget(self.btn_import_mp4)
        layout.addLayout(info_row)

        # Speed control
        speed_row = QHBoxLayout()
        speed_row.addWidget(QLabel("Speed (ms):"))
        self.speed_slider = QSlider(Qt.Horizontal)
        self.speed_slider.setRange(30, 500)
        self.speed_slider.setValue(80)
        self.speed_label = QLabel("80ms")
        self.speed_slider.valueChanged.connect(lambda v: self.speed_label.setText(f"{v}ms"))
        speed_row.addWidget(self.speed_slider)
        speed_row.addWidget(self.speed_label)
        layout.addLayout(speed_row)

    def set_frames(self, frame_list):
        """frame_list: list of (resource_dict, QImage)"""
        self.frames = frame_list
        self.current_frame = 0
        self.slider.setRange(0, max(0, len(self.frames) - 1))
        self._show_frame()

    def _show_frame(self):
        if self.frames and 0 <= self.current_frame < len(self.frames):
            res, img = self.frames[self.current_frame]
            self.screen.set_image(img)
            self.lbl_frame.setText(
                f"Frame: {self.current_frame + 1}/{len(self.frames)} - {res['name']}"
            )
            self.slider.blockSignals(True)
            self.slider.setValue(self.current_frame)
            self.slider.blockSignals(False)

    def _next_frame(self):
        if self.frames:
            self.current_frame = (self.current_frame + 1) % len(self.frames)
            self._show_frame()

    def _prev(self):
        if self.frames:
            self.current_frame = max(0, self.current_frame - 1)
            self._show_frame()

    def _next(self):
        if self.frames:
            self.current_frame = min(len(self.frames) - 1, self.current_frame + 1)
            self._show_frame()

    def _toggle_play(self):
        if self.playing:
            self.timer.stop()
            self.playing = False
            self.btn_play.setText("▶ Play")
        else:
            self.timer.start(self.speed_slider.value())
            self.playing = True
            self.btn_play.setText("⏸ Pausar")

    def _slider_changed(self, val):
        self.current_frame = val
        self._show_frame()

    def _replace_frame(self):
        if not self.frames:
            return
        self.parent_window = self.window()
        if hasattr(self.parent_window, 'replace_resource'):
            res, _ = self.frames[self.current_frame]
            self.parent_window.replace_resource(res, callback=self._on_replaced)

    def _on_replaced(self, res, new_img):
        self.frames[self.current_frame] = (res, new_img)
        self._show_frame()

    def _import_mp4(self):
        """Import a video file and distribute its frames across all animation slots."""
        if not self.frames:
            QMessageBox.warning(self, "No Frames",
                                "No animation frames loaded to replace.")
            return
        try:
            import cv2
        except ImportError:
            QMessageBox.critical(self, "Error",
                                 "opencv-python-headless is not installed.\n"
                                 "Run: pip install opencv-python-headless")
            return

        path, _ = QFileDialog.getOpenFileName(
            self.window(), "Import Video",
            str(get_app_dir()),
            "Video (*.mp4 *.avi *.mov *.mkv *.webm *.gif);;All (*.*)"
        )
        if not path:
            return

        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            QMessageBox.critical(self, "Error", f"Could not open video:\n{path}")
            return

        total_video_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_video_frames <= 0:
            QMessageBox.warning(self, "Error", "Video has no frames.")
            cap.release()
            return

        num_slots = len(self.frames)

        # Show info dialog before importing
        dlg = QDialog(self.window())
        dlg.setWindowTitle("Import Video → Animation Frames")
        dlg.setMinimumWidth(380)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"📹 Video: {Path(path).name}"))
        lay.addWidget(QLabel(f"   Video frames: {total_video_frames}"))
        lay.addWidget(QLabel(f"   Animation slots: {num_slots}"))
        if total_video_frames > num_slots:
            lay.addWidget(QLabel(f"   → Will sample {num_slots} evenly-spaced frames"))
        elif total_video_frames < num_slots:
            lay.addWidget(QLabel(f"   → Will repeat frames to fill {num_slots} slots"))
        else:
            lay.addWidget(QLabel(f"   → Exact 1:1 match"))

        # Target dimensions from first frame's resource
        res0 = self.frames[0][0]
        tw, th = res0['width'], res0['height']
        lay.addWidget(QLabel(f"   Target resolution: {tw}×{th}"))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            cap.release()
            return

        # Calculate which video frames to sample
        if total_video_frames >= num_slots:
            indices = [int(i * total_video_frames / num_slots) for i in range(num_slots)]
        else:
            indices = [int(i * total_video_frames / num_slots) for i in range(num_slots)]

        parent_win = self.window()
        replaced = 0

        for slot_idx, vid_frame_idx in enumerate(indices):
            cap.set(cv2.CAP_PROP_POS_FRAMES, vid_frame_idx)
            ret, frame_bgr = cap.read()
            if not ret:
                continue

            # Convert BGR → RGB → QImage
            frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
            h, w, ch = frame_rgb.shape
            qimg = QImage(frame_rgb.data, w, h, w * ch, QImage.Format_RGB888).copy()

            res, _ = self.frames[slot_idx]
            rw, rh = res['width'], res['height']
            if qimg.width() != rw or qimg.height() != rh:
                qimg = qimg.scaled(rw, rh, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
            qimg = qimg.convertToFormat(QImage.Format_RGBA8888)

            if hasattr(parent_win, 'firmware') and parent_win.firmware:
                parent_win.firmware.replace_image(res, qimg)
                # Update internal caches
                self.frames[slot_idx] = (res, qimg)
                if hasattr(parent_win, 'resources_by_name'):
                    parent_win.resources_by_name[res['name']] = (res, qimg)
                if hasattr(parent_win, 'all_res_images'):
                    for i, (r, _) in enumerate(parent_win.all_res_images):
                        if r['name'] == res['name']:
                            parent_win.all_res_images[i] = (res, qimg)
                            break
                replaced += 1

        cap.release()
        self._show_frame()
        if hasattr(parent_win, 'statusBar'):
            parent_win.statusBar().showMessage(
                f"✓ {replaced}/{num_slots} frames importados desde {Path(path).name}")


# ============================================================================
# Gallery Panel for static screens (main menu pages, etc.)
# ============================================================================

class GalleryPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.items = []  # list of (resource_dict, QImage)

        layout = QVBoxLayout(self)
        self.screen = DeviceScreen()
        layout.addWidget(self.screen, alignment=Qt.AlignCenter)

        # Navigation
        nav = QHBoxLayout()
        self.btn_prev = QPushButton("◀ Previous")
        self.lbl_info = QLabel("No images")
        self.btn_next = QPushButton("Next ▶")
        self.btn_replace = QPushButton("🖼 Replace Image")

        self.btn_prev.clicked.connect(self._prev)
        self.btn_next.clicked.connect(self._next)
        self.btn_replace.clicked.connect(self._replace)

        nav.addWidget(self.btn_prev)
        nav.addWidget(self.lbl_info, stretch=1)
        nav.addWidget(self.btn_next)
        layout.addLayout(nav)
        layout.addWidget(self.btn_replace)

        # Thumbnails
        self.thumb_list = QListWidget()
        self.thumb_list.setFlow(QListWidget.LeftToRight)
        self.thumb_list.setFixedHeight(90)
        self.thumb_list.setIconSize(QSize(120, 64))
        self.thumb_list.currentRowChanged.connect(self._thumb_selected)
        layout.addWidget(self.thumb_list)

        self.current_idx = 0

    def set_items(self, items):
        self.items = items
        self.thumb_list.clear()
        for res, img in items:
            pm = QPixmap.fromImage(img).scaled(120, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            item = QListWidgetItem(QIcon(pm), res['name'].split('_')[0])
            self.thumb_list.addItem(item)
        self.current_idx = 0
        self._show_current()

    def _show_current(self):
        if self.items and 0 <= self.current_idx < len(self.items):
            res, img = self.items[self.current_idx]
            self.screen.set_image(img)
            self.lbl_info.setText(
                f"{self.current_idx + 1}/{len(self.items)} - {res['name']} ({res['width']}x{res['height']})"
            )
            self.thumb_list.blockSignals(True)
            self.thumb_list.setCurrentRow(self.current_idx)
            self.thumb_list.blockSignals(False)
        elif not self.items:
            self.lbl_info.setText("No images")
            self.screen.clear_screen()

    def _prev(self):
        if self.items:
            self.current_idx = max(0, self.current_idx - 1)
            self._show_current()

    def _next(self):
        if self.items:
            self.current_idx = min(len(self.items) - 1, self.current_idx + 1)
            self._show_current()

    def _thumb_selected(self, row):
        if 0 <= row < len(self.items):
            self.current_idx = row
            self._show_current()

    def _replace(self):
        if not self.items:
            return
        win = self.window()
        if hasattr(win, 'replace_resource'):
            res, _ = self.items[self.current_idx]
            win.replace_resource(res, callback=self._on_replaced)

    def _on_replaced(self, res, new_img):
        self.items[self.current_idx] = (res, new_img)
        self._show_current()
        # Update thumbnail
        pm = QPixmap.fromImage(new_img).scaled(120, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.thumb_list.item(self.current_idx).setIcon(QIcon(pm))


# ============================================================================
# Resource Browser - browse ALL resources with categories
# ============================================================================

class ResourceBrowser(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_resources = []
        self.filtered = []

        layout = QVBoxLayout(self)

        # Filter
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.combo_filter = QComboBox()
        self.combo_filter.addItems([
            "All", "POWERON", "POWEROFF", "CHARGELEVEL",
            "MAINMENU", "MUSIC", "BROWSER", "FM", "RECORDER",
            "USB", "BT", "SETTING"
        ])
        self.combo_filter.currentTextChanged.connect(self._apply_filter)
        filter_row.addWidget(self.combo_filter, stretch=1)
        layout.addLayout(filter_row)

        # Split: list + preview
        splitter = QSplitter(Qt.Horizontal)

        self.list_widget = QListWidget()
        self.list_widget.currentRowChanged.connect(self._on_select)
        splitter.addWidget(self.list_widget)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.screen = DeviceScreen()
        right_layout.addWidget(self.screen, alignment=Qt.AlignCenter)

        self.lbl_detail = QLabel("Select a resource")
        self.lbl_detail.setWordWrap(True)
        right_layout.addWidget(self.lbl_detail)

        self.btn_replace = QPushButton("🖼 Replace")
        self.btn_replace.clicked.connect(self._replace)
        right_layout.addWidget(self.btn_replace)

        splitter.addWidget(right)
        splitter.setSizes([300, 500])
        layout.addWidget(splitter)

    def set_resources(self, resources):
        self.all_resources = resources
        self._apply_filter(self.combo_filter.currentText())

    def _apply_filter(self, text):
        if text == "All":
            self.filtered = self.all_resources
        else:
            prefix = text.upper()
            self.filtered = [r for r in self.all_resources if r[0]['name'].upper().startswith(prefix)]

        self.list_widget.clear()
        for res, img in self.filtered:
            self.list_widget.addItem(f"{res['name']} ({res['width']}x{res['height']})")

    def _on_select(self, row):
        if 0 <= row < len(self.filtered):
            res, img = self.filtered[row]
            self.screen.set_image(img)
            self.lbl_detail.setText(
                f"Name: {res['name']}\n"
                f"Dimensions: {res['width']}x{res['height']}\n"
                f"Offset: 0x{res['offset']:08X}\n"
                f"Raw size: {res['raw_size']:,} bytes"
            )

    def _replace(self):
        row = self.list_widget.currentRow()
        if row < 0 or row >= len(self.filtered):
            return
        win = self.window()
        if hasattr(win, 'replace_resource'):
            res, _ = self.filtered[row]
            win.replace_resource(res, callback=self._on_replaced)

    def _on_replaced(self, res, new_img):
        row = self.list_widget.currentRow()
        if 0 <= row < len(self.filtered):
            self.filtered[row] = (res, new_img)
            self.screen.set_image(new_img)


# ============================================================================
# Theme prefix mapping
# ============================================================================

# Maps theme key → (display name, resource prefix pattern)
# For theme A the base name has NO prefix; B prepends "B"; C-E prepend "X_"
THEMES = {
    "A": ("Elegant White",   ""),
    "B": ("Midnight Black",  "B"),
    "C": ("Cherry Blossom",  "C_"),
    "D": ("Retro Gold",      "D_"),
    "E": ("Sky Blue",        "E_"),
    "F": ("Theme F",         "F_"),
    "G": ("Theme G",         "G_"),
    "H": ("Theme H",         "H_"),
    "I": ("Theme I",         "I_"),
    "J": ("Theme J",         "J_"),
    "K": ("Theme K",         "K_"),
    "L": ("Theme L",         "L_"),
    "M": ("Theme M",         "M_"),
    "N": ("Theme N",         "N_"),
    "O": ("Theme O",         "O_"),
    "P": ("Theme P",         "P_"),
    "Q": ("Theme Q",         "Q_"),
    "R": ("Theme R",         "R_"),
    "S": ("Theme S",         "S_"),
    "T": ("Theme T",         "T_"),
}

# Base resource categories that are duplicated across themes
THEMED_CATEGORIES = ("MAINMENUPAGE", "MUSIC_", "BROWSER_", "USB_", "FM_", "RECORDER_")


def resource_matches_theme(name, prefix):
    """Return True if *name* belongs to the given theme prefix."""
    if prefix == "":
        # Theme A = no prefix.  Must NOT start with any other theme prefix.
        for _, (_, other_pfx) in THEMES.items():
            if other_pfx and name.startswith(other_pfx):
                return False
        return True
    return name.startswith(prefix)


def strip_theme_prefix(name, prefix):
    """Remove the theme prefix so we get the base resource name."""
    if prefix and name.startswith(prefix):
        return name[len(prefix):]
    return name


# ============================================================================
# Main Window
# ============================================================================

class EchoMiniCustomizer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Echo Mini Customizer - Firmware Theme Editor")
        self.setMinimumSize(950, 750)
        self.firmware = None
        self.resources_by_name = {}
        self.all_res_images = []
        self.current_theme_key = "A"
        self.active_themes = {}  # populated after firmware load

        self._build_ui()
        self._auto_load()

    def _build_ui(self):
        # Toolbar
        toolbar = QToolBar()
        toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(toolbar)

        act_open = QAction("📂 Open Firmware", self)
        act_open.triggered.connect(self._open_firmware)
        toolbar.addAction(act_open)

        act_save = QAction("💾 Save Firmware", self)
        act_save.triggered.connect(self._save_firmware)
        toolbar.addAction(act_save)

        act_saveas = QAction("💾 Save As...", self)
        act_saveas.triggered.connect(self._save_as)
        toolbar.addAction(act_saveas)

        act_export = QAction("📤 Export Images", self)
        act_export.triggered.connect(self._export_images)
        toolbar.addAction(act_export)

        act_import = QAction("📥 Import Theme", self)
        act_import.triggered.connect(self._import_theme)
        toolbar.addAction(act_import)

        act_patch = QAction("🔧 Patch Firmware", self)
        act_patch.triggered.connect(self._patch_firmware)
        toolbar.addAction(act_patch)

        toolbar.addSeparator()

        # Theme selector
        toolbar.addWidget(QLabel(" 🎨 Theme: "))
        self.theme_combo = QComboBox()
        self.theme_combo.setMinimumWidth(200)
        # Populated dynamically after firmware load via _refresh_theme_combo
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        toolbar.addWidget(self.theme_combo)

        act_rename = QAction("✏️ Rename Theme", self)
        act_rename.triggered.connect(self._rename_theme)
        toolbar.addAction(act_rename)

        toolbar.addSeparator()
        self.lbl_status = QLabel(" No firmware loaded")
        toolbar.addWidget(self.lbl_status)

        # Tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.boot_panel = AnimationPanel()
        self.shutdown_panel = GalleryPanel()
        self.charge_panel = AnimationPanel()
        self.menu_panel = GalleryPanel()
        self.browser_panel = GalleryPanel()

        # Player tab: sub-tabs for Music UI + DAC Show animation
        self.music_container = QTabWidget()
        self.music_panel = GalleryPanel()
        self.dacshow_panel = AnimationPanel()
        self.music_container.addTab(self.music_panel, "🎵 Interface")
        self.music_container.addTab(self.dacshow_panel, "📊 DAC Show")

        # DAC tab: sub-tabs for USB Player animation + backgrounds
        self.dac_container = QTabWidget()
        self.usb_player_panel = AnimationPanel()
        self.dac_static_panel = GalleryPanel()
        self.dac_container.addTab(self.usb_player_panel, "▶ USB Player")
        self.dac_container.addTab(self.dac_static_panel, "🖼 DAC Backgrounds")

        self.usb_panel = GalleryPanel()
        self.resource_browser = ResourceBrowser()

        self.tabs.addTab(self.boot_panel, "🔌 Boot")
        self.tabs.addTab(self.shutdown_panel, "⏻ Shutdown")
        self.tabs.addTab(self.charge_panel, "🔋 Charging")
        self.tabs.addTab(self.menu_panel, "📱 Main Menu")
        self.tabs.addTab(self.music_container, "🎵 Player")
        self.tabs.addTab(self.browser_panel, "📁 Folders")
        self.tabs.addTab(self.dac_container, "🎧 DAC")
        self.tabs.addTab(self.usb_panel, "🔌 USB / Data")
        self.tabs.addTab(self.resource_browser, "🔍 All Resources")

        # Status bar
        self.statusBar().showMessage("Ready. Open a firmware .IMG file.")

    def _auto_load(self):
        """Automatically load the firmware from the known path."""
        base = get_app_dir()
        img_path = base / "Retro_cassette_player_theme" / "HIFIEC20.IMG"
        if not img_path.exists():
            # Try other theme folders
            for d in base.iterdir():
                if d.is_dir():
                    for f in d.glob("*.IMG"):
                        img_path = f
                        break
                    if img_path.exists():
                        break
        if img_path.exists():
            self._load_firmware(str(img_path))

    def _open_firmware(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Firmware IMG",
            str(get_app_dir()),
            "Firmware (*.IMG *.img *.bin);;All (*.*)"
        )
        if path:
            self._load_firmware(path)

    def _load_firmware(self, path):
        try:
            self.statusBar().showMessage(f"Loading {Path(path).name}...")
            QApplication.processEvents()
            self.firmware = FirmwareParser(path)

            # Auto-patch if not already patched
            try:
                info = self.firmware.detect_patch_info()
                if not info['is_patched']:
                    self.statusBar().showMessage("Patching firmware for per-theme boots...")
                    QApplication.processEvents()
                    self.firmware.patch_for_themed_boots()
            except Exception:
                pass  # Skip patching if detection fails

            resource_list = self.firmware.get_resource_list()
            self.lbl_status.setText(f" {Path(path).name} — {len(resource_list)} resources")

            # Extract all images with progress
            self.all_res_images = []
            self.resources_by_name = {}
            total = len(resource_list)
            for idx, res in enumerate(resource_list):
                if idx % 50 == 0:
                    self.statusBar().showMessage(
                        f"Extracting resources... {idx}/{total}"
                    )
                    QApplication.processEvents()
                img = self.firmware.extract_image(res)
                self.all_res_images.append((res, img))
                self.resources_by_name[res['name']] = (res, img)

            self._detect_active_themes()
            # Sync firmware theme names → THEMES dict display names
            if self.firmware.theme_names:
                theme_keys = list(THEMES.keys())
                for i, name in enumerate(self.firmware.theme_names):
                    if i < len(theme_keys):
                        key = theme_keys[i]
                        THEMES[key] = (name, THEMES[key][1])
                        if key in self.active_themes:
                            self.active_themes[key] = THEMES[key]
            self._refresh_theme_combo()
            self._populate_panels()
            self.statusBar().showMessage(
                f"✓ Firmware loaded: {len(resource_list)} resources extracted from {Path(path).name}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load firmware:\n{e}")
            self.statusBar().showMessage("Error loading firmware")

    def _detect_active_themes(self):
        """Scan loaded resources to find which themes actually have data."""
        self.active_themes = {}
        counts = {}
        for res, _ in self.all_res_images:
            name = res['name']
            # Check themed boot resources (T_B_, T_C_, etc.)
            if name.startswith('T_') and len(name) > 3 and name[2] in 'ABCDEFGHIJKLMNOPQRST' and name[3] == '_':
                tkey = name[2]
                if tkey in THEMES:
                    counts[tkey] = counts.get(tkey, 0) + 1
                    continue
            if res['index'] < 67:
                continue
            for key, (tname, prefix) in THEMES.items():
                if key == "A":
                    continue
                if prefix and name.startswith(prefix):
                    counts[key] = counts.get(key, 0) + 1
                    break
            else:
                counts["A"] = counts.get("A", 0) + 1

        for key, count in counts.items():
            if count > 0:
                self.active_themes[key] = THEMES[key]

    def _refresh_theme_combo(self):
        """Rebuild the theme ComboBox to show only active themes."""
        self.theme_combo.blockSignals(True)
        self.theme_combo.clear()
        # Map theme key (A-T) → index 0-19
        theme_keys = list(THEMES.keys())
        for key in theme_keys:
            if key not in self.active_themes:
                continue
            tidx = theme_keys.index(key)
            # Use firmware name if available, else THEMES dict name
            if self.firmware and tidx < len(self.firmware.theme_names):
                fw_name = self.firmware.theme_names[tidx]
            else:
                fw_name = None
            dict_name, prefix = self.active_themes[key]
            display_name = fw_name if fw_name else dict_name
            label = f"{key} – {display_name}" + (f"  (prefix: {prefix})" if prefix else "  (no prefix)")
            self.theme_combo.addItem(label, key)
        self.theme_combo.blockSignals(False)
        # Reset to first theme
        if self.theme_combo.count() > 0:
            self.theme_combo.setCurrentIndex(0)
            self.current_theme_key = self.theme_combo.itemData(0)

    def _populate_panels(self):
        # All resources browser (unfiltered)
        self.resource_browser.set_resources(self.all_res_images)

        # Populate ALL panels (including boot/shutdown/charge) per theme
        self._apply_theme()

    def _on_theme_changed(self, index):
        key = self.theme_combo.itemData(index)
        if key and key != self.current_theme_key:
            self.current_theme_key = key
            if self.all_res_images:
                self._apply_theme()
                theme_name = THEMES[key][0]
                self.statusBar().showMessage(f"Theme changed to: {theme_name}")

    def _rename_theme(self):
        """Rename the currently selected theme in the firmware StrTbl."""
        if not self.firmware or not self.firmware._strtbl_info:
            QMessageBox.warning(self, "No Firmware",
                                "First load a firmware .IMG with String Table")
            return
        key = self.current_theme_key
        theme_keys = list(THEMES.keys())
        tidx = theme_keys.index(key)
        if tidx >= len(self.firmware.theme_names):
            QMessageBox.warning(self, "No Name",
                                f"Theme {key} has no name entry in String Table.\n"
                                f"Only {len(self.firmware.theme_names)} themes have editable names.")
            return
        current_name = self.firmware.theme_names[tidx]
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Rename Theme {key}")
        dlg.setMinimumWidth(350)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"Theme: {key} (index {tidx})"))
        lay.addWidget(QLabel(f"Current name: {current_name}"))
        lay.addWidget(QLabel("New name (max 99 characters):"))
        name_edit = QLineEdit()
        name_edit.setText(current_name)
        name_edit.setMaxLength(99)
        name_edit.selectAll()
        lay.addWidget(name_edit)
        lay.addWidget(QLabel("⚠ Will be changed across all 21 firmware languages"))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)
        if dlg.exec_() != QDialog.Accepted:
            return
        new_name = name_edit.text().strip()
        if not new_name:
            return
        if self.firmware.set_theme_name(tidx, new_name):
            # Also update THEMES dict display name
            THEMES[key] = (new_name, THEMES[key][1])
            if key in self.active_themes:
                self.active_themes[key] = THEMES[key]
            self._refresh_theme_combo()
            # Restore selection to the renamed theme
            for i in range(self.theme_combo.count()):
                if self.theme_combo.itemData(i) == key:
                    self.theme_combo.setCurrentIndex(i)
                    break
            self.statusBar().showMessage(
                f"✓ Theme {key} renamed to \"{new_name}\" across 21 languages")
        else:
            QMessageBox.warning(self, "Error", "Could not rename theme")

    def _apply_theme(self):
        """Re-populate ALL theme-dependent panels (including boot/shutdown/charge)."""
        prefix = THEMES[self.current_theme_key][1]
        key = self.current_theme_key

        # Themed boot prefix: Option 1 names per-theme boots as T_{key}_
        tboot = f"T_{key}_" if key != "A" else ""

        # --- Boot animation (Z_POWERON) ---
        boot_frames = []
        for name, (res, img) in self.resources_by_name.items():
            if tboot:
                # Look for themed boot: T_B_Z_POWERON0, etc.
                if name.startswith(tboot + 'Z_POWERON') and '(' in name:
                    tail = name[len(tboot + 'Z_POWERON'):]
                    try:
                        num = int(tail.split('_')[0])
                        boot_frames.append((num, res, img))
                    except ValueError:
                        pass
            else:
                # Theme A or shared: Z_POWERON0, etc. (not T_ prefixed)
                if name.startswith('Z_POWERON') and not name.startswith('T_') and '(' in name:
                    try:
                        num = int(name.split('Z_POWERON')[1].split('_')[0])
                        boot_frames.append((num, res, img))
                    except ValueError:
                        pass
        # Fallback to shared if no themed boots found
        if not boot_frames and tboot:
            for name, (res, img) in self.resources_by_name.items():
                if name.startswith('Z_POWERON') and not name.startswith('T_') and '(' in name:
                    try:
                        num = int(name.split('Z_POWERON')[1].split('_')[0])
                        boot_frames.append((num, res, img))
                    except ValueError:
                        pass
        boot_frames.sort(key=lambda x: x[0])
        self.boot_panel.set_frames([(r, i) for _, r, i in boot_frames])

        # --- Shutdown (POWEROFF + POWERON0/1) ---
        shutdown = []
        for name, (res, img) in self.resources_by_name.items():
            if tboot:
                if name.startswith(tboot + 'POWEROFF'):
                    shutdown.append((res, img))
            else:
                if name.startswith('POWEROFF') and not name.startswith('T_'):
                    shutdown.append((res, img))
        # Fallback
        if not shutdown and tboot:
            for name, (res, img) in self.resources_by_name.items():
                if name.startswith('POWEROFF') and not name.startswith('T_'):
                    shutdown.append((res, img))
        # Prepend POWERON0/1
        for suffix in ['1', '0']:
            if tboot:
                pname = f"{tboot}POWERON{suffix}_(0,0).BMP"
            else:
                pname = f"POWERON{suffix}_(0,0).BMP"
            if pname in self.resources_by_name:
                shutdown.insert(0, self.resources_by_name[pname])
            elif tboot:
                # Fallback to shared
                fallback = f"POWERON{suffix}_(0,0).BMP"
                if fallback in self.resources_by_name:
                    shutdown.insert(0, self.resources_by_name[fallback])
        self.shutdown_panel.set_items(shutdown)

        # --- Charging (CHARGELEVEL) ---
        charge_frames = []
        for name, (res, img) in self.resources_by_name.items():
            if tboot:
                if name.startswith(tboot + 'CHARGELEVEL') and '(' in name:
                    tail = name[len(tboot + 'CHARGELEVEL'):]
                    try:
                        num = int(tail.split('_')[0])
                        charge_frames.append((num, res, img))
                    except ValueError:
                        pass
            else:
                if name.startswith('CHARGELEVEL') and not name.startswith('T_') and '(' in name:
                    try:
                        num = int(name.split('CHARGELEVEL')[1].split('_')[0])
                        charge_frames.append((num, res, img))
                    except ValueError:
                        pass
        # Fallback
        if not charge_frames and tboot:
            for name, (res, img) in self.resources_by_name.items():
                if name.startswith('CHARGELEVEL') and not name.startswith('T_') and '(' in name:
                    try:
                        num = int(name.split('CHARGELEVEL')[1].split('_')[0])
                        charge_frames.append((num, res, img))
                    except ValueError:
                        pass
        charge_frames.sort(key=lambda x: x[0])
        self.charge_panel.set_frames([(r, i) for _, r, i in charge_frames])

        # --- Main Menu ---
        menu_items = []
        for name, (res, img) in self.resources_by_name.items():
            base = strip_theme_prefix(name, prefix)
            if base.startswith('MAINMENUPAGE') and '(' in base:
                if not resource_matches_theme(name, prefix):
                    continue
                try:
                    num = int(base.split('MAINMENUPAGE')[1].split('_')[0])
                    menu_items.append((num, res, img))
                except ValueError:
                    pass
        menu_items.sort(key=lambda x: x[0])
        self.menu_panel.set_items([(r, i) for _, r, i in menu_items])

        # --- Player (MUSIC) ---
        music_items = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if base.startswith('MUSIC_'):
                music_items.append((res, img))
        self.music_panel.set_items(music_items)

        # DAC Show animation (DACSHOW1-5) — part of Reproductor
        dac_show_frames = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if base.startswith('USB_DACSHOW') and '(' in base:
                tail = base[len('USB_DACSHOW'):]
                try:
                    num = int(tail.split('_')[0])
                    dac_show_frames.append((num, res, img))
                except ValueError:
                    pass
        dac_show_frames.sort(key=lambda x: x[0])
        self.dacshow_panel.set_frames([(r, i) for _, r, i in dac_show_frames])

        # --- Folders (BROWSER) ---
        browser_items = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if base.startswith('BROWSER_'):
                browser_items.append((res, img))
        self.browser_panel.set_items(browser_items)

        # --- DAC ---
        # USB Player animation (USB_PLAYER1-5)
        usb_player_frames = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if base.startswith('USB_PLAYER') and base != 'USB_PLAYER_(0,0).BMP' and '(' in base:
                tail = base[len('USB_PLAYER'):]
                try:
                    num = int(tail.split('_')[0])
                    usb_player_frames.append((num, res, img))
                except ValueError:
                    pass
        usb_player_frames.sort(key=lambda x: x[0])
        self.usb_player_panel.set_frames([(r, i) for _, r, i in usb_player_frames])

        # DAC static backgrounds (USB_DAC_ and USB_PLAYER_ base images)
        dac_static = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if base == 'USB_DAC_(0,0).BMP' or base == 'USB_PLAYER_(0,0).BMP':
                dac_static.append((res, img))
        self.dac_static_panel.set_items(dac_static)

        # --- USB / Data Transfer ---
        usb_items = []
        for name, (res, img) in self.resources_by_name.items():
            if not resource_matches_theme(name, prefix):
                continue
            base = strip_theme_prefix(name, prefix)
            if (base.startswith('USB_DATA')
                    or base.startswith('USB_BACKGROUND')
                    or base.startswith('MEDIAUPDATA')):
                usb_items.append((res, img))
        self.usb_panel.set_items(usb_items)

    def replace_resource(self, res, callback=None):
        """Open file dialog to replace a firmware resource image."""
        path, _ = QFileDialog.getOpenFileName(
            self, f"Replace: {res['name']}",
            str(get_app_dir()),
            "Images (*.png *.jpg *.bmp *.jpeg);;All (*.*)"
        )
        if not path:
            return

        new_img = QImage(path)
        if new_img.isNull():
            QMessageBox.warning(self, "Error", "Could not load image")
            return

        # Scale to exact resource dimensions
        if new_img.width() != res['width'] or new_img.height() != res['height']:
            reply = QMessageBox.question(
                self, "Resize",
                f"Image ({new_img.width()}x{new_img.height()}) will be resized "
                f"to {res['width']}x{res['height']}.\nContinue?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            new_img = new_img.scaled(
                res['width'], res['height'],
                Qt.IgnoreAspectRatio, Qt.SmoothTransformation
            )

        # Convert to RGBA
        new_img = new_img.convertToFormat(QImage.Format_RGBA8888)

        # Replace in firmware data
        self.firmware.replace_image(res, new_img)

        # Update cache
        self.resources_by_name[res['name']] = (res, new_img)
        for i, (r, _) in enumerate(self.all_res_images):
            if r['name'] == res['name']:
                self.all_res_images[i] = (res, new_img)
                break

        self.statusBar().showMessage(f"✓ Replaced: {res['name']}")

        if callback:
            callback(res, new_img)

    def _export_images(self):
        """Show dialog to export images by theme or all."""
        if not self.firmware or not self.all_res_images:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Export Images")
        dlg.setMinimumWidth(350)
        layout = QVBoxLayout(dlg)

        layout.addWidget(QLabel("What do you want to export?"))

        group = QButtonGroup(dlg)
        radios = []

        # Current theme option
        cur_name = self.active_themes.get(self.current_theme_key, THEMES.get(self.current_theme_key, ("?","")))[0]
        r_current = QRadioButton(f"Current theme: {self.current_theme_key} – {cur_name}")
        r_current.setChecked(True)
        group.addButton(r_current, 0)
        layout.addWidget(r_current)

        # Only active themes
        active_keys = [k for k in THEMES if k in self.active_themes]
        for i, key in enumerate(active_keys):
            name = self.active_themes[key][0]
            prefix = self.active_themes[key][1]
            label = f"Theme {key} – {name}" + (f"  (prefix: {prefix})" if prefix else "")
            r = QRadioButton(label)
            group.addButton(r, i + 1)
            layout.addWidget(r)
            radios.append(r)

        # All resources option
        r_all = QRadioButton("All resources (all images)")
        group.addButton(r_all, len(active_keys) + 1)
        layout.addWidget(r_all)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            return

        choice = group.checkedId()

        folder = QFileDialog.getExistingDirectory(
            self, "Destination folder", str(get_app_dir()))
        if not folder:
            return

        folder = Path(folder)

        if choice == 0:
            self._do_export_theme(folder, self.current_theme_key)
        elif 1 <= choice <= len(active_keys):
            theme_key = active_keys[choice - 1]
            self._do_export_theme(folder, theme_key)
        elif choice == len(active_keys) + 1:
            self._do_export_all(folder)

    def _do_export_theme(self, base_folder, theme_key):
        """Export all resources matching a single theme to PNGs with subfolders."""
        name, prefix = THEMES[theme_key]
        out_dir = base_folder / f"Theme_{theme_key}_{name.replace(' ', '_')}"
        boot_dir = out_dir / "Boot"
        ui_dir = out_dir / "UI"
        boot_dir.mkdir(parents=True, exist_ok=True)
        ui_dir.mkdir(parents=True, exist_ok=True)

        # Themed boot prefix (from Option 1 patch): T_B_, T_C_, etc.
        tboot = f"T_{theme_key}_" if theme_key != "A" else ""

        exported = 0
        total = len(self.all_res_images)
        for idx, (res, img) in enumerate(self.all_res_images):
            if idx % 100 == 0:
                self.statusBar().showMessage(
                    f"Exporting theme {theme_key}... {idx}/{total}")
                QApplication.processEvents()

            rname = res['name']
            is_shared = res['index'] < 67
            is_themed = resource_matches_theme(rname, prefix)
            is_themed_boot = tboot and rname.startswith(tboot)

            if not is_shared and not is_themed and not is_themed_boot:
                continue

            safe_name = rname.replace('.BMP', '').replace('/', '_').replace('\\', '_')
            fname = f"{res['index']:04d}_{safe_name}.png"
            pixmap = QPixmap.fromImage(img)

            # Shared or themed boot resources → Boot/
            if is_shared or is_themed_boot:
                pixmap.save(str(boot_dir / fname), "PNG")
            else:
                pixmap.save(str(ui_dir / fname), "PNG")
            exported += 1

        self.statusBar().showMessage(
            f"✓ Exported {exported} images from theme {theme_key} to {out_dir.name}/")
        QMessageBox.information(
            self, "Export Complete",
            f"{exported} images exported to:\n{out_dir}\n\n"
            f"Structure:\n"
            f"  Boot/ — POWERON, POWEROFF, CHARGELEVEL, etc.\n"
            f"  UI/ — Menu, player, folders, USB, etc.")

    def _do_export_all(self, base_folder):
        """Export ALL resources organized by theme into subfolders."""
        out_dir = base_folder / "Echo_Mini_Resources"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Shared subfolder
        shared_dir = out_dir / "Shared"
        shared_dir.mkdir(exist_ok=True)

        # Theme subfolders (only active)
        active_keys = [k for k in THEMES if k in self.active_themes]
        theme_dirs = {}
        for key in active_keys:
            name = self.active_themes[key][0]
            d = out_dir / f"Theme_{key}_{name.replace(' ', '_')}"
            d.mkdir(exist_ok=True)
            theme_dirs[key] = d

        exported = 0
        total = len(self.all_res_images)
        for idx, (res, img) in enumerate(self.all_res_images):
            if idx % 100 == 0:
                self.statusBar().showMessage(
                    f"Exporting all... {idx}/{total}")
                QApplication.processEvents()

            rname = res['name']
            safe_name = rname.replace('.BMP', '').replace('/', '_').replace('\\', '_')
            fname = f"{res['index']:04d}_{safe_name}.png"
            pixmap = QPixmap.fromImage(img)

            # Determine which folder
            if res['index'] < 67:
                pixmap.save(str(shared_dir / fname), "PNG")
            else:
                placed = False
                for key in active_keys:
                    pfx = self.active_themes[key][1]
                    if pfx and rname.startswith(pfx):
                        pixmap.save(str(theme_dirs[key] / fname), "PNG")
                        placed = True
                        break
                if not placed and "A" in theme_dirs:
                    pixmap.save(str(theme_dirs["A"] / fname), "PNG")
            exported += 1

        theme_list = "\n".join(f"  Theme_{k}/ — {self.active_themes[k][0]}" for k in active_keys)
        self.statusBar().showMessage(
            f"✓ Exported {exported} images to {out_dir.name}/")
        QMessageBox.information(
            self, "Export Complete",
            f"{exported} images exported to:\n{out_dir}\n\n"
            f"Structure:\n"
            f"  Shared/ — Boot/charge resources (0-66)\n"
            f"{theme_list}")

    def _import_theme(self):
        """Import a theme folder into a chosen firmware theme slot."""
        if not self.firmware:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        folder = QFileDialog.getExistingDirectory(
            self, "Select theme folder to import", str(get_app_dir()))
        if not folder:
            return

        folder = Path(folder)

        # Collect all PNGs from folder and subfolders
        png_files = list(folder.rglob("*.png"))
        if not png_files:
            QMessageBox.warning(self, "No images",
                                f"No .png files found in:\n{folder}")
            return

        # ── Dialog: choose target theme slot, prefix and name ──
        dlg = QDialog(self)
        dlg.setWindowTitle("Import Theme — Settings")
        dlg.setMinimumWidth(420)
        lay = QVBoxLayout(dlg)

        lay.addWidget(QLabel(f"Folder: {folder.name}  ({len(png_files)} images)"))
        lay.addWidget(QLabel(""))

        # Target theme selector
        lay.addWidget(QLabel("Import onto theme:"))
        theme_group = QButtonGroup(dlg)
        theme_radios = []
        all_keys = [k for k in THEMES]
        for i, key in enumerate(all_keys):
            default_name, prefix = THEMES[key]
            has_data = key in self.active_themes
            status = "✦ has data" if has_data else "empty"
            display_name = self.active_themes[key][0] if has_data else default_name
            label = f"{key} – {display_name}  (prefix: {prefix or 'none'}) [{status}]"
            r = QRadioButton(label)
            theme_group.addButton(r, i)
            lay.addWidget(r)
            theme_radios.append(r)
            # Pre-select first empty slot, or first active if all populated
            if not theme_radios[0].isChecked() and not has_data:
                r.setChecked(True)
        if not any(r.isChecked() for r in theme_radios):
            theme_radios[0].setChecked(True)

        lay.addWidget(QLabel(""))

        # Custom name
        lay.addWidget(QLabel("Theme name:"))
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("E.g.: Neon Purple, Fallout Pipboy, etc.")
        name_edit.setText(folder.name)
        lay.addWidget(name_edit)

        # Custom prefix
        lay.addWidget(QLabel("Prefix (auto-assigned by slot, modify if needed):"))
        prefix_edit = QLineEdit()
        prefix_edit.setPlaceholderText("E.g.: F_, G_, etc.")
        lay.addWidget(prefix_edit)

        # Auto-fill prefix when theme selection changes
        def _update_prefix():
            idx = theme_group.checkedId()
            if idx >= 0:
                key = all_keys[idx]
                prefix_edit.setText(THEMES[key][1])
        theme_group.buttonClicked.connect(lambda: _update_prefix())
        _update_prefix()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            return

        target_idx = theme_group.checkedId()
        target_key = all_keys[target_idx]
        target_prefix = prefix_edit.text().strip()
        custom_name = name_edit.text().strip() or f"Theme {target_key}"

        # Update THEMES dict with custom name
        THEMES[target_key] = (custom_name, target_prefix)

        # Write theme name to firmware StrTbl (all 21 languages)
        theme_keys = list(THEMES.keys())
        tidx = theme_keys.index(target_key)
        if self.firmware and self.firmware._strtbl_info and tidx < len(self.firmware.theme_names):
            self.firmware.set_theme_name(tidx, custom_name)

        # Build name→resource lookup for target theme + shared
        name_to_res = {}
        for res, img in self.all_res_images:
            safe = res['name'].replace('.BMP', '').replace('/', '_').replace('\\', '_')
            name_to_res[safe.upper()] = res

        replaced = 0
        skipped = []
        errors = []

        for png_path in png_files:
            stem = png_path.stem
            # Remove leading index prefix (####_)
            parts = stem.split('_', 1)
            if len(parts) == 2 and parts[0].isdigit():
                res_name_part = parts[1]
                file_idx = int(parts[0])
            else:
                res_name_part = stem
                file_idx = None

            match = None

            # 1. Try with target prefix (base name → target theme resource)
            if target_prefix:
                prefixed = target_prefix + res_name_part
                match = name_to_res.get(prefixed.upper())

            # 2. Strip any source theme prefix, then apply target prefix
            if match is None:
                for _, (_, src_pfx) in THEMES.items():
                    if src_pfx and res_name_part.upper().startswith(src_pfx.upper()):
                        stripped = res_name_part[len(src_pfx):]
                        remapped = (target_prefix + stripped) if target_prefix else stripped
                        match = name_to_res.get(remapped.upper())
                        if match:
                            break

            # 3. Themed boot remap: T_X_POWERON → T_target_POWERON
            if match is None and res_name_part.upper().startswith('T_'):
                t_parts = res_name_part.split('_', 2)
                if len(t_parts) >= 3:
                    base_boot = t_parts[2]
                    tboot = f"T_{target_key}_" if target_key != "A" else ""
                    candidate = (tboot + base_boot) if tboot else base_boot
                    match = name_to_res.get(candidate.upper())

            # 4. For boot resources, try T_{target}_ prefix mapping
            if match is None and target_key != "A":
                tboot = f"T_{target_key}_"
                match = name_to_res.get((tboot + res_name_part).upper())

            # 5. Direct name match — only accept if it belongs to target theme or is shared
            if match is None:
                direct = name_to_res.get(res_name_part.upper())
                if direct:
                    rname = direct['name']
                    if resource_matches_theme(rname, target_prefix) or direct['index'] < 67:
                        match = direct

            # 6. Index-based lookup (last resort)
            if match is None and file_idx is not None:
                for res, _ in self.all_res_images:
                    if res['index'] == file_idx:
                        match = res
                        break

            if match is None:
                skipped.append(png_path.name)
                continue

            new_img = QImage(str(png_path))
            if new_img.isNull():
                errors.append(f"Error loading: {png_path.name}")
                continue

            if new_img.width() != match['width'] or new_img.height() != match['height']:
                new_img = new_img.scaled(
                    match['width'], match['height'],
                    Qt.IgnoreAspectRatio, Qt.SmoothTransformation)

            new_img = new_img.convertToFormat(QImage.Format_RGBA8888)

            try:
                self.firmware.replace_image(match, new_img)
                self.resources_by_name[match['name']] = (match, new_img)
                for i, (r, _) in enumerate(self.all_res_images):
                    if r['name'] == match['name']:
                        self.all_res_images[i] = (match, new_img)
                        break
                replaced += 1
            except Exception as e:
                errors.append(f"{png_path.name}: {e}")

            if replaced % 20 == 0:
                self.statusBar().showMessage(
                    f"Importing to Theme {target_key}... {replaced} replaced")
                QApplication.processEvents()

        # Refresh theme detection and UI
        self._detect_active_themes()
        self._refresh_theme_combo()
        self._populate_panels()

        msg = f"✓ {replaced} images imported to Theme {target_key} – {custom_name}"
        if skipped:
            msg += f"\n⚠ {len(skipped)} archivos sin coincidencia"
        if errors:
            msg += f"\n✗ {len(errors)} errores"

        self.statusBar().showMessage(msg)
        detail = msg
        if skipped and len(skipped) <= 15:
            detail += "\n\nSin coincidencia:\n" + "\n".join(f"  {s}" for s in skipped[:15])
        if errors and len(errors) <= 10:
            detail += "\n\nErrores:\n" + "\n".join(f"  {e}" for e in errors[:10])

        QMessageBox.information(self, "Import Complete", detail)

    def _patch_firmware(self):
        """Apply the themed-boot firmware patch via a dialog."""
        if not self.firmware:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        # Detect current patch state
        try:
            info = self.firmware.detect_patch_info()
        except ValueError as e:
            QMessageBox.critical(self, "Detection Failed", str(e))
            return

        if info['is_patched']:
            QMessageBox.information(
                self, "Already Patched",
                f"This firmware is already patched.\n\n"
                f"CMP R0,#0x00 at offset 0x{info['cmp_offset']:X}\n"
                f"ADDW values: {info['addw_values']}\n"
                f"Resources: {info['resource_count']}")
            return

        # Show confirmation dialog
        dlg = QDialog(self)
        dlg.setWindowTitle("🔧 Patch Firmware — Themed Boots")
        dlg.setMinimumWidth(450)
        lay = QVBoxLayout(dlg)

        lay.addWidget(QLabel(
            "<b>This will patch the firmware to support per-theme boot/charge animations.</b>"))
        lay.addWidget(QLabel(""))
        lay.addWidget(QLabel(f"CMP instruction at: 0x{info['cmp_offset']:X}"))
        lay.addWidget(QLabel(f"Current ADDW values: {info['addw_values']}"))
        lay.addWidget(QLabel(f"Block size: {info['old_block_size']} → {info['new_block_size']}"))
        lay.addWidget(QLabel(f"Resources: {info['resource_count']} → {5 * info['new_block_size']}"))
        lay.addWidget(QLabel(""))
        lay.addWidget(QLabel("⚠ This modifies the firmware binary in memory.\n"
                             "Use 'Save As' to write the patched firmware to a new file."))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            return

        # Apply patch
        try:
            self.statusBar().showMessage("Patching firmware...")
            QApplication.processEvents()
            result = self.firmware.patch_for_themed_boots(
                progress_callback=lambda p: (
                    self.statusBar().showMessage(f"Patching... {p}%"),
                    QApplication.processEvents()
                )
            )
            # Reload resources from patched firmware
            self._load_firmware(str(self.firmware.img_path))
            QMessageBox.information(self, "Patch Complete", result)
        except Exception as e:
            QMessageBox.critical(self, "Patch Error", f"Failed to patch firmware:\n{e}")

    def _save_firmware(self):
        if not self.firmware:
            return
        try:
            self.firmware.save()
            self.statusBar().showMessage("✓ Firmware saved successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save:\n{e}")

    def _save_as(self):
        if not self.firmware:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Firmware As",
            str(self.firmware.img_path.parent),
            "Firmware (*.IMG);;All (*.*)"
        )
        if path:
            try:
                self.firmware.save(path)
                self.statusBar().showMessage(f"✓ Saved as: {Path(path).name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save:\n{e}")


# ============================================================================
# Entry Point
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Dark theme
    palette = app.palette()
    palette.setColor(palette.Window, QColor(45, 45, 48))
    palette.setColor(palette.WindowText, QColor(220, 220, 220))
    palette.setColor(palette.Base, QColor(30, 30, 30))
    palette.setColor(palette.AlternateBase, QColor(45, 45, 48))
    palette.setColor(palette.ToolTipBase, QColor(220, 220, 220))
    palette.setColor(palette.ToolTipText, QColor(220, 220, 220))
    palette.setColor(palette.Text, QColor(220, 220, 220))
    palette.setColor(palette.Button, QColor(55, 55, 58))
    palette.setColor(palette.ButtonText, QColor(220, 220, 220))
    palette.setColor(palette.BrightText, QColor(255, 50, 50))
    palette.setColor(palette.Link, QColor(42, 130, 218))
    palette.setColor(palette.Highlight, QColor(42, 130, 218))
    palette.setColor(palette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    window = EchoMiniCustomizer()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
