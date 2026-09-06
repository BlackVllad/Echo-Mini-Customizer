#!/usr/bin/env python3
"""
Echo Mini Firmware Customizer
Interactive preview of boot/shutdown screens, main menu, music player,
file browser, and other firmware resources with real-time editing.
"""

import sys
import os
import struct
from pathlib import Path
from collections import OrderedDict

import numpy as np

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
        self._original_trailer = bytes(self.img_data[-4:])  # saved before any modification
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
        # Byte search: table isn't always 4-byte aligned.
        first_match = None
        needle = struct.pack('<I', anchor)
        search_pos = 0
        while True:
            hit = part5.find(needle, search_pos)
            if hit == -1:
                break
            search_pos = hit + 1
            pos = hit - 20
            if pos < 0 or pos + self.METADATA_ENTRY_SIZE > len(part5):
                continue
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

        # Parse entries — stop at rock26_count to avoid reading garbage beyond the table
        self.entries = []
        pos = table_start
        while pos + self.METADATA_ENTRY_SIZE <= len(part5):
            if len(self.entries) >= rock26_count:
                break
            nm = part5[pos + 32:pos + 96].split(b'\x00')[0].decode('ascii', errors='ignore')
            if not nm or len(nm) < 3:
                break
            off = struct.unpack('<I', part5[pos + 20:pos + 24])[0]
            w = struct.unpack('<I', part5[pos + 24:pos + 28])[0]
            h = struct.unpack('<I', part5[pos + 28:pos + 32])[0]
            self.entries.append({
                'name': nm, 'offset': off, 'width': w, 'height': h,
                'raw_size': w * h * 2, 'table_pos': pos
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
        self._theme_strtbl_indices = []  # maps theme_names[i] → actual StrTbl slot index
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
        # V3.x firmware uses 0x0154; V2.0 firmware uses 0x0156
        VALID_THEME_PARENT_IDS = {0x0154, 0x0156}
        for ti in range(20):
            name_addr = section_abs + self.STRTBL_THEME_NAME_OFFSET + ti * self.STRTBL_THEME_ENTRY_SIZE
            hdr_addr = name_addr - HEADER_SIZE
            if hdr_addr < 0 or name_addr + 4 > len(self.img_data):
                break
            # Skip non-theme entries (settings, language labels, etc.) instead of stopping
            parent_id = struct.unpack_from('<H', self.img_data, hdr_addr + 2)[0]
            if parent_id not in VALID_THEME_PARENT_IDS:
                continue
            name = self._read_utf16le(name_addr)
            if not name:
                continue
            self.theme_names.append(name)
            self._theme_strtbl_indices.append(ti)

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
        # Map logical theme index (0=A, 1=B, …) to actual StrTbl slot index.
        # V2.0 firmware has non-theme entries before the theme names, so the
        # real StrTbl slot differs from the logical index.
        strtbl_slot = (self._theme_strtbl_indices[theme_index]
                       if theme_index < len(self._theme_strtbl_indices)
                       else theme_index)
        strtbl_off, nr_lang, lang_offsets = self._strtbl_info
        new_name = new_name[:99]  # max 99 chars
        encoded = new_name.encode('utf-16-le') + b'\x00\x00'
        for lang_idx in range(nr_lang):
            section_abs = strtbl_off + lang_offsets[lang_idx]
            addr = section_abs + self.STRTBL_THEME_NAME_OFFSET + strtbl_slot * self.STRTBL_THEME_ENTRY_SIZE
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

        for i in range(len(self.entries)):
            e = self.entries[i]
            if self.misalignment > 0:
                ti = i + self.misalignment
                if ti >= len(self.entries):
                    # Last entry(ies): metadata table exhausted, read offset from R26 directly
                    eo = self.rock26_start_in_part5 + i * 16
                    if eo + 16 > len(part5):
                        continue
                    offset = struct.unpack('<I', part5[eo + 12:eo + 16])[0]
                else:
                    offset = self.entries[ti]['offset']
            elif self.misalignment < 0:
                ti = i + self.misalignment
                if ti < 0:
                    continue
                offset = self.entries[ti]['offset']
            else:
                offset = e['offset']

            # BUG-1 FIX: use the same misalignment-adjusted index for dimensions
            # as is used for the offset field above — not a hardcoded i+1.
            meta_idx = i + self.misalignment
            if 0 <= meta_idx < len(self.entries):
                w = self.entries[meta_idx]['width']
                h = self.entries[meta_idx]['height']
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
        w, h = res['width'], res['height']
        if w == 0 or h == 0 or w > 10000 or h > 10000:
            return QImage(1, 1, QImage.Format_RGBA8888)
        part5 = self.get_part5()
        raw_size = res.get('raw_size', w * h * 2)
        raw = part5[res['offset']:res['offset'] + raw_size]
        return rgb565_to_qimage(raw, w, h)

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
        """Decode a Thumb2 ADDW T4 (plain 12-bit) or ADD.W T3 (modified immediate).
        ADDW T4:   hw1 = 0xF200|(i<<10)|Rn  → plain imm12
        ADD.W T3:  hw1 = 0xF100|(i<<10)|Rn  → ThumbExpandImm rotation encoding"""
        i    = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        imm8 = hw2 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        # ADDW T4: plain 12-bit immediate
        if (hw1 & 0xFBE0) == 0xF200:
            return imm12
        # ADD.W T3: ThumbExpandImm modified immediate
        if (imm12 >> 11) == 0:
            bits98 = (imm12 >> 8) & 3
            val8   = imm12 & 0xFF
            if bits98 == 0:  return val8
            if bits98 == 1:  return (val8 << 16) | val8
            if bits98 == 2:  return (val8 << 24) | (val8 << 8)
            return (val8 << 24) | (val8 << 16) | (val8 << 8) | val8
        shift = (imm12 >> 7) & 0x1F
        val   = 0x80 | (imm12 & 0x7F)
        return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF

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

    @staticmethod
    def _encode_bw(src_addr, dst_addr):
        """Encode Thumb2 B.W (unconditional 32-bit branch), 4 bytes."""
        pc = src_addr + 4
        offset = dst_addr - pc
        assert offset % 2 == 0, "Branch target not 2-byte aligned"
        imm = offset >> 1
        if imm < 0:
            imm25 = imm + (1 << 25)
        else:
            imm25 = imm
        S      = (imm25 >> 24) & 1
        I1     = (imm25 >> 23) & 1
        I2     = (imm25 >> 22) & 1
        imm10H = (imm25 >> 11) & 0x3FF
        imm11L = imm25 & 0x7FF
        J1 = (~(I1 ^ S)) & 1
        J2 = (~(I2 ^ S)) & 1
        hw1 = 0xF000 | (S << 10) | imm10H
        hw2 = 0x9000 | (J1 << 13) | (J2 << 11) | imm11L
        return struct.pack('<HH', hw1, hw2)

    @staticmethod
    def _decode_bw_target(instr_addr, hw1, hw2):
        """Decode a Thumb2 B.W instruction at instr_addr → return absolute target address."""
        S      = (hw1 >> 10) & 1
        imm10H = hw1 & 0x3FF
        J1     = (hw2 >> 13) & 1
        J2     = (hw2 >> 11) & 1
        imm11L = hw2 & 0x7FF
        I1 = 1 - (J1 ^ S)
        I2 = 1 - (J2 ^ S)
        imm25 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10H << 11) | imm11L
        if S:
            imm25 -= (1 << 25)
        return (instr_addr + 4 + imm25 * 2) & 0xFFFFFFFF

    def _find_cave_ret_addr(self, cave_addr):
        """Scan the cave code for the B.W that jumps back to the main code (ret_addr)."""
        data = self.img_data
        for off in range(cave_addr, cave_addr + 512, 2):
            if off + 4 > len(data):
                break
            hw1, hw2 = struct.unpack_from('<HH', data, off)
            if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0x9000:
                target = self._decode_bw_target(off, hw1, hw2)
                if 0x200 <= target < self.part5_offset:
                    return target
        raise ValueError("No se encontró ret_addr en el cave code")

    @staticmethod
    def _encode_bcc16(src_addr, dst_addr, cond):
        """Encode 16-bit conditional Thumb branch (range ±254 bytes), 2 bytes.
        cond: 0=EQ, 1=NE, 2=CS, 3=CC (unsigned lower), etc."""
        pc = src_addr + 4
        offset = dst_addr - pc
        assert offset % 2 == 0
        imm8 = offset >> 1
        assert -128 <= imm8 <= 127, (
            f"Branch 0x{src_addr:X}→0x{dst_addr:X} out of 16-bit range (offset={offset})")
        if imm8 < 0:
            imm8 += 256
        return struct.pack('<H', 0xD000 | (cond << 8) | (imm8 & 0xFF))

    @staticmethod
    def _encode_ldr_pc_rel(rt, instr_addr, pool_addr):
        """Encode LDR Rt, [PC, #imm8×4] (2 bytes, Thumb-1 literal pool load)."""
        pc_aligned = (instr_addr + 4) & ~3
        offset = pool_addr - pc_aligned
        assert 0 <= offset <= 1020 and offset % 4 == 0, (
            f"LDR PC-relative offset out of range: {offset}")
        imm8 = offset >> 2
        assert 0 <= rt <= 7
        return struct.pack('<H', 0x4800 | (rt << 8) | imm8)

    @staticmethod
    def _encode_ldrb_w(rt, rn, imm12):
        """Encode LDRB.W Rt, [Rn, #imm12] (4 bytes, Thumb2 unsigned byte load)."""
        assert 0 <= imm12 < 4096, f"LDRB.W offset out of range: {imm12}"
        hw1 = 0xF890 | (rn & 0xF)
        hw2 = ((rt & 0xF) << 12) | imm12
        return struct.pack('<HH', hw1, hw2)

    @staticmethod
    def _encode_cbz(rn, instr_addr, target_addr):
        """Encode CBZ Rn, target (2 bytes, Thumb-1, forward-only range 0–126 bytes)."""
        offset = target_addr - (instr_addr + 4)
        assert 0 <= offset <= 126 and offset % 2 == 0, (
            f"CBZ offset out of range: {offset}")
        imm6 = offset >> 1          # 6-bit value: i[5] | L[4:0]
        i = (imm6 >> 5) & 1
        L = imm6 & 0x1F
        hw = 0xB100 | (i << 9) | (L << 3) | (rn & 7)
        return struct.pack('<H', hw)

    @staticmethod
    def _encode_cmp_imm(rn, imm8):
        """Encode CMP Rn, #imm8 (2 bytes, Thumb-1)."""
        return struct.pack('<H', 0x2800 | ((rn & 7) << 8) | (imm8 & 0xFF))

    @staticmethod
    def _encode_it_eq():
        """Encode IT EQ (2 bytes, Thumb2)."""
        return struct.pack('<H', 0xBF08)

    @staticmethod
    def _encode_uxth_r0():
        """Encode UXTH R0, R0 (2 bytes, Thumb-1)."""
        return struct.pack('<H', 0xB280)

    def _find_code_cave(self, min_size=128):
        """Find a zero-filled region in the loader section for code injection.
        Scans from 0x10000 up to Part5, returns the file offset of the cave."""
        data = self.img_data
        p5_start = self.part5_offset
        cave_start = None
        cave_len = 0
        for off in range(0x10000, p5_start):
            if data[off] == 0:
                if cave_start is None:
                    cave_start = off
                cave_len += 1
            else:
                if cave_len >= min_size:
                    aligned = (cave_start + 3) & ~3
                    if cave_start + cave_len - aligned >= min_size:
                        return aligned
                cave_start = None
                cave_len = 0
        if cave_len >= min_size and cave_start is not None:
            aligned = (cave_start + 3) & ~3
            if cave_start + cave_len - aligned >= min_size:
                return aligned
        raise ValueError(f"No suitable code cave found (need {min_size} zero bytes before Part5)")

    def _detect_dispatch_setup(self, cmp_offset):
        """Parse LDR + LDRB.W after the CMP to extract the settings pointer value
        and the byte offset into the settings struct for the theme index.
        Returns (settings_ptr_val, ldrb_offset)."""
        data = self.img_data
        # LDR R2, [PC, #imm8×4] is at cmp_offset+4 (after CMP 2B + BCC 2B)
        ldr_addr = cmp_offset + 4
        ldr_hw   = struct.unpack_from('<H', data, ldr_addr)[0]
        if (ldr_hw & 0xF800) != 0x4800:
            raise ValueError(f"Expected LDR PC-rel at 0x{ldr_addr:X}, got 0x{ldr_hw:04X}")
        ldr_imm8     = ldr_hw & 0xFF
        pc_aligned   = (ldr_addr + 4) & ~3
        load_addr    = pc_aligned + ldr_imm8 * 4
        settings_ptr = struct.unpack_from('<I', data, load_addr)[0]

        # LDRB.W at cmp_offset+6 (LDR is 2 bytes)
        ldrb_addr = cmp_offset + 6
        ldrb_hw2  = struct.unpack_from('<H', data, ldrb_addr + 2)[0]
        ldrb_off  = ldrb_hw2 & 0xFFF
        return settings_ptr, ldrb_off

    def _build_cave_code(self, cave_addr, n_themes, new_blk,
                         settings_ptr_val, ldrb_off, ret_addr):
        """Build ARM Thumb2 dispatch cave for n_themes (including A).

        Cave layout (for n_checks = n_themes - 1 theme checks beyond A):
          +0  : CMP  R0, #0                (2)  [always falls through — preserves per-theme boots]
          +2  : BCC  → no_dispatch          (2)  [dead branch; kept for structural symmetry]
          +4  : LDR  R2, [PC, #pool_off]   (2)
          +6  : LDRB.W R2, [R2, #ldrb_off] (4)
          +10 : CBZ  R2, uxth              (2)   [theme A = 0]
          +12 : n_checks × 10-byte theme blocks:
                  CMP R2,#hw  (2) + IT EQ (2) + ADDW R0,#N (4) + BEQ uxth (2)
          uxth: UXTH R0, R0                (2)
          no_dispatch: B.W ret_addr        (4)
          [NOP padding to 4-byte align]
          pool: .word settings_ptr_val     (4)
        """
        # Dispatch order: B(hw=1), C(2), E(4), D(3), then F(5), G(6), ...
        # ADDW value for hw_idx X = hw_idx × new_blk (NOT slot_idx × new_blk!)
        # This matches the original patch: new_addw_vals = [1×, 2×, 4×, 3×] × NEW_BLK
        ORIG_HW_ORDER = [1, 2, 4, 3]
        dispatch = []
        for slot_idx, hw_idx in enumerate(ORIG_HW_ORDER, start=1):
            if slot_idx < n_themes:
                dispatch.append((hw_idx, new_blk * hw_idx))  # ADDW = hw_idx × new_blk
        for slot_idx in range(5, n_themes):
            dispatch.append((slot_idx, new_blk * slot_idx))

        n_checks   = len(dispatch)
        uxth_off   = 12 + 10 * n_checks
        bw_off     = uxth_off + 2           # B.W starts 2 bytes after UXTH
        after_bw   = bw_off + 4
        pool_off   = (after_bw + 3) & ~3   # 4-byte aligned
        total_size = pool_off + 4

        cave_uxth_addr      = cave_addr + uxth_off
        cave_no_disp_addr   = cave_addr + bw_off
        cave_pool_addr      = cave_addr + pool_off

        code = bytearray()

        # CMP R0, #0  — matches the boot patch (CMP #0 so BCC never fires;
        # ALL resources including boot frames 0-66 go through the ADDW dispatch,
        # preserving per-theme boot/shutdown/charge animations).
        code += self._encode_cmp_imm(0, 0)
        # BCC → no_dispatch  (dead branch with CMP #0, kept for structural symmetry)
        code += self._encode_bcc16(cave_addr + 2, cave_no_disp_addr, 3)
        # LDR R2, [PC, #pool]
        code += self._encode_ldr_pc_rel(2, cave_addr + 4, cave_pool_addr)
        # LDRB.W R2, [R2, #ldrb_off]
        code += self._encode_ldrb_w(2, 2, ldrb_off)
        # CBZ R2, uxth  (if theme A = 0, skip dispatch)
        code += self._encode_cbz(2, cave_addr + 10, cave_uxth_addr)

        # Per-theme dispatch blocks (10 bytes each)
        for i, (hw_idx, addw_val) in enumerate(dispatch):
            blk_addr = cave_addr + 12 + 10 * i
            code += self._encode_cmp_imm(2, hw_idx)
            code += self._encode_it_eq()
            code += self._encode_addw(addw_val, rd=0, rn=0)
            # BEQ uxth
            code += self._encode_bcc16(blk_addr + 8, cave_uxth_addr, 0)

        assert len(code) == uxth_off, f"Cave layout mismatch: {len(code)} vs {uxth_off}"

        # UXTH R0, R0 — done label
        code += self._encode_uxth_r0()
        # B.W ret_addr — no_dispatch label
        code += self._encode_bw(cave_addr + bw_off, ret_addr)

        # NOP padding to 4-byte align the literal pool
        while len(code) < pool_off:
            code += b'\xBF\x00'     # NOP (Thumb-1)

        # Literal pool: settings struct pointer (RAM address)
        code += struct.pack('<I', settings_ptr_val)

        assert len(code) == total_size, f"Cave size mismatch: {len(code)} vs {total_size}"
        return bytes(code)

    def detect_theme_count(self):
        """Return the current number of active theme slots in the firmware.
        Derived from the ROCK26 entry count and block size."""
        info = self.detect_patch_info()
        if not info['is_patched']:
            return 5  # original unpatched has 5 slots
        new_blk = info['new_block_size']
        if new_blk <= 0:
            return 5
        n = self.rock26_count // new_blk
        return max(5, n)

    def is_cave_dispatched(self):
        """Return True if the cave B.W dispatch has been applied.
        After cave expansion, detect_patch_info() finds the cave itself (CMP R0,#67
        + n ADDWs), so we check the 'is_cave' flag as the reliable indicator."""
        info = self.detect_patch_info()
        return info.get('is_cave', False)

    def expand_theme_count(self, n_themes, progress_callback=None):
        """Expand the firmware to support n_themes theme slots (must be > current count).

        Steps:
          1. Apply the standard 5-theme boot patch if not already done.
          2. If n_themes > 5: inject a code cave replacing the 4-ADDW dispatch
             with an N-theme dispatch, then expand the ROCK26 + metadata tables.

        Maximum n_themes: 11 (limited by ADDW imm12 ≤ 4095 with NEW_BLK = 374).
        """
        if n_themes < 5 or n_themes > 11:
            raise ValueError(f"n_themes must be 5–11, got {n_themes}")

        info = self.detect_patch_info()

        # ── Step 1: ensure 5-theme boot patch is applied ──────────────
        if not info['is_patched']:
            result = self.patch_for_themed_boots(
                progress_callback=lambda p: progress_callback and progress_callback(int(p * 0.4)))
            if progress_callback:
                progress_callback(40)
            # Re-detect after patch
            info = self.detect_patch_info()

        current_n = self.detect_theme_count()
        if n_themes <= current_n:
            return f"Firmware already supports {current_n} themes — no expansion needed."

        new_blk = info['new_block_size']   # 374 after boot patch
        cmp_off = info['cmp_offset']

        # ── Step 2: build + inject code cave ──────────────────────────
        cave_addr    = self._find_code_cave(min_size=256)
        # "ret_addr" = the address right after the original dispatch block
        # = CMP(2) + BCC(2) + LDR(2) + LDRB.W(4) + CBZ(2) + 4×(CMP2+IT2+ADDW4+BCC2)
        # The original code continues at cmp_off + 4 + … but the safe target is
        # cmp_off + 2 + 2 + 46 = cmp_off + 50 after UXTH at +52; the B.W must go
        # where the original BCC (R0<67) would have gone: the UXTH + continuation.
        # From analysis: original BCC targets cmp_off + 2 + 4 + BCC_imm8×2
        bcc_hw = struct.unpack_from('<H', self.img_data, cmp_off + 2)[0]
        bcc_imm8 = bcc_hw & 0xFF
        if bcc_imm8 >= 128:
            bcc_imm8 -= 256
        ret_addr = (cmp_off + 2) + 4 + bcc_imm8 * 2

        settings_ptr, ldrb_off = self._detect_dispatch_setup(cmp_off)
        cave_code = self._build_cave_code(
            cave_addr, n_themes, new_blk, settings_ptr, ldrb_off, ret_addr)

        # Write cave
        data = self.img_data
        for i, b in enumerate(cave_code):
            data[cave_addr + i] = b

        # Replace CMP+BCC with B.W → cave
        bw_bytes = self._encode_bw(cmp_off, cave_addr)
        data[cmp_off: cmp_off + 4] = bw_bytes

        if progress_callback:
            progress_callback(60)

        # ── Step 3: expand ROCK26 + metadata for new theme blocks ─────
        part5     = self.get_part5()
        r26_start = self.rock26_start_in_part5
        old_count = self.rock26_count

        # Shared resources: first 67 entries (index 0-66)
        SHARED = 67
        shared_r26  = [bytes(part5[r26_start + i * 16: r26_start + i * 16 + 16])
                       for i in range(SHARED)]
        shared_meta = [bytes(part5[self.entries[i]['table_pos']:
                                   self.entries[i]['table_pos'] + self.METADATA_ENTRY_SIZE])
                       for i in range(SHARED)]

        # Build new_r26 and new_meta for n_themes blocks
        theme_letters = 'ABCDEFGHIJKLMNOPQRST'
        new_r26  = []
        new_meta = []

        for t_idx in range(n_themes):
            letter = theme_letters[t_idx]
            # 67 boot entries per theme block
            for i in range(SHARED):
                if t_idx == 0:
                    # Theme A: use shared boot entries as-is
                    new_r26.append(shared_r26[i])
                    new_meta.append(bytes(shared_meta[i]))
                elif t_idx < current_n:
                    # Existing theme B+: preserve its own per-theme boot entries
                    # (which carry the custom boot/charge/shutdown images already stored)
                    src_idx = t_idx * new_blk + i
                    eo = r26_start + src_idx * 16
                    new_r26.append(bytes(part5[eo: eo + 16]))
                    tp = self.entries[src_idx]['table_pos']
                    new_meta.append(bytes(part5[tp: tp + self.METADATA_ENTRY_SIZE]))
                else:
                    # New theme: create T_X_ copies from shared boot entries
                    new_r26.append(shared_r26[i])
                    meta_raw = bytearray(shared_meta[i])
                    orig_name  = self.entries[i]['name']
                    new_name   = f"T_{letter}_{orig_name}"
                    name_bytes = new_name.encode('ascii')[:63]
                    meta_raw[32:96] = name_bytes + b'\x00' * (64 - len(name_bytes))
                    new_meta.append(bytes(meta_raw))

            # Per-theme UI resources — block t_idx starts at t_idx*new_blk+SHARED
            old_start = t_idx * new_blk + SHARED
            for i in range(new_blk - SHARED):   # 307 UI entries per theme
                src_idx = old_start + i
                if src_idx < old_count:
                    # Use existing resource from firmware
                    eo = r26_start + src_idx * 16
                    new_r26.append(bytes(part5[eo: eo + 16]))
                    tp = self.entries[src_idx]['table_pos']
                    meta_entry = bytearray(part5[tp: tp + self.METADATA_ENTRY_SIZE])
                else:
                    # New slot: mirror theme A's corresponding UI resource (entry SHARED+i)
                    # but rename it with the new theme prefix so Import Theme can find it
                    a_idx = SHARED + i
                    eo = r26_start + a_idx * 16
                    new_r26.append(bytes(part5[eo: eo + 16]))
                    tp = self.entries[a_idx]['table_pos']
                    meta_entry = bytearray(part5[tp: tp + self.METADATA_ENTRY_SIZE])
                    orig_name  = self.entries[a_idx]['name']
                    new_name   = f"{letter}_{orig_name}" if letter != 'A' else orig_name
                    name_bytes = new_name.encode('ascii')[:63]
                    meta_entry[32:96] = name_bytes + b'\x00' * (64 - len(name_bytes))

                if i == 0 and t_idx > 0:
                    # Fix block-boundary misalignment: the first UI metadata entry must
                    # carry the pixel offset (and dimensions) of the last shared R26 entry
                    # so that misalignment=1 is maintained consistently across the boundary.
                    last_shared_idx = t_idx * new_blk + SHARED - 1
                    last_raw = struct.unpack_from('<IIII',
                                                 part5[r26_start + last_shared_idx * 16:
                                                       r26_start + last_shared_idx * 16 + 16])
                    last_w   = last_raw[0] & 0xFFFF
                    last_h   = (last_raw[0] >> 16) & 0xFFFF
                    last_off = last_raw[3]
                    struct.pack_into('<I', meta_entry, 20, last_off)
                    struct.pack_into('<I', meta_entry, 24, last_w)
                    struct.pack_into('<I', meta_entry, 28, last_h)

                new_meta.append(bytes(meta_entry))

            if progress_callback:
                progress_callback(60 + int((t_idx + 1) / n_themes * 30))

        new_count = len(new_r26)

        # ── Relocate any R26 images that would be overwritten by new metadata ────
        # New entries [old_count..new_count) land at table_abs + old_count*MES
        # through table_abs + new_count*MES.  Any existing image whose bytes
        # overlap that zone must be moved to safe space (end of current part5)
        # BEFORE the metadata writes so the pixel data is not lost.
        table_abs_for_reloc = self.part5_offset + self.table_start
        new_zone_start = table_abs_for_reloc + old_count * self.METADATA_ENTRY_SIZE
        new_zone_end   = table_abs_for_reloc + new_count * self.METADATA_ENTRY_SIZE
        if new_zone_end > new_zone_start:
            append_abs = self.part5_offset + self.part5_size
            for i in range(new_count):
                r26_entry = bytearray(new_r26[i])
                w      = struct.unpack_from('<H', r26_entry, 0)[0]
                h      = struct.unpack_from('<H', r26_entry, 2)[0]
                off_p5 = struct.unpack_from('<I', r26_entry, 12)[0]
                if not (w and h and off_p5):
                    continue
                img_abs  = self.part5_offset + off_p5
                img_size = w * h * 2
                if img_abs < new_zone_end and img_abs + img_size > new_zone_start:
                    # Copy image to safe space at the end of part5
                    img_bytes = bytes(data[img_abs: img_abs + img_size])
                    if append_abs + img_size > len(data):
                        data.extend(b'\x00' * (append_abs + img_size - len(data)))
                    data[append_abs: append_abs + img_size] = img_bytes
                    struct.pack_into('<I', r26_entry, 12, append_abs - self.part5_offset)
                    new_r26[i] = bytes(r26_entry)
                    # Also update the metadata entry's offset field (bytes 20-23)
                    meta_entry = bytearray(new_meta[i])
                    struct.pack_into('<I', meta_entry, 20, append_abs - self.part5_offset)
                    new_meta[i] = bytes(meta_entry)
                    append_abs += img_size
            # Extend tracked part5_size to cover any relocated images
            self.part5_size = max(append_abs - self.part5_offset, self.part5_size)

        # Write ROCK26 table
        r26_abs    = self.part5_offset + self.rock26_off_in_part5
        struct.pack_into('<I', data, r26_abs + 16, new_count)
        entries_abs = self.part5_offset + r26_start
        for i, raw in enumerate(new_r26):
            pos = entries_abs + i * 16
            if pos + 16 > len(data):
                data.extend(b'\x00' * (pos + 16 - len(data)))
            data[pos: pos + 16] = raw

        # Write metadata table
        meta_abs = self.part5_offset + self.table_start
        for i, raw in enumerate(new_meta):
            pos = meta_abs + i * self.METADATA_ENTRY_SIZE
            if pos + self.METADATA_ENTRY_SIZE > len(data):
                data.extend(b'\x00' * (pos + self.METADATA_ENTRY_SIZE - len(data)))
            data[pos: pos + self.METADATA_ENTRY_SIZE] = raw

        # Update Part5 size — never shrink: firmware may have image data after metadata table
        new_p5_end = (meta_abs + new_count * self.METADATA_ENTRY_SIZE) - self.part5_offset
        new_p5_end = max(new_p5_end, self.part5_size)
        self.part5_size = new_p5_end
        struct.pack_into('<I', data, 0x150, new_p5_end)

        self._fix_integrity()
        self.rock26_count = new_count
        self._parse()

        if progress_callback:
            progress_callback(100)

        added = n_themes - current_n
        return (
            f"✅ Firmware expandido a {n_themes} temas\n\n"
            f"• Cave en   : 0x{cave_addr:X}\n"
            f"• B.W en    : 0x{cmp_off:X}\n"
            f"• Temas añadidos: {added} "
            f"({theme_letters[current_n:n_themes]})\n"
            f"• Tabla     : {old_count} → {new_count} entradas\n"
            f"• Bloque    : {new_blk} recursos/tema\n\n"
            f"Usa 'Import Theme' para cargar imágenes en los nuevos slots."
        )

    def shrink_theme_count(self, n_themes, progress_callback=None):
        """Reduce firmware to n_themes theme slots (minimum 5).

        The dispatch code is updated so only n_themes slots are active.
        Pixel data for removed themes stays in the file (unused, harmless).
        """
        if n_themes < 5 or n_themes > 11:
            raise ValueError(f"n_themes must be 5–11, got {n_themes}")

        info = self.detect_patch_info()
        if not info['is_patched']:
            raise ValueError("El firmware no está parcheado todavía.")

        new_blk = info['new_block_size']  # 374
        current_n = self.detect_theme_count()

        if n_themes >= current_n:
            return f"El firmware ya tiene {current_n} temas — no es necesario reducir."

        data = self.img_data
        cmp_off = info['cmp_offset']

        if progress_callback:
            progress_callback(10)

        if info['is_cave']:
            # Decode the B.W at cmp_off to find where the cave lives
            hw1, hw2 = struct.unpack_from('<HH', data, cmp_off)
            cave_addr = self._decode_bw_target(cmp_off, hw1, hw2)

            # Find ret_addr (the jump-back at end of cave)
            ret_addr = self._find_cave_ret_addr(cave_addr)

            if n_themes <= 5:
                # Restore the standard 5-theme CMP+BCC dispatch (4 bytes)
                # CMP R0, #0 (already the patched value; keeps per-theme boots)
                data[cmp_off:cmp_off + 2] = self._encode_cmp_imm(0, 0)
                # BCC ret_addr — jumps to the UXTH+continuation when R0 < 0 (never,
                # but kept for structural symmetry matching the original dispatch)
                data[cmp_off + 2:cmp_off + 4] = self._encode_bcc16(cmp_off + 2, ret_addr, 3)
                # The 4 ADDW instructions at cmp_off+4 are still [374,748,1496,1122]
                # (they were preserved when the cave B.W was installed), so 5-theme
                # dispatch is fully restored.
                # Zero out the old cave to clean up
                settings_ptr, ldrb_off = self._detect_dispatch_setup(cave_addr)
                old_cave_end = cave_addr + 4 + 4 + (current_n - 1) * 10 + 2 + 4 + 4 + 4
                for z in range(cave_addr, min(old_cave_end, len(data))):
                    data[z] = 0
            else:
                # Rebuild cave at the same address for fewer themes
                settings_ptr, ldrb_off = self._detect_dispatch_setup(cave_addr)
                cave_code = self._build_cave_code(
                    cave_addr, n_themes, new_blk, settings_ptr, ldrb_off, ret_addr)
                # Zero old cave first, then write new (old may be larger)
                old_cave_end = cave_addr + 4 + 4 + (current_n - 1) * 10 + 2 + 4 + 4 + 4
                for z in range(cave_addr, min(old_cave_end, len(data))):
                    data[z] = 0
                for i, b in enumerate(cave_code):
                    data[cave_addr + i] = b
        # (If not is_cave but is_patched: already at 5 themes — shrink_theme_count
        #  would have returned early above since n_themes >= current_n == 5)

        if progress_callback:
            progress_callback(60)

        # Update ROCK26 entry count
        r26_header_abs = self.part5_offset + self.rock26_off_in_part5
        new_count = n_themes * new_blk
        struct.pack_into('<I', data, r26_header_abs + 16, new_count)
        self.rock26_count = new_count

        self._fix_integrity()
        self._parse()

        if progress_callback:
            progress_callback(100)

        removed = current_n - n_themes
        theme_letters = 'ABCDEFGHIJKLMNOPQRST'
        return (
            f"✅ Firmware reducido a {n_themes} temas\n\n"
            f"• Temas eliminados: {removed} "
            f"({theme_letters[n_themes:current_n]})\n"
            f"• Tabla: {current_n * new_blk} → {new_count} entradas\n\n"
            f"Nota: los datos de los temas eliminados permanecen en el archivo\n"
            f"(inactivos e inaccesibles para el dispositivo)."
        )

    def import_themes_from_img(self, source_path, progress_callback=None):
        """Replace this firmware's Part5 (all themes/resources) with the Part5
        from source_path.  The target's code section and original trailer are
        preserved; only the resource partition is swapped.  The ARM dispatch
        code is automatically adjusted to match the source's theme count.

        Returns a human-readable summary string.
        """
        NEW_BLK = 374

        # Load source firmware (read-only — we only need its Part5)
        src = FirmwareParser(source_path)
        src_p5_bytes = bytes(
            src.img_data[src.part5_offset : src.part5_offset + src.part5_size])
        src_theme_count = max(5, src.rock26_count // NEW_BLK)

        if progress_callback:
            progress_callback(5)

        # Ensure target has the boot patch so cmp_off / cave state are valid
        tgt_info = self.detect_patch_info()
        if not tgt_info['is_patched']:
            self.patch_for_themed_boots()
            tgt_info = self.detect_patch_info()

        if progress_callback:
            progress_callback(15)

        cmp_off      = tgt_info['cmp_offset']
        is_cave      = tgt_info.get('is_cave', False)
        new_blk      = tgt_info['new_block_size']   # always 374 after patch
        tgt_current_n = self.detect_theme_count()   # from ROCK26 BEFORE swap
        data         = self.img_data

        # ── Swap Part5 ────────────────────────────────────────────────
        old_p5_end = self.part5_offset + self.part5_size
        data[self.part5_offset : old_p5_end] = src_p5_bytes
        struct.pack_into('<I', data, 0x150, len(src_p5_bytes))
        self._parse()

        if progress_callback:
            progress_callback(50)

        # ── Sync code-section dispatch to match src_theme_count ───────
        if src_theme_count > 5:
            if is_cave:
                # Rebuild cave at the same address for the new theme count
                hw1, hw2     = struct.unpack_from('<HH', data, cmp_off)
                cave_addr    = self._decode_bw_target(cmp_off, hw1, hw2)
                ret_addr     = self._find_cave_ret_addr(cave_addr)
                settings_ptr, ldrb_off = self._detect_dispatch_setup(cave_addr)
                # Zero old cave (size based on tgt_current_n before swap)
                old_cave_sz  = 4 + 4 + (tgt_current_n - 1) * 10 + 2 + 4 + 4 + 4 + 32
                for z in range(cave_addr, min(cave_addr + old_cave_sz, len(data))):
                    data[z] = 0
                cave_code = self._build_cave_code(
                    cave_addr, src_theme_count, new_blk,
                    settings_ptr, ldrb_off, ret_addr)
                for i, b in enumerate(cave_code):
                    data[cave_addr + i] = b
                # B.W at cmp_off already points to cave_addr — no need to rewrite
            else:
                # Standard ADDW dispatch → install new cave
                bcc_hw  = struct.unpack_from('<H', data, cmp_off + 2)[0]
                bcc_imm8 = bcc_hw & 0xFF
                if bcc_imm8 >= 128:
                    bcc_imm8 -= 256
                ret_addr     = (cmp_off + 2) + 4 + bcc_imm8 * 2
                settings_ptr, ldrb_off = self._detect_dispatch_setup(cmp_off)
                cave_addr    = self._find_code_cave(min_size=256)
                cave_code    = self._build_cave_code(
                    cave_addr, src_theme_count, new_blk,
                    settings_ptr, ldrb_off, ret_addr)
                for i, b in enumerate(cave_code):
                    data[cave_addr + i] = b
                bw_bytes = self._encode_bw(cmp_off, cave_addr)
                data[cmp_off : cmp_off + 4] = bw_bytes
        else:
            # src_theme_count <= 5: ensure standard ADDW dispatch
            if is_cave:
                hw1, hw2  = struct.unpack_from('<HH', data, cmp_off)
                cave_addr = self._decode_bw_target(cmp_off, hw1, hw2)
                ret_addr  = self._find_cave_ret_addr(cave_addr)
                # Restore CMP R0,#0 + BCC
                data[cmp_off     : cmp_off + 2] = self._encode_cmp_imm(0, 0)
                data[cmp_off + 2 : cmp_off + 4] = self._encode_bcc16(
                    cmp_off + 2, ret_addr, 3)
                # Zero cave
                for z in range(cave_addr, min(cave_addr + 512, len(data))):
                    data[z] = 0
            # else: standard dispatch is already correct for 5 themes

        if progress_callback:
            progress_callback(80)

        self._fix_integrity()
        self._parse()

        if progress_callback:
            progress_callback(100)

        src_mb = len(src_p5_bytes) / 1024 / 1024
        dispatch_desc = (f"code cave ({src_theme_count} temas)"
                         if src_theme_count > 5 else "ADDW estándar (5 temas)")
        return (
            f"✅ Importados {src_theme_count} temas desde "
            f"{Path(source_path).name}\n\n"
            f"• Part5 copiado: {src_mb:.1f} MB\n"
            f"• Dispatch:      {dispatch_desc}\n\n"
            f"Usa 'Save As' para guardar el firmware resultante."
        )

    # ── Firmware patching ────────────────────────────────────────────

    def detect_patch_info(self):
        """Auto-detect CMP and ADDW locations in the firmware.
        Returns a dict with detection results, or raises ValueError."""
        data = self.img_data

        # Scan for CMP R0, #0x43 (0x2843) or already-patched CMP R0, #0x00 (0x2800)
        # within the code section only — never scan into Part5 resource data.
        cmp_offset = None
        search_limit = min(self.part5_offset, 0x600000)
        for off in range(0x200, search_limit, 2):
            val = struct.unpack_from('<H', data, off)[0]
            if val == 0x2843 or val == 0x2800:
                # Check if 4 ADDW instructions follow within ~60 bytes
                addw_offsets = []
                for scan in range(off + 2, off + 80, 2):
                    if scan + 4 > len(data):
                        break
                    hw1, hw2 = struct.unpack_from('<HH', data, scan)
                    if ((hw1 & 0xFBE0) == 0xF200 or (hw1 & 0xFBEF) == 0xF100) and (hw2 & 0x8F00) == 0x0000:
                        imm = self._decode_addw(hw1, hw2)
                        if imm > 100:
                            addw_offsets.append((scan, imm))
                if len(addw_offsets) >= 4:
                    # Validate: the 4 values must form the exact pattern {k, 2k, 3k, 4k}
                    vals = {v for _, v in addw_offsets[:4]}
                    k = min(vals)
                    if k > 0 and vals == {k, k * 2, k * 3, k * 4}:
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
            if ((hw1 & 0xFBE0) == 0xF200 or (hw1 & 0xFBEF) == 0xF100) and (hw2 & 0x8F00) == 0x0000:
                imm = self._decode_addw(hw1, hw2)
                if imm > 100:
                    addw_list.append((scan, imm))
                    if len(addw_list) == 4:
                        break

        if len(addw_list) < 4:
            raise ValueError(f"Found CMP but only {len(addw_list)} ADDW instructions (need 4)")

        # Determine current state
        cmp_val = struct.unpack_from('<H', data, cmp_offset)[0]
        addw_values = [v for _, v in addw_list]

        SHARED = 67
        OLD_BLK = 307
        NEW_BLK = OLD_BLK + SHARED  # 374

        # BUG-2 FIX: Correct cave detection via B.W back-scan.
        # _build_cave_code() places CMP R0,#0 (0x2800) at the cave start — NOT 0x2843.
        # For cave firmware, the original dispatch location holds a B.W jumping to the cave.
        # Back-scan for a B.W whose branch target == cmp_offset to find the true dispatch address.
        is_cave = False
        bw_origin = None
        if cmp_val == 0x2800 and addw_values[0] >= NEW_BLK:
            for bw_scan in range(0x200, min(cmp_offset, search_limit), 2):
                if bw_scan + 4 > len(data):
                    break
                hw1b, hw2b = struct.unpack_from('<HH', data, bw_scan)
                # B.W encoding: hw1 = 0xF??? (T4), hw2 bits[15:14,12] = 0b10_1 = 0x9
                if (hw1b & 0xF800) == 0xF000 and (hw2b & 0xD000) == 0x9000:
                    if self._decode_bw_target(bw_scan, hw1b, hw2b) == cmp_offset:
                        is_cave = True
                        bw_origin = bw_scan
                        break

        # When cave is found, callers expect cmp_offset = B.W address so that
        # _decode_bw_target(cmp_off, hw1, hw2) resolves to cave_addr correctly.
        if is_cave and bw_origin is not None:
            cmp_offset = bw_origin

        is_patched = (cmp_val == 0x2800) or is_cave

        # Detect block size: first ADDW value = old block size
        if is_patched:
            block_size = addw_values[0]
            shared_count = SHARED
            old_block_size = block_size - shared_count
        else:
            old_block_size = addw_values[0]
            shared_count = SHARED
            block_size = old_block_size

        return {
            'cmp_offset': cmp_offset,
            'cmp_value': cmp_val,
            'is_patched': is_patched,
            'is_cave': is_cave,
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
                    meta_entry = bytearray(part5[tp:tp + self.METADATA_ENTRY_SIZE])
                    if i == 0 and t_idx > 0:
                        # Fix block-boundary misalignment: the first OLD_BLK metadata
                        # entry must carry the pixel offset (and dimensions) of the last
                        # shared R26 entry so that misalignment=1 stays consistent.
                        last_shared_raw = struct.unpack_from('<IIII', bytes(shared_r26[SHARED - 1]))
                        last_w = last_shared_raw[0] & 0xFFFF
                        last_h = (last_shared_raw[0] >> 16) & 0xFFFF
                        last_off = last_shared_raw[3]
                        struct.pack_into('<I', meta_entry, 20, last_off)
                        struct.pack_into('<I', meta_entry, 24, last_w)
                        struct.pack_into('<I', meta_entry, 28, last_h)
                    new_meta.append(bytes(meta_entry))
                else:
                    new_meta.append(shared_meta_raw[0])

            if progress_callback:
                progress_callback(int((t_idx + 1) * 20))

        new_count = len(new_r26)

        # ── 1b. Relocate pixel data that would be overwritten by expanded metadata ──
        # The new table extends from [table_start + old_count×MES, table_start + new_count×MES).
        # Any image whose bytes overlap that zone must be moved to end-of-Part5 first,
        # so the pixel data is not silently destroyed by the metadata write below.
        table_abs = self.part5_offset + self.table_start
        new_zone_start = table_abs + old_count * self.METADATA_ENTRY_SIZE
        new_zone_end   = table_abs + new_count * self.METADATA_ENTRY_SIZE
        if new_zone_end > new_zone_start:
            append_abs = self.part5_offset + self.part5_size
            for i in range(new_count):
                r26_entry = bytearray(new_r26[i])
                w      = struct.unpack_from('<H', r26_entry, 0)[0]
                h      = struct.unpack_from('<H', r26_entry, 2)[0]
                off_p5 = struct.unpack_from('<I', r26_entry, 12)[0]
                if not (w and h and off_p5):
                    continue
                img_abs  = self.part5_offset + off_p5
                img_size = w * h * 2
                if img_abs < new_zone_end and img_abs + img_size > new_zone_start:
                    # Copy pixel bytes to safe space at the end of Part5
                    img_bytes = bytes(data[img_abs: img_abs + img_size])
                    if append_abs + img_size > len(data):
                        data.extend(b'\x00' * (append_abs + img_size - len(data)))
                    data[append_abs: append_abs + img_size] = img_bytes
                    new_off_p5 = append_abs - self.part5_offset
                    struct.pack_into('<I', r26_entry, 12, new_off_p5)
                    new_r26[i] = bytes(r26_entry)
                    meta_entry = bytearray(new_meta[i])
                    struct.pack_into('<I', meta_entry, 20, new_off_p5)
                    new_meta[i] = bytes(meta_entry)
                    append_abs += img_size
            self.part5_size = max(append_abs - self.part5_offset, self.part5_size)

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

        # ── 4. Update Part5 size — never shrink ──
        new_p5_end = (meta_abs + len(new_meta) * self.METADATA_ENTRY_SIZE) - self.part5_offset
        new_p5_end = max(new_p5_end, self.part5_size)
        self.part5_size = new_p5_end
        struct.pack_into('<I', data, 0x150, new_p5_end)

        # ── 5. Patch CMP R0, #0x43 → CMP R0, #0x00 ──
        data[cmp_off:cmp_off + 2] = struct.pack('<H', 0x2800)

        # ── 6. Patch ADDW values ──
        # ADDW[2] -> device slot E, ADDW[3] -> device slot D (confirmed by hardware behavior)
        new_addw_vals = [NEW_BLK, NEW_BLK * 2, NEW_BLK * 4, NEW_BLK * 3]
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

    def _update_loader_constants(self):
        """Update the 6 ARM Thumb-2 bytes in the loader binary that encode NAND partition
        layout constants.  Uses linear interpolation between two reference points:
          • HIFIEC320 / HIFIEC33 (part5=22 968 838 B): CMP=67, A1=51,  A2=614, A4=921,  A3=1228
          • HIFIEC20             (part5=45 823 568 B): CMP=0,  A1=118, A2=748, A4=1496, A3=1122
        HIFIEC33 (V3.3.0) shares the same part5_size and loader zone as HIFIEC320 (V3.2.0),
        so delta=0.0 for both — the loader constants remain identical.
        Delta is clamped to [0, 1] so values never exceed the confirmed-good HIFIEC20 set.
        The function is a no-op when the loader does not match the expected byte pattern.
        V3.4.0 (HIFIEC34): dispatch zone shifted +0x2C; magic bytes at V3.2.0 positions fail
        the check, so this function is automatically a no-op for V3.4.0 firmware.
        """
        data = self.img_data
        if len(data) < 0x03DF8C:
            return

        # Verify expected magic bytes before touching anything
        if not (data[0x03DF5B] == 0x28              # CMP R0, #imm8 opcode
                and data[0x03DF6A:0x03DF6C] == b'\x00\xF2'   # ADDW first halfword
                and data[0x03DF74:0x03DF76] == b'\x00\xF2'
                and data[0x03DF7E:0x03DF80] == b'\x00\xF2'
                and data[0x03DF88:0x03DF8A] == b'\x00\xF2'):
            return  # Unrecognised loader variant — skip

        REF_P5_320 = 22_968_838
        REF_P5_20  = 45_823_568
        new_p5 = struct.unpack_from('<I', data, 0x150)[0]
        delta = max(0.0, min(1.0, (new_p5 - REF_P5_320) / (REF_P5_20 - REF_P5_320)))

        def lerp_int(a, b, t):
            return max(0, round(a + (b - a) * t))

        new_cmp = lerp_int(67, 0,    delta)   # CMP  R0, #imm8
        new_a1  = lerp_int(51, 118,  delta)   # ADDW R1, R0, #imm12  (Rd=R1)
        new_a2  = lerp_int(614, 748, delta)   # ADDW R0, R0, #imm12  (Rd=R0)
        new_a4  = lerp_int(921, 1496, delta)  # ADDW R0, R0, #imm12
        new_a3  = lerp_int(1228, 1122, delta) # ADDW R0, R0, #imm12

        def write_addw(lo_off, imm12, rd):
            """Write imm12 into second halfword of ADDW: [imm8] at lo_off, [(imm3<<4)|rd] at lo_off+1."""
            data[lo_off]     = imm12 & 0xFF
            data[lo_off + 1] = ((imm12 >> 8) & 0x7) << 4 | (rd & 0xF)

        # BUG-3 / BUG-NEW FIX: Guard ALL writes when firmware is already theme-patched.
        # CMP == 0x00 means patch_for_themed_boots() already set the correct ADDW dispatch
        # values [NEW_BLK, NEW_BLK*2, NEW_BLK*4, NEW_BLK*3].  Overwriting them here with
        # the lerp-interpolated NAND layout values corrupts A1 (imm3+Rd wrong) → all theme
        # image offsets are calculated incorrectly → black screen on device (BUG-NEW).
        if data[0x03DF5A] != 0x00:
            data[0x03DF5A] = new_cmp & 0xFF   # CMP R0, #new_cmp
            write_addw(0x03DF6C, new_a1, rd=1)
            write_addw(0x03DF76, new_a2, rd=0)
            write_addw(0x03DF80, new_a4, rd=0)
            write_addw(0x03DF8A, new_a3, rd=0)

    def _fix_integrity(self):
        """Update fw_end pointer, extend file if needed, and write bootloader header copy.

        NOTE: The Echo Mini does not actively verify the RKnano CRC32 trailer,
        so CRC recalculation is intentionally skipped to avoid potential issues
        from incorrect file-size alignment. A backup with CRC logic is kept in
        echo_mini_customizer.CRC32_BACKUP.py if ever needed.
        """
        data = self.img_data
        if data[0x1F8:0x200] != b'RKnanoFW':
            return

        # ① Preserve the original trailer (saved at load time, before any bytearray growth)
        saved_trailer = self._original_trailer
        if saved_trailer == b'\x00\x00\x00\x00':
            raise ValueError(
                "El firmware base tiene trailer 00000000 (archivo corrupto o bricked).\n"
                "Carga un firmware original válido (ej. HIFIEC320.IMG) antes de guardar."
            )

        # ② Recalculate fw_end from actual Part5 end
        ir_off = struct.unpack_from('<I', data, 0x14C)[0]
        ir_sz  = struct.unpack_from('<I', data, 0x150)[0]
        p5_end = ir_off + ir_sz

        fw_end = struct.unpack_from('<I', data, 0x1F4)[0]
        if p5_end > fw_end:
            fw_end = ((p5_end + 0xFFFF) // 0x10000) * 0x10000
            struct.pack_into('<I', data, 0x1F4, fw_end)

        # ②-b Update the 6 loader NAND-partition constants to match the new part5 size.
        #   These ARM Thumb-2 constants in the loader encode partition block offsets and
        #   must scale with firmware size.  Uses linear interpolation between the two
        #   confirmed-working reference firmwares (HIFIEC320 ↔ HIFIEC20).
        self._update_loader_constants()

        # ③ Extend the file if fw_end is beyond the current file size.
        #    This fixes .IMG files that were patched/modified but not properly
        #    resized — the Echo Mini rejects them because the bootloader tries
        #    to read the header copy at fw_end and finds nothing valid.
        ALIGN  = 0x100000
        fw_size = ((fw_end + 16384 + ALIGN) // ALIGN) * ALIGN
        needed  = fw_size + 4

        # ③-b Safety: block firmware that exceeds the confirmed-brick threshold.
        #   • ≤ 54 MB  → confirmed safe (HIFIEC20 works at 54 MB)
        #   • 54–60 MB → risky but may work; loader constants are now updated above
        #   • ≥ 62 MB  → confirmed brick (HIFIEC22 at 62 MB brickea el dispositivo)
        MAX_SAFE_BYTES = 62 * 1024 * 1024  # Hard block at confirmed-brick threshold
        if needed > MAX_SAFE_BYTES:
            mb = needed / 1024 / 1024
            raise ValueError(
                f"⛔ BRICK CONFIRMADO — firmware demasiado grande\n\n"
                f"Tamaño resultante: {mb:.1f} MB\n"
                f"HIFIEC22 (62 MB) brickeó el dispositivo → límite duro: 62 MB.\n\n"
                f"Para reducir el tamaño:\n"
                f"• Usa menos temas o elimina imágenes de boot de algún tema\n"
                f"• Recuerda que cada tema de boot agrega ~5-7 MB de datos únicos"
            )
        if len(data) < needed:
            data.extend(b'\x00' * (needed - len(data)))
        elif len(data) > needed:
            del data[needed:]

        # ④ Copy the 512-byte header to fw_end (bootloader requires it there)
        data[fw_end:fw_end + 0x200] = data[0:0x200]

        # ⑤ Restore the trailer at the very end of the file
        data[-4:] = saved_trailer

    def fix_corrupt_firmware(self) -> str:
        """
        Repair an .IMG that the Echo Mini rejects (detects update then cancels it).

        Use this when:
          - The device detects the update file but cancels it after 1-3 seconds
          - The .IMG was patched or modified but fw_end points beyond the file
          - The trailer bytes are corrupt (e.g. c618c618 instead of a valid value)

        Corrections applied:
          1. Recalculates fw_end from the actual Part5 end
          2. Extends the file to the size required to contain fw_end
          3. Writes the 512-byte header copy at fw_end (bootloader requires it)
          4. Preserves the original trailer bytes (device does not verify CRC32)
        """
        data = self.img_data
        if data[0x1F8:0x200] != b'RKnanoFW':
            raise ValueError("Not a valid RKnano firmware (missing RKnanoFW magic).")

        old_size   = len(data)
        old_fw_end = struct.unpack_from('<I', data, 0x1F4)[0]
        old_trailer = bytes(data[-4:])

        # Run the full integrity fix (extend + header copy + restore trailer)
        self._fix_integrity()

        new_size   = len(data)
        new_fw_end = struct.unpack_from('<I', data, 0x1F4)[0]
        new_trailer = bytes(data[-4:])

        header_copy_ok = (data[new_fw_end:new_fw_end + 0x200] == data[0:0x200])

        return (
            f"✅ Firmware integrity fixed\n\n"
            f"• fw_end  : 0x{old_fw_end:X} → 0x{new_fw_end:X}\n"
            f"• Size    : {old_size:,} → {new_size:,} bytes "
            f"({(new_size - old_size) // 1024:+,} KB)\n"
            f"• Header copy at fw_end: {'✓' if header_copy_ok else '✗'}\n"
            f"• Trailer : {old_trailer.hex()} → {new_trailer.hex()}\n\n"
            f"Use 'Save As' to write the fixed firmware to a new file."
        )


def rgb565_to_qimage(raw, w, h):
    """Fast RGB565 to QImage conversion using numpy."""
    n = w * h
    raw_bytes = raw[:n * 2]
    if len(raw_bytes) < n * 2:
        raw_bytes = raw_bytes + b'\x00' * (n * 2 - len(raw_bytes))

    # Read as big-endian uint16 (equivalent to byte-swapping LE pairs)
    pixels = np.frombuffer(raw_bytes, dtype='>u2').astype(np.uint16)

    # Extract R5G6B5 components and scale to 8-bit
    rgba = np.empty((n, 4), dtype=np.uint8)
    rgba[:, 0] = ((pixels >> 11) & 0x1F) * 255 // 31  # R
    rgba[:, 1] = ((pixels >> 5)  & 0x3F) * 255 // 63  # G
    rgba[:, 2] = ( pixels        & 0x1F) * 255 // 31  # B
    rgba[:, 3] = 255                                   # A

    img = QImage(rgba.tobytes(), w, h, w * 4, QImage.Format_RGBA8888)
    return img.copy()


def qimage_to_rgb565(qimg, w, h):
    """Fast QImage to RGB565 conversion using numpy."""
    qimg = qimg.convertToFormat(QImage.Format_RGBA8888)
    ptr = qimg.bits()
    # BUG-4 FIX: use bytesPerLine() to account for Qt row-stride padding.
    # ptr.setsize(w*h*4) would include row-end padding bytes as pixel data when
    # bytesPerLine() > w*4, producing shifted/corrupted colours on every replace.
    stride = qimg.bytesPerLine()
    ptr.setsize(stride * h)
    raw = np.frombuffer(bytes(ptr), dtype=np.uint8).reshape(h, stride)
    rgba = raw[:, :w * 4].reshape(h * w, 4)

    r = rgba[:, 0].astype(np.uint16)
    g = rgba[:, 1].astype(np.uint16)
    b = rgba[:, 2].astype(np.uint16)

    pixel = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    # Big-endian storage (byte-swapped format in firmware)
    data = np.empty(w * h * 2, dtype=np.uint8)
    data[0::2] = (pixel >> 8).astype(np.uint8)
    data[1::2] = (pixel & 0xFF).astype(np.uint8)
    return data.tobytes()


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

        # BUG-6 FIX: removed dead duplicate else-branch. The formula naturally
        # handles both cases (downsample and repeat) via integer division / modulo.
        indices = [int(i * total_video_frames / num_slots) % total_video_frames
                   for i in range(num_slots)]

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
    "D": ("Sky Blue",        "D_"),
    "E": ("Retro Gold",      "E_"),
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

# ---------------------------------------------------------------------------
# PROTECTED_THEME_KEYS — prefijos de tema que JAMÁS deben tocarse
# ---------------------------------------------------------------------------
# "P" — no es un tema real; P_GREENC0-9 son dígitos internos del Tema A.
# "T" — el prefijo T_ se usa para los fotogramas de arranque por tema
#        (T_B_POWERON0_, T_C_Z_POWERON1_, T_F_POWEROFF0_, …).
#        Si se usara como ranura de tema sobreescribiría esos datos de boot.
# ---------------------------------------------------------------------------
PROTECTED_THEME_KEYS: frozenset = frozenset({"P", "T"})

# ---------------------------------------------------------------------------
# _THEME_A_B_STARTS — recursos del Tema A que empiezan con 'B'
# ---------------------------------------------------------------------------
# El Tema B usa prefijo 'B' (sin guion bajo) para todos sus recursos.
# El Tema A también tiene recursos que empiezan con 'B' (BROWSER_, BTOFF_…);
# el firmware los distingue duplicando la 'B' en el Tema B (BBROWSER_, etc.).
# Esta lista permite que resource_matches_theme los diferencie correctamente.
# ---------------------------------------------------------------------------
_THEME_A_B_STARTS: frozenset = frozenset({
    'BROWSER_', 'BREAKPOINT_', 'BTOFF_', 'BTON_', 'BTOK_', 'BATTC',
})

# Base resource categories that are duplicated across themes
THEMED_CATEGORIES = ("MAINMENUPAGE", "MUSIC_", "BROWSER_", "USB_", "FM_", "RECORDER_")


def resource_matches_theme(name, prefix):
    """Return True if *name* belongs to the given theme prefix.

    Special cases handled:
    - prefix=''  (Theme A): excludes any name matching another theme's prefix,
      but correctly keeps Theme A's 30 'B'-starting resources (BROWSER_, etc.)
      which Theme B mirrors with double-'B' (BBROWSER_, BBREAKPOINT_, …).
      Also excludes XSTYLE_ entries for 'X_'-prefix themes (firmware quirk).
    - prefix='B' (Theme B): excludes Theme A's 'B'-starting resources so they
      don't pollute Theme B's resource panels.
    - 'X_' prefixes (C_, D_, E_, …): also matches XSTYLE_ entries which the
      firmware stores without the underscore (e.g. CSTYLE_, DSTYLE_).
    """
    if prefix == "":
        # Theme A = no prefix.  Must NOT start with any other theme's prefix.
        for _, (_, other_pfx) in THEMES.items():
            if not other_pfx:
                continue
            if name.startswith(other_pfx):
                # 'B' prefix overlaps Theme A resources (BROWSER_, BTOFF_, …).
                # Those are Theme A; Theme B mirrors them with 'BB' (BBROWSER_…).
                if other_pfx == 'B' and any(name.startswith(p) for p in _THEME_A_B_STARTS):
                    continue
                return False
            # Also exclude XSTYLE_ for 'X_' prefixes (firmware naming quirk:
            # CSTYLE_/DSTYLE_/ESTYLE_ omit the underscore in the STYLE entry).
            if (len(other_pfx) == 2 and other_pfx[1] == '_'
                    and name.startswith(other_pfx[0] + 'STYLE_')):
                return False
        return True

    # For prefix 'B': Theme A resources that start with 'B' are NOT Theme B.
    if prefix == 'B' and any(name.startswith(p) for p in _THEME_A_B_STARTS):
        return False

    if name.startswith(prefix):
        return True

    # For 'X_' prefixes: also match XSTYLE_ (firmware stores without underscore).
    if (len(prefix) == 2 and prefix[1] == '_'
            and name.startswith(prefix[0] + 'STYLE_')):
        return True

    return False


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
        self.setWindowTitle("Echo Mini Customizer v1.6 - Firmware Theme Editor")
        self.setMinimumSize(950, 750)
        self.firmware = None
        self.resources_by_name = {}
        self.all_res_images = []
        self.current_theme_key = "A"
        self.active_themes = {}  # populated after firmware load
        self._undo_stack = {}   # {res_name: [(raw_bytes, qimage), ...]} — max 5 levels

        self._build_ui()
        self.setAcceptDrops(True)
        QTimer.singleShot(0, self._auto_load)

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

        act_export = QAction("📤 Export Themes", self)
        act_export.triggered.connect(self._export_images)
        toolbar.addAction(act_export)

        act_import = QAction("📥 Import Theme", self)
        act_import.triggered.connect(self._import_theme)
        toolbar.addAction(act_import)

        act_import_img = QAction("📦 Import from IMG", self)
        act_import_img.triggered.connect(self._import_from_img)
        toolbar.addAction(act_import_img)

        act_undo = QAction("↩ Undo", self)
        act_undo.setShortcut("Ctrl+Z")
        act_undo.triggered.connect(lambda: self.undo_replace())
        toolbar.addAction(act_undo)

        act_patch = QAction("🔧 Patch Firmware", self)
        act_patch.triggered.connect(self._patch_firmware)
        toolbar.addAction(act_patch)

        act_expand= QAction("➕➖ Themes", self)
        act_expand.triggered.connect(self._expand_theme_slots)
        toolbar.addAction(act_expand)

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

        # Spacer to push size indicator to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.lbl_size = QLabel("  ")
        self.lbl_size.setMinimumWidth(260)
        self.lbl_size.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        toolbar.addWidget(self.lbl_size)

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

    # ------------------------------------------------------------------
    # Drag-and-drop support
    # ------------------------------------------------------------------
    def dragEnterEvent(self, event):
        """Accept drag if it contains exactly one local .IMG/.img/.bin file."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if len(urls) == 1 and urls[0].isLocalFile():
                ext = Path(urls[0].toLocalFile()).suffix.lower()
                if ext in (".img", ".bin"):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event):
        """Load the dropped firmware file."""
        path = event.mimeData().urls()[0].toLocalFile()
        self._load_firmware(path)

    def _auto_load(self):
        """On startup, immediately prompt the user to select a firmware file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Firmware to Open",
            str(get_app_dir()),
            "Firmware (*.IMG *.img *.bin);;All (*.*)"
        )
        if path:
            self._load_firmware(path)
        else:
            self.statusBar().showMessage(
                "No firmware loaded. Use 📂 Open Firmware to load a .IMG file."
            )

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

            _was_auto_patched = False
            resource_list = self.firmware.get_resource_list()
            # BUG-5 FIX: mark firmware as unsaved when auto-patch was applied so the user
            # knows the in-memory state differs from the file on disk.
            _suffix = " (⚠ no guardado)" if _was_auto_patched else ""
            self.lbl_status.setText(f" {Path(path).name} — {len(resource_list)} resources{_suffix}")

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
            # Apply firmware StrTbl display names (override hardcoded THEMES defaults)
            self._apply_strtbl_names()
            self._refresh_theme_combo()
            self._populate_panels()
            self._update_size_label()
            self.statusBar().showMessage(
                f"✓ Firmware loaded: {len(resource_list)} resources extracted from {Path(path).name}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load firmware:\n{e}")
            self.statusBar().showMessage("Error loading firmware")

    def _update_size_label(self):
        """Update the firmware size indicator in the toolbar."""
        if self.firmware is None:
            self.lbl_size.setText("  ")
            return
        LIMIT = 62 * 1024 * 1024
        SAFE  = 54 * 1024 * 1024   # last confirmed-safe size (HIFIEC20)
        RISKY = 60 * 1024 * 1024   # approaching confirmed-brick zone
        size = len(self.firmware.img_data)
        free = LIMIT - size
        size_mb = size / 1024 / 1024
        free_mb = free / 1024 / 1024
        if free < 0:
            color = "#cc0000"
            icon = "⛔"
            free_txt = f"¡{-free_mb:.1f} MB sobre el límite!"
        elif size > RISKY:
            color = "#cc0000"
            icon = "⚠"
            free_txt = f"{free_mb:.1f} MB — ¡ZONA DE BRICK!"
        elif size > SAFE:
            color = "#cc6600"
            icon = "⚠"
            free_txt = f"{free_mb:.1f} MB libres (zona de riesgo)"
        else:
            color = "#007700"
            icon = "✔"
            free_txt = f"{free_mb:.1f} MB libres"
        self.lbl_size.setText(
            f'<span style="color:{color}">{icon} {size_mb:.1f} / 62 MB  ({free_txt})</span>'
        )

        # Compute per-theme size breakdown for tooltip
        if self.all_res_images:
            theme_sizes = {}
            shared_size = 0
            for res, _ in self.all_res_images:
                sz = res.get('size', res['width'] * res['height'] * 2)
                rname = res['name']
                if res['index'] < 67:
                    shared_size += sz
                    continue
                placed = False
                for key in (self.active_themes or {}):
                    pfx = self.active_themes[key][1]
                    if pfx and rname.startswith(pfx):
                        theme_sizes[key] = theme_sizes.get(key, 0) + sz
                        placed = True
                        break
                if not placed:
                    theme_sizes["A"] = theme_sizes.get("A", 0) + sz
            lines = [f"Shared (idx 0–66): {shared_size/1024/1024:.2f} MB"]
            for key in sorted(theme_sizes):
                tname = (self.active_themes or {}).get(key, THEMES.get(key, ("?","")))[0]
                lines.append(f"  Tema {key} – {tname}: {theme_sizes[key]/1024/1024:.2f} MB")
            total_res = (shared_size + sum(theme_sizes.values())) / 1024 / 1024
            lines.append(f"Total recursos: {total_res:.2f} MB")
            self.lbl_size.setToolTip("\n".join(lines))
        else:
            self.lbl_size.setToolTip("")

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
                if key == "A" or key in PROTECTED_THEME_KEYS:
                    continue
                if prefix and name.startswith(prefix):
                    counts[key] = counts.get(key, 0) + 1
                    break
            else:
                counts["A"] = counts.get("A", 0) + 1

        for key, count in counts.items():
            # Nunca activar un tema protegido. "P" no es un tema real; sus
            # recursos (P_GREENC0-9) son dígitos internos del Tema A.
            if key in PROTECTED_THEME_KEYS:
                continue
            # Exigir mínimo 50 recursos para evitar falsos positivos:
            # los 10 P_GREENC pasarían el filtro de prefijo pero no son un tema.
            if count >= 50:
                self.active_themes[key] = THEMES[key]

    def _apply_strtbl_names(self):
        """Override active_themes display names with firmware StrTbl names.

        Called after _detect_active_themes() so that user-renamed names (saved
        to the StrTbl) are respected instead of the hardcoded THEMES defaults.
        Falls back to THEMES[key][0] when no StrTbl entry exists (e.g. newly
        added theme slots that have not been named yet).
        """
        if self.firmware is None:
            return
        theme_keys = list(THEMES.keys())
        for key in list(self.active_themes.keys()):
            pfx = THEMES[key][1]
            tidx = theme_keys.index(key) if key in theme_keys else -1
            if (self.firmware.theme_names
                    and 0 <= tidx < len(self.firmware.theme_names)
                    and self.firmware.theme_names[tidx]):
                display_name = self.firmware.theme_names[tidx]
            else:
                display_name = THEMES[key][0]
            self.active_themes[key] = (display_name, pfx)

    def _refresh_theme_combo(self):
        """Rebuild the theme ComboBox to show only active themes."""
        self.theme_combo.blockSignals(True)
        self.theme_combo.clear()
        # Map theme key (A-T) → index 0-19
        theme_keys = list(THEMES.keys())
        for key in theme_keys:
            if key not in self.active_themes:
                continue
            dict_name, prefix = self.active_themes[key]
            label = f"{key} – {dict_name}" + (f"  (prefix: {prefix})" if prefix else "  (no prefix)")
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
            # Update THEMES dict and active_themes with new display name
            THEMES[key] = (new_name, THEMES[key][1])
            if key in self.active_themes:
                self.active_themes[key] = (new_name, THEMES[key][1])
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

    def _show_replace_preview(self, res, current_qimg, new_qimg):
        """Show side-by-side preview of current vs new image before confirming replacement.
        Returns True if user confirms, False to cancel."""
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Confirm Replace: {res['name']}")
        dlg.setMinimumWidth(700)
        lay = QVBoxLayout(dlg)

        info_label = QLabel(
            f"Resource: <b>{res['name']}</b>  ({res['width']}×{res['height']} px, "
            f"index {res['index']})"
        )
        info_label.setTextFormat(Qt.RichText)
        lay.addWidget(info_label)

        compare_row = QHBoxLayout()

        # Current image panel
        left_col = QVBoxLayout()
        left_col.addWidget(QLabel("<b>Imagen actual (firmware)</b>", alignment=Qt.AlignCenter))
        lbl_cur = QLabel()
        lbl_cur.setAlignment(Qt.AlignCenter)
        lbl_cur.setMinimumSize(320, 170)
        pix_cur = QPixmap.fromImage(current_qimg).scaled(
            320, 170, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        lbl_cur.setPixmap(pix_cur)
        lbl_cur.setStyleSheet("border: 2px solid #666; background: #111;")
        left_col.addWidget(lbl_cur)
        compare_row.addLayout(left_col)

        # Arrow
        arrow = QLabel("  →  ")
        arrow.setAlignment(Qt.AlignCenter)
        arrow.setStyleSheet("font-size: 24px; color: #aaa;")
        compare_row.addWidget(arrow)

        # New image panel
        right_col = QVBoxLayout()
        right_col.addWidget(QLabel("<b>Nueva imagen (a importar)</b>", alignment=Qt.AlignCenter))
        lbl_new = QLabel()
        lbl_new.setAlignment(Qt.AlignCenter)
        lbl_new.setMinimumSize(320, 170)
        pix_new = QPixmap.fromImage(new_qimg).scaled(
            320, 170, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        lbl_new.setPixmap(pix_new)
        lbl_new.setStyleSheet("border: 2px solid #2a82da; background: #111;")
        right_col.addWidget(lbl_new)
        compare_row.addLayout(right_col)

        lay.addLayout(compare_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("✓ Confirmar reemplazo")
        buttons.button(QDialogButtonBox.Cancel).setText("✗ Cancelar")
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        return dlg.exec_() == QDialog.Accepted

    def replace_resource(self, res, callback=None):
        """Open file dialog to replace a firmware resource image."""
        # Bloquear sobreescritura de recursos protegidos.
        # Los prefijos en PROTECTED_THEME_KEYS no son temas reales; por ejemplo
        # P_GREENC0-9 son los dígitos del contador del reproductor (Tema A).
        # Sobreescribirlos corrompería la UI sin añadir ningún tema nuevo.
        for key in PROTECTED_THEME_KEYS:
            pfx = THEMES[key][1]
            if pfx and res['name'].startswith(pfx):
                QMessageBox.warning(
                    self, "Protected Resource",
                    f"'{res['name']}' is a protected system resource (Theme {key}) "
                    f"and cannot be overwritten.\n\n"
                    f"These are internal UI digits used by the firmware."
                )
                return

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
                self, "⚠ Dimensiones diferentes",
                f"La imagen seleccionada tiene dimensiones distintas al recurso:\n\n"
                f"  Imagen importada:   {new_img.width()} × {new_img.height()} px\n"
                f"  Recurso en firmware: {res['width']} × {res['height']} px\n\n"
                f"Se redimensionará con suavizado bicúbico.\n"
                f"Para mejor calidad, exporta el recurso original y edita sobre él.\n\n"
                f"¿Continuar con el redimensionado?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            new_img = new_img.scaled(
                res['width'], res['height'],
                Qt.IgnoreAspectRatio, Qt.SmoothTransformation
            )

        # Side-by-side preview before confirming
        current_qimg = self.resources_by_name[res['name']][1] if res['name'] in self.resources_by_name else None
        if current_qimg is not None:
            if not self._show_replace_preview(res, current_qimg, new_img):
                return

        # Save current state to undo stack (max 5 levels)
        cur_entry = self.resources_by_name.get(res['name'])
        if cur_entry:
            _, cur_img = cur_entry
            if res['name'] not in self._undo_stack:
                self._undo_stack[res['name']] = []
            raw_copy = bytes(self.firmware.img_data[res['offset']:res['offset']+res['size']])
            self._undo_stack[res['name']].append((raw_copy, cur_img.copy()))
            if len(self._undo_stack[res['name']]) > 5:
                self._undo_stack[res['name']].pop(0)
        self._last_replaced_res = res['name']

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

    def undo_replace(self, res_name=None):
        """Undo the last image replacement. If res_name is None, use current selected resource."""
        if res_name is None:
            res_name = getattr(self, '_last_replaced_res', None)
        if res_name is None or res_name not in self._undo_stack or not self._undo_stack[res_name]:
            self.statusBar().showMessage("Nada que deshacer")
            return
        raw_bytes, prev_qimg = self._undo_stack[res_name].pop()
        # Find the resource entry
        res = None
        for r, _ in self.all_res_images:
            if r['name'] == res_name:
                res = r
                break
        if res is None:
            return
        # Restore raw bytes in firmware
        off = res['offset']
        self.firmware.img_data[off:off + len(raw_bytes)] = bytearray(raw_bytes)
        # Update cache
        self.resources_by_name[res_name] = (res, prev_qimg)
        for i, (r, _) in enumerate(self.all_res_images):
            if r['name'] == res_name:
                self.all_res_images[i] = (res, prev_qimg)
                break
        self.statusBar().showMessage(
            f"↩ Reemplazado deshecho: {res_name}  ({len(self._undo_stack[res_name])} niveles restantes)")
        self._update_size_label()

    def _export_images(self):
        """Show dialog to export images by theme or all."""
        if not self.firmware or not self.all_res_images:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Export Themes")
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
        import json as _json
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
        manifest = {
            "echo_mini_theme_export": True,
            "version": "1.0",
            "theme_key": theme_key,
            "theme_name": name,
            "theme_prefix": prefix,
            "firmware": str(self.firmware.img_path.name) if self.firmware else "",
            "resource_count": 0,
            "resources": []
        }

        from PyQt5.QtWidgets import QProgressDialog
        prog = QProgressDialog(
            f"Exporting theme {theme_key}...", "Cancel", 0, len(self.all_res_images), self)
        prog.setWindowTitle("Export Theme")
        prog.setWindowModality(Qt.WindowModal)
        prog.setMinimumDuration(0)

        for idx, (res, img) in enumerate(self.all_res_images):
            prog.setValue(idx)
            prog.setLabelText(f"Exportando {idx+1}/{total}: {res['name']}")
            QApplication.processEvents()
            if prog.wasCanceled():
                break

            rname = res['name']
            is_shared = res['index'] < 67
            is_themed = resource_matches_theme(rname, prefix)
            is_themed_boot = tboot and rname.startswith(tboot)

            if not is_shared and not is_themed and not is_themed_boot:
                continue

            safe_name = rname.strip().replace('.BMP', '').strip().replace('/', '_').replace('\\', '_')
            fname = f"{res['index']:04d}_{safe_name}.png"
            pixmap = QPixmap.fromImage(img)


            if is_shared or is_themed_boot:
                dest_folder = "Boot"
                pixmap.save(str(boot_dir / fname), "PNG")
            else:
                dest_folder = "UI"
                pixmap.save(str(ui_dir / fname), "PNG")
            exported += 1

            manifest["resources"].append({
                "index": res['index'],
                "name": rname,
                "file": fname,
                "folder": dest_folder,
                "width": res['width'],
                "height": res['height'],
                "is_shared": is_shared,
                "is_themed_boot": bool(is_themed_boot),
            })

        prog.setValue(total)
        manifest["resource_count"] = exported
        manifest_path = out_dir / "manifest.json"
        with open(str(manifest_path), "w", encoding="utf-8") as f:
            _json.dump(manifest, f, indent=2, ensure_ascii=False)

        self.statusBar().showMessage(
            f"✓ Exported {exported} images from theme {theme_key} to {out_dir.name}/")
        QMessageBox.information(
            self, "Export Complete",
            f"{exported} images exported to:\n{out_dir}\n\n"
            f"Structure:\n"
            f"  Boot/ — POWERON, POWEROFF, CHARGELEVEL, etc.\n"
            f"  UI/ — Menu, player, folders, USB, etc.\n\n"
            f"📋 manifest.json incluido — permite re-importar exactamente estos recursos.")

    def _do_export_all(self, base_folder):
        """Export ALL resources organized by theme into subfolders."""
        import json as _json
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

        # Per-theme manifests
        manifests = {"_shared": {
            "echo_mini_theme_export": True,
            "version": "1.0",
            "theme_key": "Shared",
            "theme_name": "Shared Resources",
            "theme_prefix": "",
            "firmware": str(self.firmware.img_path.name) if self.firmware else "",
            "resource_count": 0,
            "resources": []
        }}
        for key in active_keys:
            manifests[key] = {
                "echo_mini_theme_export": True,
                "version": "1.0",
                "theme_key": key,
                "theme_name": self.active_themes[key][0],
                "theme_prefix": self.active_themes[key][1],
                "firmware": str(self.firmware.img_path.name) if self.firmware else "",
                "resource_count": 0,
                "resources": []
            }

        # Progress dialog
        from PyQt5.QtWidgets import QProgressDialog
        total = len(self.all_res_images)
        prog = QProgressDialog("Exporting all resources...", "Cancel", 0, total, self)
        prog.setWindowTitle("Export All")
        prog.setWindowModality(Qt.WindowModal)
        prog.setMinimumDuration(0)

        exported = 0
        for idx, (res, img) in enumerate(self.all_res_images):
            prog.setValue(idx)
            prog.setLabelText(f"Exporting {idx+1}/{total}: {res['name']}")
            QApplication.processEvents()
            if prog.wasCanceled():
                break

            rname = res['name']
            safe_name = rname.strip().replace('.BMP', '').strip().replace('/', '_').replace('\\', '_')
            fname = f"{res['index']:04d}_{safe_name}.png"
            pixmap = QPixmap.fromImage(img)

            if res['index'] < 67:
                pixmap.save(str(shared_dir / fname), "PNG")
                manifests["_shared"]["resources"].append({
                    "index": res['index'], "name": rname, "file": fname,
                    "folder": "Shared", "width": res['width'], "height": res['height'],
                    "is_shared": True, "is_themed_boot": False,
                })
            else:
                placed = False
                for key in active_keys:
                    pfx = self.active_themes[key][1]
                    if pfx and rname.startswith(pfx):
                        pixmap.save(str(theme_dirs[key] / fname), "PNG")
                        manifests[key]["resources"].append({
                            "index": res['index'], "name": rname, "file": fname,
                            "folder": f"Theme_{key}", "width": res['width'], "height": res['height'],
                            "is_shared": False, "is_themed_boot": False,
                        })
                        placed = True
                        break
                if not placed and "A" in theme_dirs:
                    pixmap.save(str(theme_dirs["A"] / fname), "PNG")
                    manifests["A"]["resources"].append({
                        "index": res['index'], "name": rname, "file": fname,
                        "folder": "Theme_A", "width": res['width'], "height": res['height'],
                        "is_shared": False, "is_themed_boot": False,
                    })
            exported += 1

        prog.setValue(total)

        # Write manifests
        manifests["_shared"]["resource_count"] = len(manifests["_shared"]["resources"])
        with open(str(shared_dir / "manifest.json"), "w", encoding="utf-8") as f:
            _json.dump(manifests["_shared"], f, indent=2, ensure_ascii=False)
        for key in active_keys:
            manifests[key]["resource_count"] = len(manifests[key]["resources"])
            with open(str(theme_dirs[key] / "manifest.json"), "w", encoding="utf-8") as f:
                _json.dump(manifests[key], f, indent=2, ensure_ascii=False)

        theme_list = "\n".join(f"  Theme_{k}/ — {self.active_themes[k][0]}" for k in active_keys)
        self.statusBar().showMessage(
            f"✓ Exported {exported} images to {out_dir.name}/")
        QMessageBox.information(
            self, "Export Complete",
            f"{exported} images exported to:\n{out_dir}\n\n"
            f"Structure:\n"
            f"  Shared/ — Boot/charge resources (0-66)\n"
            f"{theme_list}\n\n"
            f"📋 manifest.json en cada carpeta — permite re-importar exactamente.")

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
        all_keys = [k for k in THEMES if k not in PROTECTED_THEME_KEYS]
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

        # ── Auto-expand if the target slot exceeds current firmware capacity ──
        try:
            current_n = self.firmware.detect_theme_count()
        except Exception:
            current_n = 5

        # target_idx is 0-based (A=0, B=1, …); firmware supports slots 0..current_n-1
        needed_n = target_idx + 1
        if needed_n > current_n:
            reply = QMessageBox.question(
                self,
                "Expandir temas",
                f"El slot elegido (Tema {target_key}, posición {target_idx}) "
                f"supera el límite actual ({current_n} temas).\n\n"
                f"¿Expandir el firmware de {current_n} → {needed_n} temas "
                f"automáticamente?\n\n"
                f"Se inyectará un code cave en el ARM del firmware para soportar "
                f"los nuevos slots.",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            try:
                self.statusBar().showMessage(f"Expandiendo firmware a {needed_n} temas...")
                QApplication.processEvents()
                result = self.firmware.expand_theme_count(needed_n)
                # Rebuild resource lookup after expansion using get_resource_list()
                # (NOT self.firmware.entries directly — that uses raw metadata indices
                # which are off-by-misalignment vs the correct R26 indices)
                self.all_res_images = []
                self.resources_by_name = {}
                for res in self.firmware.get_resource_list():
                    img = self.firmware.extract_image(res)
                    self.all_res_images.append((res, img))
                    self.resources_by_name[res['name']] = (res, img)
                self._detect_active_themes()
                self._apply_strtbl_names()
                self._refresh_theme_combo()
                self._update_size_label()
                self.statusBar().showMessage(
                    f"✓ Firmware expandido a {needed_n} temas")
            except Exception as ex:
                QMessageBox.critical(self, "Error al expandir",
                                     f"No se pudo expandir el firmware:\n{ex}")
                return

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
                        # Fallback: some resources use concatenated prefix (CSTYLE not C_STYLE)
                        if match is None and target_prefix and target_prefix.endswith('_'):
                            alt_remapped = target_prefix[:-1] + stripped
                            match = name_to_res.get(alt_remapped.upper())
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
        self._apply_strtbl_names()
        self._refresh_theme_combo()
        self._populate_panels()
        self._update_size_label()

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
        """Apply the themed-boot patch (CMP + ADDW + table expansion)."""
        if not self.firmware:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return
        try:
            info = self.firmware.detect_patch_info()
        except ValueError as e:
            QMessageBox.critical(self, "Detection Failed", str(e))
            return

        if info['is_patched']:
            QMessageBox.information(self, "Ya parcheado",
                "El firmware ya tiene el parche de boots temáticos aplicado.")
            return

        reply = QMessageBox.question(
            self, "Patch Firmware",
            "Este parche activa las pantallas de inicio y apagado por tema.\n\n"
            "¿Qué hace?\n"
            "• Cada tema tendrá su propia pantalla de arranque y apagado.\n"
            "• Se adaptan las tablas internas del firmware para 5 temas.\n"
            "• El firmware queda listo para añadir recursos personalizados por tema.\n\n"
            "El cambio se realiza en memoria. Usa 'Save As' para guardarlo en disco.",
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel
        )
        if reply != QMessageBox.Ok:
            return

        prog_bar = QProgressBar(self)
        prog_bar.setRange(0, 100)
        self.statusBar().addPermanentWidget(prog_bar)
        prog_bar.show()

        try:
            self.statusBar().showMessage("Aplicando parche de boots temáticos...")
            QApplication.processEvents()
            result = self.firmware.patch_for_themed_boots(
                progress_callback=lambda p: (prog_bar.setValue(p),
                                             QApplication.processEvents()))

            # Refresh UI from in-memory patched firmware
            resource_list = self.firmware.get_resource_list()
            self.lbl_status.setText(
                f" {self.firmware.img_path.name} — {len(resource_list)} resources (⚠ no guardado)")
            self.all_res_images = []
            self.resources_by_name = {}
            total = len(resource_list)
            for idx, res in enumerate(resource_list):
                if idx % 50 == 0:
                    self.statusBar().showMessage(f"Recargando recursos... {idx}/{total}")
                    QApplication.processEvents()
                img = self.firmware.extract_image(res)
                self.all_res_images.append((res, img))
                self.resources_by_name[res['name']] = (res, img)

            self._detect_active_themes()
            self._apply_strtbl_names()
            self._refresh_theme_combo()
            self._populate_panels()

            QMessageBox.information(self, "Parche Aplicado", result)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo parchear:\n{e}")
        finally:
            self.statusBar().removeWidget(prog_bar)

    def _import_from_img(self):
        """Import ALL themes from another .IMG firmware file (replaces current Part5)."""
        if not self.firmware:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        path, _ = QFileDialog.getOpenFileName(
            self, "Select source firmware .IMG",
            str(self.firmware.img_path.parent),
            "Firmware (*.IMG *.img);;All (*.*)")
        if not path:
            return

        # Peek at source to show info in confirmation dialog
        try:
            src_peek = FirmwareParser(path)
            src_n  = max(5, src_peek.rock26_count // 374)
            src_mb = src_peek.part5_size / 1024 / 1024
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo leer el firmware fuente:\n{e}")
            return

        # Warn if source Part5 is too large and would exceed the 57 MB firmware limit
        MAX_SAFE_P5_MB = 43.5
        if src_mb > MAX_SAFE_P5_MB:
            QMessageBox.critical(
                self, "⚠ Part5 demasiado grande — RIESGO DE BRICK",
                f"La Part5 del firmware fuente mide <b>{src_mb:.1f} MB</b>.<br><br>"
                f"El límite seguro del Echo Mini es ~43 MB de Part5 (firmware ≤ 57 MB total).<br>"
                f"HIFIEC22 tuvo una Part5 de {src_mb:.0f} MB → firmware de 62 MB → <b>BRICK</b>.<br><br>"
                f"<b>NO importes desde esta fuente.</b><br>"
                f"Usa HIFIEC20 (43.4 MB Part5) o HIFIEC320 (21.9 MB Part5) como fuente segura."
            )
            return

        reply = QMessageBox.question(
            self, "Confirmar importación",
            f"<b>Fuente:</b> {Path(path).name}<br>"
            f"<b>Temas detectados:</b> {src_n} &nbsp;|&nbsp; "
            f"<b>Part5:</b> {src_mb:.1f} MB<br><br>"
            f"⚠ Esto reemplazará <b>TODOS</b> los temas del firmware actual "
            f"con los del archivo fuente.<br>"
            f"El código ARM y el trailer del firmware base se conservan.<br><br>"
            f"¿Continuar?",
            QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return

        prog_bar = QProgressBar(self)
        prog_bar.setRange(0, 100)
        self.statusBar().addPermanentWidget(prog_bar)
        prog_bar.show()

        def on_progress(p):
            prog_bar.setValue(p)
            QApplication.processEvents()

        try:
            result = self.firmware.import_themes_from_img(path, progress_callback=on_progress)

            # Refresh UI
            resource_list = self.firmware.get_resource_list()
            self.lbl_status.setText(
                f" {self.firmware.img_path.name} — "
                f"{len(resource_list)} resources (⚠ no guardado)")
            self.all_res_images  = []
            self.resources_by_name = {}
            total = len(resource_list)
            for idx, res in enumerate(resource_list):
                if idx % 50 == 0:
                    self.statusBar().showMessage(
                        f"Recargando recursos... {idx}/{total}")
                    QApplication.processEvents()
                img = self.firmware.extract_image(res)
                self.all_res_images.append((res, img))
                self.resources_by_name[res['name']] = (res, img)

            self._detect_active_themes()
            self._apply_strtbl_names()
            self._refresh_theme_combo()
            self._populate_panels()
            QMessageBox.information(self, "Importación Completa", result)
            self._apply_theme()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Importación fallida:\n{e}")
        finally:
            self.statusBar().removeWidget(prog_bar)

    def _expand_theme_slots(self):
        """Add or remove theme slots in the firmware."""
        if not self.firmware:
            QMessageBox.warning(self, "No Firmware", "First load a firmware .IMG file")
            return

        try:
            current_n = self.firmware.detect_theme_count()
            cave_ok   = self.firmware.is_cave_dispatched()
        except ValueError as e:
            QMessageBox.critical(self, "Detection Failed", str(e))
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("➕➖ Add / Remove Theme Slots")
        dlg.setMinimumWidth(480)
        lay = QVBoxLayout(dlg)

        lay.addWidget(QLabel(f"<b>Temas actuales en el firmware: {current_n}</b>"))
        lay.addWidget(QLabel(
            f"Dispatch: {'Code Cave (expandido)' if cave_ok else 'ADDW original (máx 5)'}"))
        lay.addWidget(QLabel(""))
        lay.addWidget(QLabel("Selecciona el número <b>total</b> de temas deseado:"))
        lay.addWidget(QLabel(
            "  • Mínimo: 5 (A–E, dispatch ADDW estándar)\n"
            "  • Máximo: 11 (A–K, requiere code cave ARM)\n"
            "  Bajar del número actual <b>elimina</b> los últimos slots.\n"
            "  Los datos de temas eliminados quedan inactivos en el archivo."))

        from PyQt5.QtWidgets import QSpinBox
        spin = QSpinBox()
        spin.setMinimum(5)
        spin.setMaximum(11)
        spin.setValue(current_n)          # start at current so user can go up OR down
        lay.addWidget(spin)

        lbl_action = QLabel("")
        lay.addWidget(lbl_action)

        def _update_label(val):
            if val > current_n:
                lbl_action.setText(
                    f"<span style='color:#4caf50'>➕ Añadir {val - current_n} tema(s): "
                    f"{'ABCDEFGHIJKLMNOPQRST'[current_n:val]}</span>")
            elif val < current_n:
                lbl_action.setText(
                    f"<span style='color:#f44336'>➖ Eliminar {current_n - val} tema(s): "
                    f"{'ABCDEFGHIJKLMNOPQRST'[val:current_n]}</span>")
            else:
                lbl_action.setText("<i>Sin cambios</i>")

        spin.valueChanged.connect(_update_label)
        _update_label(current_n)

        lay.addWidget(QLabel(""))
        lay.addWidget(QLabel(
            "⚠ Los cambios se aplican en memoria.\n"
            "Guarda con 'Save As' para escribir el archivo resultante."))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            return

        target_n = spin.value()
        if target_n == current_n:
            return

        prog_bar = QProgressBar(self)
        prog_bar.setRange(0, 100)
        self.statusBar().addPermanentWidget(prog_bar)
        prog_bar.show()

        def on_progress(p):
            prog_bar.setValue(p)
            QApplication.processEvents()

        try:
            if target_n > current_n:
                self.statusBar().showMessage(f"Expandiendo a {target_n} temas...")
                QApplication.processEvents()
                result = self.firmware.expand_theme_count(target_n, progress_callback=on_progress)
                title = "Expansión Completa"
            else:
                self.statusBar().showMessage(f"Reduciendo a {target_n} temas...")
                QApplication.processEvents()
                result = self.firmware.shrink_theme_count(target_n, progress_callback=on_progress)
                title = "Reducción Completa"

            # Refresh UI from the modified in-memory firmware
            resource_list = self.firmware.get_resource_list()
            self.lbl_status.setText(
                f" {self.firmware.img_path.name} — {len(resource_list)} resources (⚠ no guardado)")
            self.all_res_images = []
            self.resources_by_name = {}
            total = len(resource_list)
            for idx, res in enumerate(resource_list):
                if idx % 50 == 0:
                    self.statusBar().showMessage(f"Recargando recursos... {idx}/{total}")
                    QApplication.processEvents()
                img = self.firmware.extract_image(res)
                self.all_res_images.append((res, img))
                self.resources_by_name[res['name']] = (res, img)

            self._detect_active_themes()
            self._apply_strtbl_names()
            self._refresh_theme_combo()
            self._populate_panels()
            self._update_size_label()

            QMessageBox.information(self, title, result)
            self._apply_theme()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cambiar el número de temas:\n{e}")
        finally:
            self.statusBar().removeWidget(prog_bar)


    def _save_firmware(self):
        if not self.firmware:
            return
        try:
            orig_path = self.firmware.img_path.with_suffix(
                self.firmware.img_path.suffix + ".orig")
            if not orig_path.exists():
                import shutil
                shutil.copy2(str(self.firmware.img_path), str(orig_path))
                QMessageBox.information(
                    self, "Backup creado",
                    f"Se creó una copia de seguridad automática:\n{orig_path.name}\n\n"
                    f"Puedes restaurar el firmware original renombrando ese archivo."
                )
            self.firmware.save()
            self.statusBar().showMessage("✓ Firmware guardado correctamente")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar:\n{e}")

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
