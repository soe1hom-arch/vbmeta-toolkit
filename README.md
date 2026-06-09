# VBMeta Toolkit v1.0

**Android Verified Boot Image Manipulator**  
*By. soe1hom-arch / Wandi*

Tool untuk memeriksa dan memodifikasi vbmeta image (Verified Boot Metadata) dari firmware Android. Diadaptasi dari AOSP `avbtool.py` (platform/external/avb).

## Fitur

- **Info vbmeta** — Lihat header, flags, algoritma, descriptor
- **Patch vbmeta** — Nonaktifkan AVB verification & dm-verity
- **Check all** — Periksa semua vbmeta image dalam satu tampilan
- **Export** — Simpan informasi vbmeta ke file teks

## Cara Pakai

```bash
cd py-vbmeta-tool
python main.py
```

### Menu

```
[1] Info vbmeta image       — Lihat detail vbmeta
[2] Patch vbmeta            — Disable verity/verification
[3] Check all vbmeta        — Cek status semua vbmeta
[4] Export vbmeta info      — Simpan info ke file .txt
[5] Exit
```

### Untuk disable verified boot (unlock bootloader):

1. Letakkan `vbmeta.img` di folder `input/`
2. Pilih menu [2] → pilih file → pilih [3] disable both
3. Hasil di `output/vbmeta-noverification-noverity.img`
4. Flash via fastboot: `fastboot flash vbmeta output/vbmeta-noverification-noverity.img`

## Format VBMeta

```
+-----------------------------+
| Header (256 bytes)          |
|  - magic "AVB0"             |
|  - flags (verity/verifikasi)|
|  - rollback index           |
|  - release string           |
+-----------------------------+
| Authentication Data (opsional)|
|  - hash / signature         |
|  - public key               |
+-----------------------------+
| Auxiliary Data              |
|  - hash descriptors         |
|  - hashtree descriptors     |
+-----------------------------+
```

## Build Binary

```bash
pip install pyinstaller
pyinstaller --onefile main.py -n vbmeta-tool
./dist/vbmeta-tool
```

## Sumber

- AOSP `platform/external/avb` — Format vbmeta
- AOSP `system/core/fs_mgr/avbtool.py` — Referensi implementasi

## Lisensi

MIT License
