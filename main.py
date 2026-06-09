# ============================================================
# VBMeta Toolkit v1.0
# Android Verified Boot Image Manipulator
# Adapted from AOSP system/core/fs_mgr/avbtool.py
# By. soe1hom-arch / Wandi
# ============================================================
#
# Tools untuk memeriksa, memodifikasi, dan menandatangani
# vbmeta image (Verified Boot Metadata) dari Android.
#
# Sumber kode diadaptasi dari:
#   https://android.googlesource.com/platform/external/avb/
#   https://android.googlesource.com/platform/system/core/+/refs/heads/master/fs_mgr/avbtool.py
#
# Fitur:
#   - Parse vbmeta.img, vbmeta_vendor.img, vbmeta_system.img
#   - Lihat header, flags, descriptor, signature
#   - Nonaktifkan verified boot (disable verity & verification)
#   - Cek status vbmeta (amankah? sudah di-patch?)
#   - Export info vbmeta ke file teks

import sys
import os
from pathlib import Path

# Tambahkan root project ke path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.avb import (
    VBMetaImage,
    VBMetaHeader,
    patch_vbmeta,
    FLAG_VERIFICATION_DISABLED,
    FLAG_VERITY_DISABLED,
    ALGORITHM_NAMES,
    AVB_MAGIC,
)
from modules.common import (
    INPUT_DIR,
    OUTPUT_DIR,
    ensure_workspace,
    OperationResult,
)


# =========================================================
# COLORS
# =========================================================

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


# =========================================================
# BANNER
# =========================================================

APP_VERSION = "1.0"


def show_header(title=""):
    print(f"{GREEN}=============================={RESET}")
    if title:
        print(f"{CYAN}   {title}{RESET}")
    print(f"{YELLOW}   VBMeta Toolkit v{APP_VERSION}{RESET}")
    print(f"{YELLOW}   By. soe1hom-arch / Wandi{RESET}")
    print(f"{GREEN}=============================={RESET}")


def show_banner():
    print(f"""
{GREEN}╔══════════════════════════════════════════════╗
║        {CYAN}ANDROID VBMETA TOOLKIT{RESET}{GREEN}             ║
║        {CYAN}AOSP Verified Boot Manipulator{RESET}{GREEN}     ║
║        {YELLOW}v{APP_VERSION} — By. soe1hom-arch / Wandi{RESET}{GREEN}   ║
╚══════════════════════════════════════════════╝{RESET}
""")


# =========================================================
# HELPERS
# =========================================================

def find_vbmeta_images():
    """Cari file vbmeta di input/ dan direktori saat ini."""
    candidates = []
    search_dirs = [INPUT_DIR, Path(".")]
    
    for folder in search_dirs:
        if folder.exists():
            for f in folder.iterdir():
                if f.is_file() and ("vbmeta" in f.name.lower()) and f.suffix.lower() == ".img":
                    candidates.append(f)
    
    return sorted(set(candidates))


def choose_vbmeta(prompt="Pilih vbmeta image:") -> Path | None:
    candidates = find_vbmeta_images()
    
    if not candidates:
        print(f"\n{RED}[✗] Tidak ada vbmeta image ditemukan!{RESET}")
        print(f"{YELLOW}  Letakkan file vbmeta*.img di folder input/{RESET}")
        return None
    
    print(f"\n{CYAN}{prompt}{RESET}\n")
    for idx, img in enumerate(candidates, 1):
        size_mb = img.stat().st_size / (1024 * 1024)
        print(f"  [{idx}] {img.name}  ({size_mb:.3f} MB)")
    
    try:
        choice = int(input("\nPilih nomor : ").strip())
        if 1 <= choice <= len(candidates):
            return candidates[choice - 1]
        print(f"{RED}[✗] Pilihan tidak valid.{RESET}")
        return None
    except (ValueError, EOFError):
        print(f"{RED}[✗] Input tidak valid.{RESET}")
        return None


def print_result(result: OperationResult):
    if result.ok:
        print(f"\n{GREEN}[✓] {result.title}: {result.message}{RESET}")
    else:
        print(f"\n{RED}[✗] {result.title}: {result.message}{RESET}")
    if result.output_path:
        print(f"  Output: {result.output_path}")


# =========================================================
# MENU 1: INFO VBMETA
# =========================================================

def menu_info():
    show_header("VBmeta Info")
    image = choose_vbmeta("Pilih vbmeta untuk diperiksa:")
    if not image:
        input(f"\n{YELLOW}Press Enter...{RESET}")
        return
    
    try:
        vbmeta = VBMetaImage.load(image)
        print(f"\n{GREEN}{'='*50}{RESET}")
        print(vbmeta.info_text())
        print(f"{GREEN}{'='*50}{RESET}")
    except Exception as e:
        print(f"\n{RED}[✗] Gagal memuat vbmeta: {e}{RESET}")
    
    input(f"\n{YELLOW}Press Enter...{RESET}")


# =========================================================
# MENU 2: DISABLE VERIFICATION
# =========================================================

def menu_disable_verification():
    show_header("Disable AVB Verification")
    image = choose_vbmeta("Pilih vbmeta untuk di-patch:")
    if not image:
        input(f"\n{YELLOW}Press Enter...{RESET}")
        return
    
    print(f"\n{YELLOW}Pilih opsi patch:{RESET}")
    print(f"  {CYAN}[1]{RESET} Disable verification only (bit 0)")
    print(f"  {CYAN}[2]{RESET} Disable verity only (bit 1)")
    print(f"  {CYAN}[3]{RESET} Disable BOTH (verification + verity)")
    
    try:
        choice = input("\nPilih [1/2/3]: ").strip()
    except EOFError:
        return
    
    disable_verification = choice in ("1", "3")
    disable_verity = choice in ("2", "3")
    
    if not disable_verification and not disable_verity:
        print(f"\n{RED}[✗] Tidak ada perubahan yang dipilih.{RESET}")
        input(f"\n{YELLOW}Press Enter...{RESET}")
        return
    
    try:
        # Load dulu untuk info
        vbmeta = VBMetaImage.load(image)
        
        # Buat nama output
        stem = image.stem
        suffix = ""
        if disable_verification:
            suffix += "-noverification"
        if disable_verity:
            suffix += "-noverity"
        output_name = f"{stem}{suffix}.img"
        output_path = OUTPUT_DIR / output_name
        
        result = patch_vbmeta(
            image, output_path,
            disable_verity=disable_verity,
            disable_verification=disable_verification,
        )
        
        print(f"\n{GREEN}[✓] vbmeta berhasil di-patch!{RESET}")
        print(f"  {'Flags sebelum':30s}: 0x{result['old_flags']:016x}")
        print(f"  {'Flags sesudah':30s}: 0x{result['new_flags']:016x}")
        print(f"  {'Verification':30s}: {YELLOW if result['old_verification'] else GREEN}ENABLED{RESET} → {RED if not result['new_verification'] else GREEN}{'DISABLED' if result['new_verification'] else 'ENABLED'}{RESET}")
        print(f"  {'Verity':30s}: {YELLOW if result['old_verity'] else GREEN}ENABLED{RESET} → {RED if not result['new_verity'] else GREEN}{'DISABLED' if result['new_verity'] else 'ENABLED'}{RESET}")
        print(f"  {'Output':30s}: {result['output']}")
        print(f"  {'Ukuran':30s}: {result['size']} bytes")
        
    except Exception as e:
        print(f"\n{RED}[✗] Gagal patch vbmeta: {e}{RESET}")
    
    input(f"\n{YELLOW}Press Enter...{RESET}")


# =========================================================
# MENU 3: CHECK ALL VBMETA
# =========================================================

def menu_check_all():
    show_header("Check All VBmeta")
    
    images = find_vbmeta_images()
    if not images:
        print(f"\n{YELLOW}[!] Tidak ada vbmeta image ditemukan.{RESET}")
        print(f"{YELLOW}  Letakkan file di folder input/{RESET}")
        input(f"\n{YELLOW}Press Enter...{RESET}")
        return
    
    print(f"\n{CYAN}Memeriksa {len(images)} vbmeta image(s)...{RESET}\n")
    
    for img in images:
        try:
            vbmeta = VBMetaImage.load(img)
            size_mb = img.stat().st_size / (1024 * 1024)
            
            status = f"{GREEN}[OK]{RESET}"
            warnings = []
            
            if vbmeta.flags & FLAG_VERIFICATION_DISABLED:
                warnings.append("NO_VERIFICATION")
            if vbmeta.flags & FLAG_VERITY_DISABLED:
                warnings.append("NO_VERITY")
            
            if warnings:
                status = f"{RED}[PATCHED - {', '.join(warnings)}]{RESET}"
            elif vbmeta.algorithm_type != 0:
                status = f"{GREEN}[LOCKED - signed]{RESET}"
            else:
                status = f"{YELLOW}[UNLOCKED - no signature]{RESET}"
            
            print(f"  {img.name:35s} {size_mb:6.2f} MB  {status}")
            print(f"  {'':35s} Flags: 0x{vbmeta.header.flags:016x} | AVB {vbmeta.header.major_version}.{vbmeta.header.minor_version} | {vbmeta.header.algorithm_name}")
            if vbmeta.descriptors:
                for desc in vbmeta.descriptors:
                    print(f"  {'':35s} ├─ {desc.summary()}: {desc.partition_name}")
            print()
            
        except Exception as e:
            print(f"  {img.name:35s} {RED}[ERROR] {e}{RESET}\n")
    
    input(f"\n{YELLOW}Press Enter...{RESET}")


# =========================================================
# MENU 4: EXPORT VBMETA INFO
# =========================================================

def menu_export():
    show_header("Export VBMeta Info to Text")
    image = choose_vbmeta("Pilih vbmeta untuk diexport:")
    if not image:
        input(f"\n{YELLOW}Press Enter...{RESET}")
        return
    
    try:
        vbmeta = VBMetaImage.load(image)
        output_txt = OUTPUT_DIR / f"{image.stem}_info.txt"
        output_txt.write_text(vbmeta.info_text(), encoding="utf-8")
        print(f"\n{GREEN}[✓] Info vbmeta berhasil diexport!{RESET}")
        print(f"  Output: {output_txt}")
    except Exception as e:
        print(f"\n{RED}[✗] Gagal export: {e}{RESET}")
    
    input(f"\n{YELLOW}Press Enter...{RESET}")


# =========================================================
# MAIN MENU
# =========================================================

def main():
    ensure_workspace()
    
    while True:
        show_banner()
        print(f"""
{CYAN}[1]{RESET} Info vbmeta image
{CYAN}[2]{RESET} Patch vbmeta (disable verity/verification)
{CYAN}[3]{RESET} Check all vbmeta images
{CYAN}[4]{RESET} Export vbmeta info to file
{CYAN}[5]{RESET} Exit
""")
        
        try:
            choice = input("Select Menu : ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        if choice == "1":
            menu_info()
        elif choice == "2":
            menu_disable_verification()
        elif choice == "3":
            menu_check_all()
        elif choice == "4":
            menu_export()
        elif choice == "5":
            print(f"\n{CYAN}Terima kasih telah menggunakan VBMeta Toolkit!{RESET}")
            break
        else:
            print(f"\n{RED}[✗] Pilihan tidak valid.{RESET}")
            input(f"\n{YELLOW}Press Enter...{RESET}")


if __name__ == "__main__":
    main()
