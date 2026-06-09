# ============================================================
# VBMeta Toolkit — AVB (Android Verified Boot) Parser
# Adapted from AOSP system/core/fs_mgr/avbtool.py
# By. soe1hom-arch / Wandi
# ============================================================
#
# Format reference:
#   https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_vbmeta_image.h
#   https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_descriptor.h
#
# AVB VBMeta Image Layout:
#   +-----------------------------+
#   | Header (256 bytes)          |
#   +-----------------------------+
#   | Authentication Data         |  (padding hashes + signatures)
#   |  - hash or signature        |
#   +-----------------------------+
#   | Auxiliary Data              |  (descriptors + padding)
#   |  - hash descriptors         |
#   |  - hashtree descriptors     |
#   |  - property descriptors     |
#   +-----------------------------+

import struct
import os
from pathlib import Path

# AVB magic
AVB_MAGIC = b"AVB0"

# Algorithm types
ALGORITHM_NONE = 0
ALGORITHM_SHA256_RSA2048 = 1
ALGORITHM_SHA256_RSA4096 = 2
ALGORITHM_SHA256_RSA8192 = 3
ALGORITHM_SHA512_RSA2048 = 4
ALGORITHM_SHA512_RSA4096 = 5
ALGORITHM_SHA512_RSA8192 = 6

ALGORITHM_NAMES = {
    0: "NONE",
    1: "SHA256_RSA2048",
    2: "SHA256_RSA4096",
    3: "SHA256_RSA8192",
    4: "SHA512_RSA2048",
    5: "SHA512_RSA4096",
    6: "SHA512_RSA8192",
}

# Descriptor tags
DESCRIPTOR_TAG_HASH = 0
DESCRIPTOR_TAG_HASHTREE = 1
DESCRIPTOR_TAG_HASH_PROP = 2
DESCRIPTOR_TAG_HASHTREE_PROP = 3

DESCRIPTOR_NAMES = {
    0: "Hash Descriptor",
    1: "Hashtree Descriptor",
    2: "Hash Descriptor (Property)",
    3: "Hashtree Descriptor (Property)",
}

# Flag bit positions
FLAG_VERIFICATION_DISABLED = 1 << 0   # bit 0
FLAG_VERITY_DISABLED       = 1 << 1   # bit 1


# =========================================================
# VBMeta Header Parser
# =========================================================

class VBMetaHeader:
    """AVB VBMeta image header (256 bytes)."""
    
    FORMAT = struct.Struct(">4sIIQQIQQQQQQIIQQ48s104s")
    
    def __init__(self):
        self.magic = b""
        self.major_version = 0
        self.minor_version = 0
        self.auth_data_size = 0
        self.aux_data_size = 0
        self.algorithm_type = 0
        self.hash_offset = 0
        self.hash_size = 0
        self.signature_offset = 0
        self.signature_size = 0
        self.public_key_offset = 0
        self.public_key_size = 0
        self.public_key_type = 0
        self.rollback_index_location = 0
        self.flags = 0
        self.rollback_index = 0
        self.release_string = ""
        self.reserved = b""
    
    @classmethod
    def parse(cls, data: bytes) -> "VBMetaHeader":
        if len(data) < 256:
            raise ValueError(f"Data too short for VBMeta header: {len(data)} < 256")
        
        hdr = cls()
        fields = cls.FORMAT.unpack_from(data, 0)
        
        hdr.magic = fields[0]
        if hdr.magic != AVB_MAGIC:
            raise ValueError(f"Invalid AVB magic: {hdr.magic!r}")
        
        hdr.major_version = fields[1]
        hdr.minor_version = fields[2]
        hdr.auth_data_size = fields[3]
        hdr.aux_data_size = fields[4]
        hdr.algorithm_type = fields[5]
        hdr.hash_offset = fields[6]
        hdr.hash_size = fields[7]
        hdr.signature_offset = fields[8]
        hdr.signature_size = fields[9]
        hdr.public_key_offset = fields[10]
        hdr.public_key_size = fields[11]
        hdr.public_key_type = fields[12]
        hdr.rollback_index_location = fields[13]
        hdr.flags = fields[14]
        hdr.rollback_index = fields[15]
        hdr.release_string = fields[16].rstrip(b'\x00').decode('utf-8', errors='replace')
        hdr.reserved = fields[17]
        
        return hdr
    
    def pack(self) -> bytes:
        release_bytes = self.release_string.encode('utf-8')[:48].ljust(48, b'\x00')
        return self.FORMAT.pack(
            self.magic or AVB_MAGIC,
            self.major_version,
            self.minor_version,
            self.auth_data_size,
            self.aux_data_size,
            self.algorithm_type,
            self.hash_offset,
            self.hash_size,
            self.signature_offset,
            self.signature_size,
            self.public_key_offset,
            self.public_key_size,
            self.public_key_type,
            self.rollback_index_location,
            self.flags,
            self.rollback_index,
            release_bytes,
            self.reserved[:104].ljust(104, b'\x00'),
        )
    
    @property
    def is_verification_disabled(self) -> bool:
        return bool(self.flags & FLAG_VERIFICATION_DISABLED)
    
    @property
    def is_verity_disabled(self) -> bool:
        return bool(self.flags & FLAG_VERITY_DISABLED)
    
    @property
    def algorithm_name(self) -> str:
        return ALGORITHM_NAMES.get(self.algorithm_type, f"UNKNOWN({self.algorithm_type})")
    
    def total_header_size(self) -> int:
        return 256 + self.auth_data_size + self.aux_data_size


# =========================================================
# Descriptor Parsing
# =========================================================

class AVBDescriptor:
    """Base descriptor from auxiliary data."""
    
    DESCRIPTOR_FORMAT = struct.Struct(">Q")  # num_bytes_following
    
    def __init__(self, tag: int, partition_name: str = ""):
        self.tag = tag
        self.partition_name = partition_name
        self.raw_data = b""
    
    @classmethod
    def parse_from(cls, data: bytes, offset: int) -> tuple["AVBDescriptor", int]:
        """Parse a descriptor from data at offset. Returns (descriptor, next_offset)."""
        if offset + 8 > len(data):
            raise ValueError(f"Data too short at offset {offset}")
        
        tag = struct.unpack_from(">I", data, offset)[0]
        num_following = struct.unpack_from(">Q", data, offset + 4)[0]
        
        # Total descriptor size: tag(4) + num_following(8) + data(num_following)
        total_sz = 12 + num_following
        
        if offset + total_sz > len(data):
            raise ValueError(f"Descriptor truncated at offset {offset}")
        
        desc = cls(tag)
        desc.raw_data = data[offset:offset + total_sz]
        
        # Extract partition name from descriptor data
        # Common for hash/hashtree: starts after 16-byte header
        # Name is null-terminated
        desc_data = data[offset + 12:offset + total_sz]
        name_end = desc_data.find(b'\x00')
        if name_end >= 0:
            desc.partition_name = desc_data[:name_end].decode('utf-8', errors='replace')
        
        return desc, offset + total_sz
    
    def summary(self) -> str:
        return f"{DESCRIPTOR_NAMES.get(self.tag, f'Tag({self.tag})')}"
    
    def detail(self) -> str:
        name = DESCRIPTOR_NAMES.get(self.tag, f"Unknown Tag({self.tag})")
        text = f"  Tag: {self.tag} ({name})\n"
        text += f"  Partition: {self.partition_name}"
        return text
    
    def pack(self) -> bytes:
        return self.raw_data


# =========================================================
# VBMeta Image
# =========================================================

class VBMetaImage:
    """Represents a full vbmeta image."""
    
    def __init__(self):
        self.header = None
        self.authentication_data = b""
        self.auxiliary_data = b""
        self.descriptors = []
        self.original_size = 0
        self.file_path = ""
    
    @classmethod
    def load(cls, path: str | Path) -> "VBMetaImage":
        path = Path(path)
        data = path.read_bytes()
        
        vbmeta = cls()
        vbmeta.file_path = str(path)
        vbmeta.original_size = len(data)
        
        # Parse header
        vbmeta.header = VBMetaHeader.parse(data)
        
        # Extract authentication data
        auth_start = 256
        auth_end = auth_start + vbmeta.header.auth_data_size
        vbmeta.authentication_data = data[auth_start:auth_end]
        
        # Extract auxiliary data
        aux_start = auth_end
        aux_end = aux_start + vbmeta.header.aux_data_size
        vbmeta.auxiliary_data = data[aux_start:aux_end]
        
        # Parse descriptors
        offset = 0
        while offset < len(vbmeta.auxiliary_data):
            if offset + 16 > len(vbmeta.auxiliary_data):
                break
            tag = struct.unpack_from(">I", vbmeta.auxiliary_data, offset)[0]
            if tag > 3:  # Unknown tag, stop
                break
            desc, offset = AVBDescriptor.parse_from(vbmeta.auxiliary_data, offset)
            vbmeta.descriptors.append(desc)
        
        return vbmeta
    
    def save(self, path: str | Path):
        """Save vbmeta image to file."""
        data = self.header.pack()
        data += self.authentication_data
        data += self.auxiliary_data
        
        Path(path).write_bytes(data)
    
    @property
    def flags(self) -> int:
        return self.header.flags
    
    @flags.setter
    def flags(self, value: int):
        self.header.flags = value
    
    def set_flag(self, bit: int, enabled: bool = True):
        if enabled:
            self.header.flags |= (1 << bit)
        else:
            self.header.flags &= ~(1 << bit)
    
    def info_text(self) -> str:
        h = self.header
        lines = []
        lines.append(f"File: {self.file_path}")
        lines.append(f"Size: {self.original_size} bytes")
        lines.append("")
        lines.append("=== VBMeta Header ===")
        lines.append(f"  Magic:             {h.magic.decode()}")
        lines.append(f"  AVB Version:       {h.major_version}.{h.minor_version}")
        lines.append(f"  Algorithm:         {h.algorithm_name}")
        lines.append(f"  Flags:             0x{h.flags:016x}")
        lines.append(f"    Verification:    {'DISABLED' if h.is_verification_disabled else 'ENABLED'}")
        lines.append(f"    Verity:          {'DISABLED' if h.is_verity_disabled else 'ENABLED'}")
        lines.append(f"  Rollback Index:    {h.rollback_index}")
        lines.append(f"  Rollback Location: {h.rollback_index_location}")
        lines.append(f"  Release String:    {h.release_string}")
        lines.append(f"  Auth Data Size:    {h.auth_data_size} bytes")
        lines.append(f"  Aux Data Size:     {h.aux_data_size} bytes")
        if h.algorithm_type != 0:
            lines.append(f"  Hash Offset:        {h.hash_offset}")
            lines.append(f"  Hash Size:          {h.hash_size}")
            lines.append(f"  Signature Offset:   {h.signature_offset}")
            lines.append(f"  Signature Size:     {h.signature_size}")
            lines.append(f"  Public Key Offset:  {h.public_key_offset}")
            lines.append(f"  Public Key Size:    {h.public_key_size}")
        lines.append("")
        lines.append("=== Descriptors ===")
        if not self.descriptors:
            lines.append("  (none)")
        for i, desc in enumerate(self.descriptors):
            lines.append(f"  [{i+1}] {desc.detail()}")
        
        return "\n".join(lines)


# =========================================================
# VBmeta Patcher
# =========================================================

def patch_vbmeta(input_path: str | Path, output_path: str | Path,
                 disable_verity: bool = False,
                 disable_verification: bool = False) -> dict:
    """Patch vbmeta image flags.
    
    Args:
        input_path: Source vbmeta image
        output_path: Output path for patched image
        disable_verity: Set bit 1 (disable dm-verity)
        disable_verification: Set bit 0 (disable AVB verification)
    
    Returns:
        dict with result info
    """
    vbmeta = VBMetaImage.load(input_path)
    
    old_flags = vbmeta.flags
    
    if disable_verification:
        vbmeta.set_flag(0, True)
    if disable_verity:
        vbmeta.set_flag(1, True)
    
    vbmeta.save(output_path)
    
    return {
        "old_flags": old_flags,
        "new_flags": vbmeta.flags,
        "old_verification": bool(old_flags & FLAG_VERIFICATION_DISABLED),
        "new_verification": bool(vbmeta.flags & FLAG_VERIFICATION_DISABLED),
        "old_verity": bool(old_flags & FLAG_VERITY_DISABLED),
        "new_verity": bool(vbmeta.flags & FLAG_VERITY_DISABLED),
        "input": str(input_path),
        "output": str(output_path),
        "size": Path(output_path).stat().st_size,
    }
