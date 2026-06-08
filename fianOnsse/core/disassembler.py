import struct
from typing import Optional


ARCH_AUTO  = "auto"
ARCH_X86   = "x86_32"
ARCH_X64   = "x86_64"
ARCH_ARM   = "arm"
ARCH_ARM64 = "arm64"


class Disassembler:
    def __init__(self, file_bytes: bytes, arch: str = ARCH_AUTO):
        self.data = file_bytes
        self.arch = arch

    def disassemble(self, limit: int = 100) -> dict:
        result = {
            "instructions":   [],
            "arch_detected":  "Unknown",
            "entry_point":    0,
            "error":          None,
        }

        try:
            import capstone
        except ImportError:
            result["error"] = "capstone yüklü değil: pip3 install capstone"
            return result

        try:
            # Mimari ve kod bölgesini belirle
            cs, code, entry = self._setup(capstone)
            if cs is None:
                result["error"] = "Desteklenmeyen mimari veya geçersiz binary."
                return result

            result["arch_detected"] = self._arch_label()
            result["entry_point"]   = entry

            # Disassemble
            instructions = []
            for ins in cs.disasm(code, entry):
                instructions.append({
                    "address":  ins.address,
                    "mnemonic": ins.mnemonic,
                    "op_str":   ins.op_str,
                    "bytes":    ins.bytes.hex(),
                    "size":     ins.size,
                })
                if len(instructions) >= limit:
                    break

            result["instructions"] = instructions

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Setup: mimari + kod bölgesi ───────────────────────────────────────────
    def _setup(self, capstone):
        arch = self.arch if self.arch != ARCH_AUTO else self._detect_arch()

        cs_map = {
            ARCH_X86:   (capstone.CS_ARCH_X86,  capstone.CS_MODE_32),
            ARCH_X64:   (capstone.CS_ARCH_X86,  capstone.CS_MODE_64),
            ARCH_ARM:   (capstone.CS_ARCH_ARM,  capstone.CS_MODE_ARM),
            ARCH_ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }

        if arch not in cs_map:
            return None, None, 0

        cs_arch, cs_mode = cs_map[arch]
        cs = capstone.Cs(cs_arch, cs_mode)
        cs.detail = False

        # Kod bölgesini ve entry point'i bul
        code, entry = self._extract_code(arch)
        self._detected_arch = arch

        return cs, code, entry

    # ── Mimari tespiti ────────────────────────────────────────────────────────
    def _detect_arch(self) -> str:
        # PE
        if self.data[:2] == b"MZ":
            pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
            if pe_offset + 6 < len(self.data):
                machine = struct.unpack_from("<H", self.data, pe_offset + 4)[0]
                if machine == 0x8664:
                    return ARCH_X64
                if machine == 0x014c:
                    return ARCH_X86
                if machine == 0x01c0:
                    return ARCH_ARM
                if machine == 0xaa64:
                    return ARCH_ARM64
            return ARCH_X86

        # ELF
        if self.data[:4] == b"\x7fELF":
            e_machine = struct.unpack_from("<H", self.data, 0x12)[0]
            if e_machine == 0x3e:
                return ARCH_X64
            if e_machine == 0x03:
                return ARCH_X86
            if e_machine == 0x28:
                return ARCH_ARM
            if e_machine == 0xb7:
                return ARCH_ARM64
            return ARCH_X86

        # Varsayılan
        return ARCH_X86

    def _arch_label(self) -> str:
        arch = getattr(self, "_detected_arch", self.arch)
        labels = {
            ARCH_X86:   "x86 32-bit",
            ARCH_X64:   "x86 64-bit",
            ARCH_ARM:   "ARM",
            ARCH_ARM64: "ARM64",
        }
        return labels.get(arch, arch)

    # ── Kod bölgesi çıkarma ───────────────────────────────────────────────────
    def _extract_code(self, arch: str):
        """Binary'den .text bölümünü veya entry point'ten itibaren kodu çıkar."""

        # PE
        if self.data[:2] == b"MZ":
            return self._extract_pe_code()

        # ELF
        if self.data[:4] == b"\x7fELF":
            return self._extract_elf_code()

        # Raw binary — baştan itibaren
        return self.data[:4096], 0

    def _extract_pe_code(self):
        try:
            pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
            # Optional header offset
            opt_offset = pe_offset + 24
            magic = struct.unpack_from("<H", self.data, opt_offset)[0]

            if magic == 0x10b:   # PE32
                ep_rva   = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                img_base = struct.unpack_from("<I", self.data, opt_offset + 28)[0]
            elif magic == 0x20b: # PE32+
                ep_rva   = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                img_base = struct.unpack_from("<Q", self.data, opt_offset + 24)[0]
            else:
                return self.data[:4096], 0

            # Section tablosundan .text bölümünü bul
            num_sections = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
            opt_size     = struct.unpack_from("<H", self.data, pe_offset + 20)[0]
            sec_offset   = pe_offset + 24 + opt_size

            text_raw_offset = None
            text_raw_size   = None
            text_va         = None

            for i in range(num_sections):
                s = sec_offset + i * 40
                if s + 40 > len(self.data):
                    break
                name         = self.data[s:s+8].rstrip(b"\x00")
                virtual_size = struct.unpack_from("<I", self.data, s + 8)[0]
                virtual_addr = struct.unpack_from("<I", self.data, s + 12)[0]
                raw_size     = struct.unpack_from("<I", self.data, s + 16)[0]
                raw_offset   = struct.unpack_from("<I", self.data, s + 20)[0]

                if name in (b".text", b"CODE", b".code"):
                    text_raw_offset = raw_offset
                    text_raw_size   = raw_size
                    text_va         = virtual_addr
                    break

            if text_raw_offset and text_raw_size:
                end = min(text_raw_offset + text_raw_size, len(self.data))
                code = self.data[text_raw_offset:end]
                entry = img_base + ep_rva
                return code, entry

            # .text bulunamadı — entry point RVA'dan itibaren al
            # RVA → raw offset dönüşümü için section tablosunu tara
            for i in range(num_sections):
                s = sec_offset + i * 40
                if s + 40 > len(self.data):
                    break
                vaddr    = struct.unpack_from("<I", self.data, s + 12)[0]
                vsize    = struct.unpack_from("<I", self.data, s + 8)[0]
                raw_off  = struct.unpack_from("<I", self.data, s + 20)[0]
                raw_size = struct.unpack_from("<I", self.data, s + 16)[0]

                if vaddr <= ep_rva < vaddr + vsize:
                    offset_in_sec = ep_rva - vaddr
                    start = raw_off + offset_in_sec
                    end   = min(raw_off + raw_size, len(self.data))
                    code  = self.data[start:end]
                    return code, img_base + ep_rva

            # Son çare
            return self.data[:4096], img_base + ep_rva

        except Exception:
            return self.data[:4096], 0

    def _extract_elf_code(self):
        try:
            bits = self.data[4]  # 1=32bit, 2=64bit
            endian = self.data[5]  # 1=LE, 2=BE
            fmt = "<" if endian == 1 else ">"

            if bits == 1:   # 32-bit
                e_entry  = struct.unpack_from(f"{fmt}I", self.data, 0x18)[0]
                e_phoff  = struct.unpack_from(f"{fmt}I", self.data, 0x1c)[0]
                e_phnum  = struct.unpack_from(f"{fmt}H", self.data, 0x2c)[0]
                ph_size  = 32
            else:            # 64-bit
                e_entry  = struct.unpack_from(f"{fmt}Q", self.data, 0x18)[0]
                e_phoff  = struct.unpack_from(f"{fmt}Q", self.data, 0x20)[0]
                e_phnum  = struct.unpack_from(f"{fmt}H", self.data, 0x38)[0]
                ph_size  = 56

            # PT_LOAD segment ile EXEC permission'lı bölümü bul
            for i in range(e_phnum):
                off = e_phoff + i * ph_size
                if off + ph_size > len(self.data):
                    break

                if bits == 1:
                    p_type   = struct.unpack_from(f"{fmt}I", self.data, off)[0]
                    p_offset = struct.unpack_from(f"{fmt}I", self.data, off + 4)[0]
                    p_vaddr  = struct.unpack_from(f"{fmt}I", self.data, off + 8)[0]
                    p_filesz = struct.unpack_from(f"{fmt}I", self.data, off + 16)[0]
                    p_flags  = struct.unpack_from(f"{fmt}I", self.data, off + 24)[0]
                else:
                    p_type   = struct.unpack_from(f"{fmt}I", self.data, off)[0]
                    p_flags  = struct.unpack_from(f"{fmt}I", self.data, off + 4)[0]
                    p_offset = struct.unpack_from(f"{fmt}Q", self.data, off + 8)[0]
                    p_vaddr  = struct.unpack_from(f"{fmt}Q", self.data, off + 16)[0]
                    p_filesz = struct.unpack_from(f"{fmt}Q", self.data, off + 32)[0]

                PT_LOAD = 1
                PF_X    = 0x1  # Execute flag

                if p_type == PT_LOAD and (p_flags & PF_X):
                    end  = min(p_offset + p_filesz, len(self.data))
                    code = self.data[p_offset:end]
                    return code, e_entry

            # Segment bulunamadı
            return self.data[:4096], e_entry

        except Exception:
            return self.data[:4096], 0
