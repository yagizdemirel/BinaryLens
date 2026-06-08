import math
import struct
from collections import Counter


class EntropyAnalyzer:
    def __init__(self, file_bytes: bytes, block_size: int = 256):
        self.data = file_bytes
        self.block_size = block_size

    def analyze(self) -> dict:
        result = {
            "avg_entropy":    0.0,
            "max_entropy":    0.0,
            "min_entropy":    8.0,
            "is_packed":      False,
            "block_entropies": [],
            "section_entropies": [],
            "verdict":        "",
            "error":          None,
        }

        try:
            # Blok bazlı entropi
            block_entropies = self._calc_block_entropies()
            result["block_entropies"] = block_entropies

            if block_entropies:
                result["avg_entropy"] = round(sum(block_entropies) / len(block_entropies), 4)
                result["max_entropy"] = round(max(block_entropies), 4)
                result["min_entropy"] = round(min(block_entropies), 4)

            # Packed tespiti
            result["is_packed"] = self._detect_packed(block_entropies)

            # Section bazlı entropi (PE/ELF)
            result["section_entropies"] = self._calc_section_entropies()

            # Yorum
            result["verdict"] = self._verdict(result)

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Blok bazlı entropi ────────────────────────────────────────────────────
    def _calc_block_entropies(self) -> list:
        entropies = []
        data = self.data
        size = len(data)

        for offset in range(0, size, self.block_size):
            block = data[offset: offset + self.block_size]
            if len(block) < 16:
                break
            entropies.append(self._entropy(block))

        return entropies

    # ── Section bazlı entropi ─────────────────────────────────────────────────
    def _calc_section_entropies(self) -> list:
        sections = []

        # PE
        if self.data[:2] == b"MZ":
            sections = self._pe_section_entropies()

        # ELF
        elif self.data[:4] == b"\x7fELF":
            sections = self._elf_section_entropies()

        return sections

    def _pe_section_entropies(self) -> list:
        try:
            pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
            num_sections = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
            opt_size     = struct.unpack_from("<H", self.data, pe_offset + 20)[0]
            sec_offset   = pe_offset + 24 + opt_size

            sections = []
            for i in range(num_sections):
                s = sec_offset + i * 40
                if s + 40 > len(self.data):
                    break

                name       = self.data[s:s+8].rstrip(b"\x00").decode(errors="replace")
                raw_size   = struct.unpack_from("<I", self.data, s + 16)[0]
                raw_offset = struct.unpack_from("<I", self.data, s + 20)[0]

                if raw_size == 0 or raw_offset == 0:
                    continue

                end   = min(raw_offset + raw_size, len(self.data))
                chunk = self.data[raw_offset:end]
                if not chunk:
                    continue

                entropy = self._entropy(chunk)
                risk    = self._entropy_risk(entropy)

                sections.append({
                    "Bölüm":   name or "(boş)",
                    "Entropi": round(entropy, 3),
                    "Risk":    risk,
                    "Boyut":   raw_size,
                })

            return sections

        except Exception:
            return []

    def _elf_section_entropies(self) -> list:
        try:
            from elftools.elf.elffile import ELFFile
            import io

            elf = ELFFile(io.BytesIO(self.data))
            sections = []

            for sec in elf.iter_sections():
                if not sec.name or sec["sh_size"] == 0:
                    continue
                chunk   = sec.data()
                if not chunk:
                    continue
                entropy = self._entropy(chunk)
                risk    = self._entropy_risk(entropy)
                sections.append({
                    "Bölüm":   sec.name,
                    "Entropi": round(entropy, 3),
                    "Risk":    risk,
                    "Boyut":   sec["sh_size"],
                })

            return sections

        except Exception:
            return []

    # ── Packed tespiti ────────────────────────────────────────────────────────
    def _detect_packed(self, entropies: list) -> bool:
        if not entropies:
            return False

        avg = sum(entropies) / len(entropies)

        # Yüksek ortalama entropi
        if avg > 7.0:
            return True

        # Blokların %30'undan fazlası 7.2 üzerindeyse
        high_blocks = sum(1 for e in entropies if e > 7.2)
        if len(entropies) > 0 and high_blocks / len(entropies) > 0.3:
            return True

        # PE: bilinen packer imzaları
        if self.data[:2] == b"MZ":
            if self._check_packer_signatures():
                return True

        return False

    def _check_packer_signatures(self) -> bool:
        """Bilinen packer imzalarını kontrol et."""
        signatures = {
            # UPX
            b"UPX0": "UPX",
            b"UPX1": "UPX",
            b"UPX!": "UPX",
            # MPRESS
            b"MPRESS1": "MPRESS",
            b"MPRESS2": "MPRESS",
            # ASPack
            b".aspack": "ASPack",
            b".adata":  "ASPack",
            # PECompact
            b"PEC2": "PECompact",
            # Themida / WinLicense
            b".themida": "Themida",
            # NSPack
            b"nsp0": "NSPack",
            b"nsp1": "NSPack",
        }

        data_lower = self.data[:8192]
        for sig in signatures:
            if sig in data_lower:
                return True
        return False

    def _detect_packer_name(self) -> str:
        """Hangi packer kullanıldığını tespit et."""
        signatures = {
            b"UPX0":    "UPX",
            b"UPX1":    "UPX",
            b"UPX!":    "UPX",
            b"MPRESS1": "MPRESS",
            b"MPRESS2": "MPRESS",
            b".aspack": "ASPack",
            b"PEC2":    "PECompact",
            b".themida":"Themida",
            b"nsp0":    "NSPack",
        }
        data_lower = self.data[:8192]
        for sig, name in signatures.items():
            if sig in data_lower:
                return name
        return "Bilinmeyen"

    # ── Entropi risk seviyesi ─────────────────────────────────────────────────
    def _entropy_risk(self, entropy: float) -> str:
        if entropy >= 7.5:
            return "🔴 Çok Yüksek"
        elif entropy >= 7.0:
            return "🟠 Yüksek"
        elif entropy >= 6.0:
            return "🟡 Orta"
        elif entropy >= 4.0:
            return "🟢 Normal"
        else:
            return "⚪ Düşük"

    # ── Genel yorum ───────────────────────────────────────────────────────────
    def _verdict(self, result: dict) -> str:
        avg = result["avg_entropy"]
        is_packed = result["is_packed"]

        if is_packed:
            packer = self._detect_packer_name()
            if packer != "Bilinmeyen":
                return f"⚠️ Binary packed! Tespit edilen packer: {packer}"
            return "⚠️ Binary muhtemelen packed veya şifrelenmiş (yüksek entropi)"

        if avg > 6.5:
            return "🟡 Bazı bölümler sıkıştırılmış veya şifrelenmiş olabilir"
        elif avg > 5.0:
            return "🟢 Normal binary — belirgin bir packing tespit edilmedi"
        else:
            return "🟢 Temiz binary — düşük entropi, şüpheli bölge yok"

    # ── Yardımcı: Shannon entropisi ───────────────────────────────────────────
    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        total   = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
