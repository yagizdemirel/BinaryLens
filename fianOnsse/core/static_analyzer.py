import hashlib
import math
import re
import struct
from collections import Counter


SUSPICIOUS_APIS = [
    # Process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "NtCreateThreadEx", "RtlCreateUserThread",
    # Anti-debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "FindWindow", "GetTickCount",
    # Persistence
    "RegSetValue", "RegCreateKey", "RegOpenKey",
    "CreateService", "OpenService",
    # Network
    "WSASocket", "connect", "send", "recv",
    "InternetOpen", "InternetConnect", "HttpSendRequest",
    "WinHttpOpen", "WinHttpConnect",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
    # Shell
    "ShellExecute", "ShellExecuteEx", "WinExec",
    "CreateProcess", "system",
    # File ops
    "DeleteFile", "MoveFile", "CopyFile",
]


class StaticAnalyzer:
    def __init__(self, file_bytes: bytes, filename: str = ""):
        self.data = file_bytes
        self.filename = filename

    def analyze(self) -> dict:
        result = {
            "file_type": "Unknown",
            "arch": "Unknown",
            "headers": {},
            "sections": [],
            "imports": [],
            "import_count": 0,
            "suspicious_count": 0,
            "strings": [],
            "hashes": {},
            "error": None,
        }

        try:
            result["hashes"] = self._calc_hashes()
            result["file_type"] = self._detect_file_type()
            result["strings"] = self._extract_strings()

            if self._is_pe():
                pe_data = self._parse_pe()
                result.update(pe_data)
            elif self._is_elf():
                elf_data = self._parse_elf()
                result.update(elf_data)
            else:
                result["headers"] = {"Tip": "Raw Binary / Bilinmeyen Format"}

            # Suspicious sayısı
            sus_names = [s.lower() for s in SUSPICIOUS_APIS]
            result["suspicious_count"] = sum(
                1 for imp in result["imports"]
                if any(s in imp.get("name", "").lower() for s in sus_names)
            )
            result["import_count"] = len(result["imports"])

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Hash ──────────────────────────────────────────────────────────────────
    def _calc_hashes(self) -> dict:
        return {
            "md5":    hashlib.md5(self.data).hexdigest(),
            "sha1":   hashlib.sha1(self.data).hexdigest(),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }

    # ── Dosya tipi tespiti ────────────────────────────────────────────────────
    def _detect_file_type(self) -> str:
        if self.data[:2] == b"MZ":
            return "PE (Windows)"
        if self.data[:4] == b"\x7fELF":
            return "ELF (Linux)"
        if self.data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                              b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return "Mach-O (macOS)"
        if self.data[:2] == b"PK":
            return "ZIP / JAR"
        if self.data[:4] == b"\x89PNG":
            return "PNG Image"
        if self.data[:2] == b"\xff\xd8":
            return "JPEG Image"
        return "Raw Binary"

    def _is_pe(self) -> bool:
        return self.data[:2] == b"MZ"

    def _is_elf(self) -> bool:
        return self.data[:4] == b"\x7fELF"

    # ── PE Parse ──────────────────────────────────────────────────────────────
    def _parse_pe(self) -> dict:
        try:
            import pefile
        except ImportError:
            return {"error": "pefile kütüphanesi yüklü değil: pip3 install pefile"}

        pe = pefile.PE(data=self.data)

        # Mimari
        machine = pe.FILE_HEADER.Machine
        arch_map = {
            0x014c: "x86 32-bit",
            0x8664: "x86 64-bit",
            0x01c0: "ARM",
            0xaa64: "ARM64",
        }
        arch = arch_map.get(machine, f"0x{machine:04x}")

        # Headers
        headers = {
            "Entry Point":      hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base":       hex(pe.OPTIONAL_HEADER.ImageBase),
            "Compile Time":     self._pe_timestamp(pe.FILE_HEADER.TimeDateStamp),
            "Subsystem":        self._pe_subsystem(pe.OPTIONAL_HEADER.Subsystem),
            "Number of Sections": pe.FILE_HEADER.NumberOfSections,
            "Linker Version":   f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
            "OS Version":       f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}",
        }

        # Sections
        sections = []
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").rstrip("\x00")
            sections.append({
                "İsim":        name,
                "Sanal Adres": hex(sec.VirtualAddress),
                "Boyut":       sec.SizeOfRawData,
                "Entropi":     round(self._section_entropy(sec.get_data()), 3),
                "Özellikler":  self._section_flags(sec.Characteristics),
            })

        # Imports
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    func_name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    imports.append({"dll": dll_name, "name": func_name})

        pe.close()
        return {
            "arch": arch,
            "headers": headers,
            "sections": sections,
            "imports": imports,
        }

    def _pe_timestamp(self, ts: int) -> str:
        import datetime
        try:
            return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(ts)

    def _pe_subsystem(self, sub: int) -> str:
        subs = {
            1: "Native", 2: "Windows GUI", 3: "Windows CUI",
            5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
            10: "EFI Application", 14: "Xbox",
        }
        return subs.get(sub, f"Unknown ({sub})")

    def _section_flags(self, chars: int) -> str:
        flags = []
        if chars & 0x20000000: flags.append("EXEC")
        if chars & 0x40000000: flags.append("READ")
        if chars & 0x80000000: flags.append("WRITE")
        return " | ".join(flags) if flags else "?"

    # ── ELF Parse ─────────────────────────────────────────────────────────────
    def _parse_elf(self) -> dict:
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection
            import io
        except ImportError:
            return {"error": "pyelftools kütüphanesi yüklü değil: pip3 install pyelftools"}

        elf = ELFFile(io.BytesIO(self.data))

        # Mimari
        arch_map = {
            "EM_386":    "x86 32-bit",
            "EM_X86_64": "x86 64-bit",
            "EM_ARM":    "ARM",
            "EM_AARCH64":"ARM64",
            "EM_MIPS":   "MIPS",
        }
        arch = arch_map.get(elf.header.e_machine, elf.header.e_machine)

        headers = {
            "ELF Sınıfı":    elf.elfclass,
            "Veri Kodlama":  elf.header.e_ident["EI_DATA"],
            "Dosya Tipi":    elf.header.e_type,
            "Makine":        elf.header.e_machine,
            "Entry Point":   hex(elf.header.e_entry),
            "Bölüm Sayısı":  elf.num_sections(),
            "Segment Sayısı":elf.num_segments(),
        }

        sections = []
        for sec in elf.iter_sections():
            if sec.name:
                sections.append({
                    "İsim":   sec.name,
                    "Tip":    sec["sh_type"],
                    "Adres":  hex(sec["sh_addr"]),
                    "Boyut":  sec["sh_size"],
                    "Entropi": round(self._section_entropy(sec.data()), 3),
                })

        imports = []
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        imports.append({"dll": tag.needed, "name": "(shared lib)"})

        return {
            "arch": arch,
            "headers": headers,
            "sections": sections,
            "imports": imports,
        }

    # ── Strings ───────────────────────────────────────────────────────────────
    def _extract_strings(self, min_len: int = 4) -> list:
        pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        matches = pattern.findall(self.data)
        strings = [m.decode("ascii", errors="replace") for m in matches]

        # Filtreleme — sadece anlamlı stringleri göster
        filtered = []
        for s in strings:
            if len(s) < 4:
                continue
            # Çok tekrarlı karakter içerenleri atla
            if len(set(s)) < 2:
                continue
            filtered.append(s)

        # En ilginç olanları üste al (URL, path, DLL, API benzeri)
        priority = []
        normal = []
        keywords = ["http", "://", ".dll", ".exe", ".bat", "cmd", "reg",
                    "HKEY", "\\\\", "password", "token", "key", "secret"]
        for s in filtered:
            if any(k.lower() in s.lower() for k in keywords):
                priority.append(s)
            else:
                normal.append(s)

        return priority[:30] + normal[:70]

    # ── Bölüm entropisi ───────────────────────────────────────────────────────
    def _section_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
