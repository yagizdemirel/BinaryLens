import struct
import math
from collections import defaultdict


class CFGBuilder:
    def __init__(self, file_bytes: bytes):
        self.data = file_bytes

    def build(self, func_limit: int = 15) -> dict:
        result = {
            "node_count":     0,
            "edge_count":     0,
            "component_count": 0,
            "edges":          [],
            "plotly_fig":     None,
            "error":          None,
        }

        try:
            import capstone
            import networkx as nx
        except ImportError as e:
            result["error"] = f"Eksik kütüphane: {e} — pip3 install capstone networkx"
            return result

        try:
            # Binary'den çağrı ilişkilerini çıkar
            calls = self._extract_calls(capstone, func_limit)

            if not calls:
                result["error"] = "Çağrı ilişkisi bulunamadı. Binary çok küçük veya desteklenmiyor."
                return result

            # Graf oluştur
            G = nx.DiGraph()
            for src, dst in calls:
                G.add_edge(src, dst)

            result["node_count"]      = G.number_of_nodes()
            result["edge_count"]      = G.number_of_edges()
            result["component_count"] = nx.number_weakly_connected_components(G)
            result["edges"]           = [(src, dst) for src, dst in G.edges()]

            # Plotly görselleştirme
            result["plotly_fig"] = self._build_plotly(G)

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Çağrı ilişkilerini çıkar ──────────────────────────────────────────────
    def _extract_calls(self, capstone, func_limit: int) -> list:
        arch, mode, code, base = self._setup_arch(capstone)
        if code is None:
            return []

        cs = capstone.Cs(arch, mode)
        cs.detail = False

        calls = []
        seen_targets = set()
        instruction_count = 0
        max_instructions = func_limit * 200  # Her fonksiyon için ~200 komut

        for ins in cs.disasm(code, base):
            instruction_count += 1
            if instruction_count > max_instructions:
                break

            mnem = ins.mnemonic.lower()

            # CALL komutlarını yakala
            if mnem == "call":
                op = ins.op_str.strip()
                target = self._resolve_operand(op, ins.address)
                if target and target != ins.address:
                    src_label = self._addr_label(ins.address)
                    dst_label = self._addr_label(target)
                    calls.append((src_label, dst_label))
                    seen_targets.add(target)

            # JMP ile fonksiyon geçişlerini yakala (sadece uzak atlamalar)
            elif mnem in ("jmp",) and len(seen_targets) < func_limit * 3:
                op = ins.op_str.strip()
                target = self._resolve_operand(op, ins.address)
                if target and abs(target - ins.address) > 64:
                    src_label = self._addr_label(ins.address)
                    dst_label = self._addr_label(target)
                    calls.append((src_label, dst_label))

        # Import tablosundan da ekle (PE için)
        import_calls = self._extract_import_calls()
        calls.extend(import_calls)

        # Tekrarları kaldır
        calls = list(dict.fromkeys(calls))

        return calls[:func_limit * 10]

    # ── Import tablosundan çağrılar ───────────────────────────────────────────
    def _extract_import_calls(self) -> list:
        if self.data[:2] != b"MZ":
            return []
        try:
            import pefile
            pe = pefile.PE(data=self.data)
            calls = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors="replace").replace(".dll", "").replace(".DLL", "")
                    for imp in entry.imports[:8]:  # Her DLL'den max 8 fonksiyon
                        if imp.name:
                            fname = imp.name.decode(errors="replace")
                            calls.append((dll, fname))
            pe.close()
            return calls
        except Exception:
            return []

    # ── Mimari kurulum ────────────────────────────────────────────────────────
    def _setup_arch(self, capstone):
        if self.data[:2] == b"MZ":
            return self._setup_pe(capstone)
        elif self.data[:4] == b"\x7fELF":
            return self._setup_elf(capstone)
        else:
            # Raw binary — x86_64 varsay
            return (
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_64,
                self.data[:min(len(self.data), 65536)],
                0,
            )

    def _setup_pe(self, capstone):
        try:
            pe_offset    = struct.unpack_from("<I", self.data, 0x3C)[0]
            machine      = struct.unpack_from("<H", self.data, pe_offset + 4)[0]
            opt_offset   = pe_offset + 24
            magic        = struct.unpack_from("<H", self.data, opt_offset)[0]

            if magic == 0x10b:
                ep_rva   = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                img_base = struct.unpack_from("<I", self.data, opt_offset + 28)[0]
            else:
                ep_rva   = struct.unpack_from("<I", self.data, opt_offset + 16)[0]
                img_base = struct.unpack_from("<Q", self.data, opt_offset + 24)[0]

            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_64 if machine == 0x8664 else capstone.CS_MODE_32

            # .text section
            num_sections = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
            opt_size     = struct.unpack_from("<H", self.data, pe_offset + 20)[0]
            sec_offset   = pe_offset + 24 + opt_size

            for i in range(num_sections):
                s = sec_offset + i * 40
                if s + 40 > len(self.data):
                    break
                name       = self.data[s:s+8].rstrip(b"\x00")
                raw_size   = struct.unpack_from("<I", self.data, s + 16)[0]
                raw_offset = struct.unpack_from("<I", self.data, s + 20)[0]
                if name in (b".text", b"CODE"):
                    end  = min(raw_offset + raw_size, len(self.data))
                    code = self.data[raw_offset:end]
                    return arch, mode, code, img_base + ep_rva

            return arch, mode, self.data[:65536], img_base + ep_rva

        except Exception:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64, self.data[:65536], 0

    def _setup_elf(self, capstone):
        try:
            bits   = self.data[4]
            endian = self.data[5]
            fmt    = "<" if endian == 1 else ">"

            if bits == 2:
                e_machine = struct.unpack_from(f"{fmt}H", self.data, 0x12)[0]
                e_entry   = struct.unpack_from(f"{fmt}Q", self.data, 0x18)[0]
                e_phoff   = struct.unpack_from(f"{fmt}Q", self.data, 0x20)[0]
                e_phnum   = struct.unpack_from(f"{fmt}H", self.data, 0x38)[0]
                ph_size   = 56
            else:
                e_machine = struct.unpack_from(f"{fmt}H", self.data, 0x12)[0]
                e_entry   = struct.unpack_from(f"{fmt}I", self.data, 0x18)[0]
                e_phoff   = struct.unpack_from(f"{fmt}I", self.data, 0x1c)[0]
                e_phnum   = struct.unpack_from(f"{fmt}H", self.data, 0x2c)[0]
                ph_size   = 32

            arch_map = {
                0x3e: capstone.CS_ARCH_X86,
                0x03: capstone.CS_ARCH_X86,
                0x28: capstone.CS_ARCH_ARM,
                0xb7: capstone.CS_ARCH_ARM64,
            }
            mode_map = {
                0x3e: capstone.CS_MODE_64,
                0x03: capstone.CS_MODE_32,
                0x28: capstone.CS_MODE_ARM,
                0xb7: capstone.CS_MODE_ARM,
            }

            arch = arch_map.get(e_machine, capstone.CS_ARCH_X86)
            mode = mode_map.get(e_machine, capstone.CS_MODE_64)

            # LOAD+EXEC segment
            for i in range(e_phnum):
                off = e_phoff + i * ph_size
                if off + ph_size > len(self.data):
                    break
                if bits == 2:
                    p_type   = struct.unpack_from(f"{fmt}I", self.data, off)[0]
                    p_flags  = struct.unpack_from(f"{fmt}I", self.data, off + 4)[0]
                    p_offset = struct.unpack_from(f"{fmt}Q", self.data, off + 8)[0]
                    p_filesz = struct.unpack_from(f"{fmt}Q", self.data, off + 32)[0]
                else:
                    p_type   = struct.unpack_from(f"{fmt}I", self.data, off)[0]
                    p_offset = struct.unpack_from(f"{fmt}I", self.data, off + 4)[0]
                    p_filesz = struct.unpack_from(f"{fmt}I", self.data, off + 16)[0]
                    p_flags  = struct.unpack_from(f"{fmt}I", self.data, off + 24)[0]

                if p_type == 1 and (p_flags & 0x1):
                    end  = min(p_offset + p_filesz, len(self.data))
                    code = self.data[p_offset:end]
                    return arch, mode, code, e_entry

            return arch, mode, self.data[:65536], e_entry

        except Exception:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64, self.data[:65536], 0

    # ── Operand çözümleme ─────────────────────────────────────────────────────
    def _resolve_operand(self, op_str: str, current_addr: int) -> int:
        op = op_str.strip()
        # Direkt adres: 0x401234
        if op.startswith("0x") or op.startswith("0X"):
            try:
                return int(op, 16)
            except ValueError:
                return None
        # Sayısal
        if op.lstrip("-").isdigit():
            try:
                val = int(op)
                # Görece offset ise ekle
                if abs(val) < 0x10000:
                    return current_addr + val
                return val
            except ValueError:
                return None
        return None

    def _addr_label(self, addr: int) -> str:
        return f"0x{addr:08x}"

    # ── Plotly görselleştirme ─────────────────────────────────────────────────
    def _build_plotly(self, G):
        try:
            import networkx as nx
            import plotly.graph_objects as go

            # Layout
            if G.number_of_nodes() <= 20:
                pos = nx.spring_layout(G, seed=42, k=2.5)
            else:
                pos = nx.kamada_kawai_layout(G)

            nodes = list(G.nodes())
            in_degrees = dict(G.in_degree())

            # Kenarlar
            edge_x, edge_y = [], []
            for src, dst in G.edges():
                x0, y0 = pos[src]
                x1, y1 = pos[dst]
                edge_x += [x0, x1, None]
                edge_y += [y0, y1, None]

            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                mode="lines",
                line=dict(width=0.8, color="#1e3d5a"),
                hoverinfo="none",
            )

            # Düğümler
            node_x = [pos[n][0] for n in nodes]
            node_y = [pos[n][1] for n in nodes]
            node_sizes  = [8 + in_degrees.get(n, 0) * 4 for n in nodes]
            node_colors = [in_degrees.get(n, 0) for n in nodes]

            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode="markers+text",
                hoverinfo="text",
                text=[n[:12] for n in nodes],
                textposition="top center",
                textfont=dict(
                    family="Share Tech Mono",
                    size=9,
                    color="#4a7fa5",
                ),
                hovertext=nodes,
                marker=dict(
                    size=node_sizes,
                    color=node_colors,
                    colorscale=[[0, "#1a2f45"], [0.5, "#1e6b50"], [1, "#39d98a"]],
                    line=dict(width=1, color="#39d98a44"),
                    showscale=True,
                    colorbar=dict(
                        title="In-degree",
                        titlefont=dict(color="#4a7fa5", size=10),
                        tickfont=dict(color="#4a7fa5", size=9),
                        bgcolor="#0d1117",
                        bordercolor="#1e2d3d",
                    ),
                ),
            )

            fig = go.Figure(
                data=[edge_trace, node_trace],
                layout=go.Layout(
                    paper_bgcolor="#0d1117",
                    plot_bgcolor="#0d1117",
                    font=dict(family="Share Tech Mono", color="#c0cfe0"),
                    showlegend=False,
                    height=500,
                    margin=dict(l=0, r=0, t=10, b=0),
                    xaxis=dict(
                        showgrid=False, zeroline=False,
                        showticklabels=False,
                        color="#1e2d3d",
                    ),
                    yaxis=dict(
                        showgrid=False, zeroline=False,
                        showticklabels=False,
                        color="#1e2d3d",
                    ),
                    hovermode="closest",
                ),
            )

            return fig

        except Exception:
            return None
