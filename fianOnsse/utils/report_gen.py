import json
import datetime
from core.static_analyzer import StaticAnalyzer, SUSPICIOUS_APIS
from core.entropy_analyzer import EntropyAnalyzer


class ReportGenerator:
    def __init__(self, file_bytes: bytes, filename: str):
        self.file_bytes = file_bytes
        self.filename = filename
        self.now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._static = None
        self._entropy = None

    def _run_analysis(self):
        if self._static is None:
            self._static = StaticAnalyzer(self.file_bytes, self.filename).analyze()
        if self._entropy is None:
            self._entropy = EntropyAnalyzer(self.file_bytes).analyze()

    # ── JSON ──────────────────────────────────────────────────────────────────
    def to_json(self) -> str:
        self._run_analysis()
        report = {
            "meta": {
                "filename":   self.filename,
                "generated":  self.now,
                "size_bytes": len(self.file_bytes),
            },
            "static": {
                "file_type":        self._static.get("file_type"),
                "arch":             self._static.get("arch"),
                "hashes":           self._static.get("hashes", {}),
                "headers":          self._static.get("headers", {}),
                "sections":         self._static.get("sections", []),
                "imports":          self._static.get("imports", []),
                "import_count":     self._static.get("import_count", 0),
                "suspicious_count": self._static.get("suspicious_count", 0),
            },
            "entropy": {
                "avg_entropy":       self._entropy.get("avg_entropy"),
                "max_entropy":       self._entropy.get("max_entropy"),
                "min_entropy":       self._entropy.get("min_entropy"),
                "is_packed":         self._entropy.get("is_packed"),
                "verdict":           self._entropy.get("verdict"),
                "section_entropies": self._entropy.get("section_entropies", []),
            },
            "risk_score": self._calc_risk(),
        }
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)

    # ── HTML ──────────────────────────────────────────────────────────────────
    def to_html(self) -> str:
        self._run_analysis()
        s = self._static
        e = self._entropy
        risk = self._calc_risk()
        risk_color = "#ff6b6b" if risk >= 7 else "#ffa500" if risk >= 4 else "#39d98a"

        sus_names = [x.lower() for x in SUSPICIOUS_APIS]
        sus_imports = [
            imp for imp in s.get("imports", [])
            if any(x in imp.get("name", "").lower() for x in sus_names)
        ]

        # Bölümler tablosu
        sections_rows = ""
        for sec in s.get("sections", []):
            vals = list(sec.values())
            sections_rows += "<tr>" + "".join(f"<td>{v}</td>" for v in vals) + "</tr>"

        # Şüpheli importlar
        sus_rows = ""
        for imp in sus_imports:
            sus_rows += f"<tr><td>{imp.get('dll','')}</td><td style='color:#ff6b6b'>{imp.get('name','')}</td></tr>"

        # Section entropileri
        sec_ent_rows = ""
        for sec in e.get("section_entropies", []):
            sec_ent_rows += (
                f"<tr><td>{sec.get('Bölüm','')}</td>"
                f"<td>{sec.get('Entropi','')}</td>"
                f"<td>{sec.get('Risk','')}</td>"
                f"<td>{sec.get('Boyut','')}</td></tr>"
            )

        # Header bilgileri
        header_rows = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in s.get("headers", {}).items()
        )

        # Hash kutuları
        hash_boxes = "".join(
            f'<div class="hash-box"><div class="hash-label">{k.upper()}</div>{v}</div>'
            for k, v in s.get("hashes", {}).items()
        )

        return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>BinaryLens — {self.filename}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0e14; color: #c0cfe0; font-family: 'Rajdhani', sans-serif; padding: 32px; line-height: 1.6; }}
  h1 {{ font-family: 'Share Tech Mono', monospace; color: #39d98a; letter-spacing: 3px; font-size: 24px; margin-bottom: 4px; }}
  h2 {{ font-family: 'Share Tech Mono', monospace; color: #4a7fa5; font-size: 13px; letter-spacing: 2px;
        text-transform: uppercase; margin: 32px 0 12px 0;
        border-left: 3px solid #39d98a; padding-left: 10px; }}
  .meta {{ font-family: 'Share Tech Mono', monospace; font-size: 12px; color: #1e3d5a; margin: 8px 0 28px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px; }}
  th {{ background: #0d1117; color: #4a7fa5; font-family: 'Share Tech Mono', monospace;
        font-size: 11px; text-transform: uppercase; padding: 8px 12px; text-align: left;
        border-bottom: 1px solid #1e2d3d; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #0d1117; }}
  tr:hover td {{ background: #0d1117; }}
  .hash-box {{ background: #0d1117; border: 1px solid #1e2d3d; border-radius: 6px;
               padding: 10px 14px; font-family: 'Share Tech Mono', monospace; font-size: 12px;
               color: #39d98a; margin-bottom: 8px; word-break: break-all; }}
  .hash-label {{ color: #4a7fa5; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }}
  .risk-badge {{ display: inline-block; background: {risk_color}22; color: {risk_color};
                 border: 1px solid {risk_color}44; border-radius: 20px; padding: 4px 18px;
                 font-family: 'Share Tech Mono', monospace; font-size: 15px; font-weight: 700; }}
  .footer {{ margin-top: 48px; font-family: 'Share Tech Mono', monospace;
             font-size: 10px; color: #1e3d5a; text-align: center; }}
</style>
</head>
<body>

<h1>🔬 BINARYLENS RAPORU</h1>
<div class="meta">
  Dosya: {self.filename} &nbsp;·&nbsp; Tarih: {self.now} &nbsp;·&nbsp;
  Boyut: {len(self.file_bytes):,} byte ({len(self.file_bytes)/1024:.1f} KB)
</div>

<h2>1. Risk Özeti</h2>
<p style="margin-bottom:12px">
  <span class="risk-badge">Risk: {risk}/10</span>
  &nbsp;&nbsp;
  {'⚠️ Packed tespit edildi' if e.get('is_packed') else '✅ Packed değil'}
  &nbsp;·&nbsp;
  Şüpheli API: {s.get('suspicious_count', 0)}
</p>

<h2>2. Dosya Bilgileri</h2>
<table>
  <tr><th>Alan</th><th>Değer</th></tr>
  <tr><td>Dosya Tipi</td><td>{s.get('file_type','?')}</td></tr>
  <tr><td>Mimari</td><td>{s.get('arch','?')}</td></tr>
  <tr><td>Import Sayısı</td><td>{s.get('import_count',0)}</td></tr>
  <tr><td>Şüpheli API</td><td>{s.get('suspicious_count',0)}</td></tr>
  {header_rows}
</table>

<h2>3. Hash Değerleri</h2>
{hash_boxes}

<h2>4. Bölümler</h2>
<table>
  <tr><th>İsim</th><th>Sanal Adres</th><th>Boyut</th><th>Entropi</th><th>Özellikler</th></tr>
  {sections_rows if sections_rows else "<tr><td colspan='5'>Bölüm bulunamadı</td></tr>"}
</table>

<h2>5. Şüpheli API'ler</h2>
<table>
  <tr><th>DLL</th><th>Fonksiyon</th></tr>
  {sus_rows if sus_rows else "<tr><td colspan='2'>✅ Şüpheli API tespit edilmedi</td></tr>"}
</table>

<h2>6. Entropi Analizi</h2>
<table>
  <tr><th>Ortalama</th><th>Max</th><th>Min</th><th>Packed?</th><th>Yorum</th></tr>
  <tr>
    <td>{e.get('avg_entropy',0)}</td>
    <td>{e.get('max_entropy',0)}</td>
    <td>{e.get('min_entropy',0)}</td>
    <td>{'⚠️ Evet' if e.get('is_packed') else '✅ Hayır'}</td>
    <td>{e.get('verdict','')}</td>
  </tr>
</table>

{"<h2>7. Bölüm Entropileri</h2><table><tr><th>Bölüm</th><th>Entropi</th><th>Risk</th><th>Boyut</th></tr>" + sec_ent_rows + "</table>" if sec_ent_rows else ""}

<div class="footer">BinaryLens tarafından oluşturuldu — {self.now}</div>
</body>
</html>"""

    # ── Markdown (eski metod, geriye dönük uyumluluk) ─────────────────────────
    def generate_markdown(self, static: dict = None, entropy: dict = None,
                          disasm: dict = None, cfg: dict = None) -> str:
        self._run_analysis()
        s = static or self._static
        e = entropy or self._entropy
        risk = self._calc_risk()

        sus_names = [x.lower() for x in SUSPICIOUS_APIS]
        sus_imports = [
            imp for imp in s.get("imports", [])
            if any(x in imp.get("name", "").lower() for x in sus_names)
        ]

        lines = [
            "# 🔬 BinaryLens Analiz Raporu", "",
            f"| Alan | Değer |", f"|------|-------|",
            f"| **Dosya** | `{self.filename}` |",
            f"| **Tarih** | {self.now} |",
            f"| **Boyut** | {len(self.file_bytes):,} byte |",
            "", "---", "",
            "## 1. Dosya Bilgileri", "",
            f"- **Tip:** {s.get('file_type', '?')}",
            f"- **Mimari:** {s.get('arch', '?')}",
            f"- **MD5:** `{s.get('hashes', {}).get('md5', '?')}`",
            f"- **SHA256:** `{s.get('hashes', {}).get('sha256', '?')}`", "",
            "## 2. İmport Analizi", "",
            f"- **Toplam:** {s.get('import_count', 0)}",
            f"- **Şüpheli:** {s.get('suspicious_count', 0)}", "",
        ]

        if sus_imports:
            lines += ["### ⚠️ Şüpheli API'ler", "",
                      "| DLL | Fonksiyon |", "|-----|-----------|"]
            for imp in sus_imports:
                lines.append(f"| `{imp.get('dll','')}` | `{imp.get('name','')}` |")
            lines.append("")

        lines += [
            "## 3. Entropi", "",
            f"- **Ortalama:** {e.get('avg_entropy', 0)}",
            f"- **Packed:** {'⚠️ Evet' if e.get('is_packed') else '✅ Hayır'}",
            f"- **Yorum:** {e.get('verdict', '')}", "",
            "---",
            f"**Risk Skoru: {risk}/10**", "",
            f"*BinaryLens — {self.now}*",
        ]
        return "\n".join(lines)

    # ── Risk hesaplama ────────────────────────────────────────────────────────
    def _calc_risk(self) -> int:
        self._run_analysis()
        score = 0
        sus = self._static.get("suspicious_count", 0)
        if sus > 10:   score += 4
        elif sus > 5:  score += 3
        elif sus > 0:  score += 2

        avg_e = self._entropy.get("avg_entropy", 0)
        if avg_e > 7.0:   score += 3
        elif avg_e > 6.5: score += 2
        elif avg_e > 6.0: score += 1

        if self._entropy.get("is_packed"):         score += 2
        if sus > 0 and self._entropy.get("is_packed"): score += 1

        return min(score, 10)