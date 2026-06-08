import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px


# ── HEADER ────────────────────────────────────────────────────────────────────
def render_header():
    st.markdown("""
    <div style="
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 20px 0 8px 0;
        border-bottom: 1px solid #1e2d3d;
        margin-bottom: 24px;
    ">
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 28px;
            font-weight: 700;
            color: #39d98a;
            letter-spacing: 2px;
        ">BINARY<span style="color:#4a7fa5">LENS</span></div>
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: #1e3d5a;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-top: 6px;
        ">// tersine mühendislik & statik analiz</div>
        <div style="margin-left: auto;">
            <span style="
                font-family: 'Share Tech Mono', monospace;
                font-size: 10px;
                color: #39d98a;
                border: 1px solid #39d98a33;
                padding: 2px 10px;
                border-radius: 20px;
                background: #39d98a11;
            ">v1.0.0</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── SIDEBAR ───────────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 13px;
            color: #39d98a;
            letter-spacing: 2px;
            text-transform: uppercase;
            border-bottom: 1px solid #1e2d3d;
            padding-bottom: 10px;
            margin-bottom: 16px;
        ">⚙ Ayarlar</div>
        """, unsafe_allow_html=True)

        st.markdown("**Disassembly**")
        st.session_state["disasm_arch"] = st.selectbox(
            "Mimari",
            ["Otomatik Tespit", "x86 32-bit", "x86 64-bit", "ARM", "ARM64"],
            key="arch_select"
        )
        st.session_state["disasm_limit"] = st.slider(
            "Max Komut Sayısı", 50, 500, 100, step=50
        )

        st.markdown("---")
        st.markdown("**Entropy**")
        st.session_state["entropy_block"] = st.slider(
            "Blok Boyutu (byte)", 64, 1024, 256, step=64
        )

        st.markdown("---")
        st.markdown("**CFG**")
        st.session_state["cfg_func_limit"] = st.slider(
            "Max Fonksiyon", 5, 50, 15, step=5
        )

        st.markdown("---")
        st.markdown("""
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: #4a7fa5;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 8px;
        ">Suspicious API Listesi</div>
        """, unsafe_allow_html=True)

        suspicious_apis = [
            "VirtualAlloc", "CreateRemoteThread",
            "WriteProcessMemory", "ShellExecute",
            "RegSetValue", "WSASocket",
            "CryptEncrypt", "IsDebuggerPresent",
        ]
        for api in suspicious_apis:
            st.markdown(f"""
            <div style="
                font-family: 'Share Tech Mono', monospace;
                font-size: 11px;
                color: #e05555;
                padding: 2px 0;
            ">⚠ {api}</div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("""
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 10px;
            color: #1e3d5a;
            text-align: center;
        ">BinaryLens · Siber Güvenlik Projesi</div>
        """, unsafe_allow_html=True)


# ── UPLOAD ────────────────────────────────────────────────────────────────────
def render_upload_section():
    st.markdown("""
    <div style="
        font-family: 'Share Tech Mono', monospace;
        font-size: 12px;
        color: #4a7fa5;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 8px;
    ">// Binary Dosya Yükle</div>
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "PE (.exe, .dll) veya ELF binary seç",
        type=None,
        label_visibility="collapsed",
    )

    if uploaded:
        col1, col2, col3 = st.columns(3)
        size_kb = len(uploaded.getvalue()) / 1024
        col1.metric("📁 Dosya Adı", uploaded.name[:20])
        col2.metric("📦 Boyut", f"{size_kb:.1f} KB")
        col3.metric("🔢 Bytes", f"{len(uploaded.getvalue()):,}")

    return uploaded


# ── STATİK ANALİZ TAB ─────────────────────────────────────────────────────────
def render_static_tab(file_bytes: bytes, filename: str):
    from core.static_analyzer import StaticAnalyzer

    section_title("Statik Analiz", "Binary yapısını ve metadata bilgilerini inceler")

    with st.spinner("🔍 Analiz ediliyor..."):
        analyzer = StaticAnalyzer(file_bytes, filename)
        result = analyzer.analyze()

    if result.get("error"):
        st.error(f"Hata: {result['error']}")
        return

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Dosya Tipi", result.get("file_type", "?"))
    col2.metric("Mimari", result.get("arch", "?"))
    col3.metric("Import Sayısı", result.get("import_count", 0))
    col4.metric("Şüpheli API", result.get("suspicious_count", 0))

    st.markdown("---")

    col_left, col_right = st.columns(2)

    with col_left:
        sub_title("📋 Dosya Başlıkları")
        headers = result.get("headers", {})
        if headers:
            df = pd.DataFrame(list(headers.items()), columns=["Alan", "Değer"])
            st.dataframe(df, use_container_width=True, hide_index=True)

        sub_title("📦 Bölümler (Sections)")
        sections = result.get("sections", [])
        if sections:
            st.dataframe(pd.DataFrame(sections), use_container_width=True, hide_index=True)
        else:
            st.info("Bölüm bilgisi bulunamadı.")

    with col_right:
        sub_title("📥 Import Edilen Fonksiyonlar")
        imports = result.get("imports", [])
        if imports:
            suspicious_list = [
                "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                "ShellExecute", "RegSetValue", "WSASocket", "CryptEncrypt",
                "IsDebuggerPresent", "NtQueryInformationProcess",
            ]
            rows = []
            for imp in imports:
                is_sus = any(s.lower() in imp.get("name", "").lower() for s in suspicious_list)
                rows.append({
                    "DLL": imp.get("dll", ""),
                    "Fonksiyon": imp.get("name", ""),
                    "⚠": "🔴" if is_sus else "✅",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=300)
        else:
            st.info("Import bilgisi bulunamadı.")

        sub_title("🔤 Strings (İlk 50)")
        strings = result.get("strings", [])[:50]
        if strings:
            st.code("\n".join(strings), language=None)
        else:
            st.info("String bulunamadı.")

    sub_title("🔐 Dosya Hash'leri")
    hashes = result.get("hashes", {})
    if hashes:
        h_col1, h_col2, h_col3 = st.columns(3)
        h_col1.code(f"MD5\n{hashes.get('md5', 'N/A')}", language=None)
        h_col2.code(f"SHA1\n{hashes.get('sha1', 'N/A')}", language=None)
        h_col3.code(f"SHA256\n{hashes.get('sha256', 'N/A')}", language=None)


# ── DİSASSEMBLY TAB ──────────────────────────────────────────────────────────
def render_disasm_tab(file_bytes: bytes):
    from core.disassembler import Disassembler

    section_title("Disassembly", "Makine kodunu assembly diline çevirir")

    arch_map = {
        "Otomatik Tespit": "auto",
        "x86 32-bit": "x86_32",
        "x86 64-bit": "x86_64",
        "ARM": "arm",
        "ARM64": "arm64",
    }
    arch_str = arch_map.get(st.session_state.get("disasm_arch", "Otomatik Tespit"), "auto")
    limit = st.session_state.get("disasm_limit", 100)

    if st.button("▶  DİSASSEMBLE ET", key="disasm_btn"):
        with st.spinner("⚙️ Disassemble ediliyor..."):
            disasm = Disassembler(file_bytes, arch=arch_str)
            result = disasm.disassemble(limit=limit)

        if result.get("error"):
            st.error(result["error"])
            return

        instructions = result.get("instructions", [])

        col1, col2, col3 = st.columns(3)
        col1.metric("Toplam Komut", len(instructions))
        col2.metric("Tespit Edilen Mimari", result.get("arch_detected", "?"))
        col3.metric("Entry Point", hex(result.get("entry_point", 0)))

        st.markdown("---")

        if instructions:
            sub_title("📊 Mnemonic Dağılımı")
            mnemonics = {}
            for ins in instructions:
                m = ins.get("mnemonic", "?")
                mnemonics[m] = mnemonics.get(m, 0) + 1

            top_mnemonics = sorted(mnemonics.items(), key=lambda x: x[1], reverse=True)[:15]
            df_mn = pd.DataFrame(top_mnemonics, columns=["Mnemonic", "Sayı"])

            fig = px.bar(
                df_mn, x="Mnemonic", y="Sayı",
                color="Sayı",
                color_continuous_scale=[[0, "#1e3d5a"], [1, "#39d98a"]],
                template="plotly_dark",
            )
            fig.update_layout(
                paper_bgcolor="#0d1117",
                plot_bgcolor="#0d1117",
                font_family="Share Tech Mono",
                font_color="#c0cfe0",
                height=280,
                margin=dict(l=0, r=0, t=10, b=0),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig, use_container_width=True)

        sub_title("💻 Assembly Kodu")
        asm_lines = []
        for ins in instructions:
            addr = f"0x{ins['address']:08x}"
            mnem = ins.get("mnemonic", "")
            ops  = ins.get("op_str", "")
            note = "  ← CALL" if mnem == "call" else ""
            asm_lines.append(f"{addr}:  {mnem:<8} {ops}{note}")

        st.code("\n".join(asm_lines), language="asm")
    else:
        st.info("Ayarları yapıp butona bas.")


# ── ENTROPİ TAB ───────────────────────────────────────────────────────────────
def render_entropy_tab(file_bytes: bytes):
    from core.entropy_analyzer import EntropyAnalyzer

    section_title("Entropi Analizi", "Yüksek entropi → packed / şifrelenmiş bölge")

    block_size = st.session_state.get("entropy_block", 256)

    with st.spinner("📊 Entropi hesaplanıyor..."):
        analyzer = EntropyAnalyzer(file_bytes, block_size=block_size)
        result = analyzer.analyze()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Ortalama Entropi", f"{result['avg_entropy']:.3f}")
    col2.metric("Max Entropi", f"{result['max_entropy']:.3f}")
    col3.metric("Min Entropi", f"{result['min_entropy']:.3f}")
    col4.metric("Packed Bölge", "⚠️ EVET" if result['is_packed'] else "✅ HAYIR")

    st.markdown("---")

    sub_title("📈 Entropi Dağılımı (blok bazlı)")
    entropies = result.get("block_entropies", [])
    if entropies:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            y=entropies,
            mode="lines",
            fill="tozeroy",
            line=dict(color="#39d98a", width=1.5),
            fillcolor="rgba(57,217,138,0.1)",
            name="Entropi",
        ))
        fig.add_hline(
            y=7.0,
            line_dash="dash",
            line_color="#e05555",
            annotation_text="Tehlike eşiği (7.0)",
            annotation_font_color="#e05555",
        )
        fig.update_layout(
            paper_bgcolor="#0d1117",
            plot_bgcolor="#0d1117",
            font_family="Share Tech Mono",
            font_color="#c0cfe0",
            xaxis_title="Blok No",
            yaxis_title="Entropi (0-8)",
            yaxis=dict(range=[0, 8.5]),
            height=350,
            margin=dict(l=0, r=0, t=10, b=0),
        )
        st.plotly_chart(fig, use_container_width=True)

    avg = result['avg_entropy']
    if avg > 7.0:
        st.error("🔴 Yüksek entropi tespit edildi! Binary muhtemelen packed veya şifrelenmiş.")
    elif avg > 6.0:
        st.warning("🟡 Orta-yüksek entropi. Bazı bölümler sıkıştırılmış olabilir.")
    else:
        st.success("🟢 Normal entropi seviyesi. Binary packed görünmüyor.")


# ── CFG TAB ───────────────────────────────────────────────────────────────────
def render_cfg_tab(file_bytes: bytes):
    from core.cfg_builder import CFGBuilder

    section_title("Control Flow Graph", "Fonksiyonlar arası çağrı ilişkilerini görselleştirir")

    func_limit = st.session_state.get("cfg_func_limit", 15)

    if st.button("🕸  CFG OLUŞTUR", key="cfg_btn"):
        with st.spinner("🕸️ Graf oluşturuluyor..."):
            builder = CFGBuilder(file_bytes)
            result = builder.build(func_limit=func_limit)

        if result.get("error"):
            st.error(result["error"])
            return

        col1, col2, col3 = st.columns(3)
        col1.metric("Düğüm (Node)", result.get("node_count", 0))
        col2.metric("Kenar (Edge)", result.get("edge_count", 0))
        col3.metric("Bileşen", result.get("component_count", 0))

        st.markdown("---")

        fig = result.get("plotly_fig")
        if fig:
            sub_title("🕸️ Çağrı Grafiği")
            st.plotly_chart(fig, use_container_width=True)

        sub_title("📋 Kenar Listesi")
        edges = result.get("edges", [])
        if edges:
            df_e = pd.DataFrame(edges, columns=["Kaynak", "Hedef"])
            st.dataframe(df_e, use_container_width=True, hide_index=True, height=250)
    else:
        st.info("CFG oluşturmak için butona bas.")


# ── RAPOR TAB ─────────────────────────────────────────────────────────────────
def render_report_tab(file_bytes: bytes, filename: str):
    from utils.report_gen import ReportGenerator

    section_title("Rapor", "Tüm analiz sonuçlarını dışa aktar")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("📄  JSON RAPOR OLUŞTUR", use_container_width=True):
            with st.spinner("Rapor hazırlanıyor..."):
                gen = ReportGenerator(file_bytes, filename)
                json_data = gen.to_json()
            st.download_button(
                "⬇ JSON İndir",
                data=json_data,
                file_name=f"{filename}_report.json",
                mime="application/json",
                use_container_width=True,
            )
            st.code(json_data[:2000] + "\n...", language="json")

    with col2:
        if st.button("🌐  HTML RAPOR OLUŞTUR", use_container_width=True):
            with st.spinner("HTML rapor hazırlanıyor..."):
                gen = ReportGenerator(file_bytes, filename)
                html_data = gen.to_html()
            st.download_button(
                "⬇ HTML İndir",
                data=html_data,
                file_name=f"{filename}_report.html",
                mime="text/html",
                use_container_width=True,
            )
            st.success("HTML rapor hazır, indir butonuna bas.")


# ── YARDIMCI FONKSİYONLAR ────────────────────────────────────────────────────
def section_title(title: str, subtitle: str = ""):
    st.markdown(f"""
    <div style="margin-bottom: 20px;">
        <div style="
            font-family: 'Share Tech Mono', monospace;
            font-size: 16px;
            color: #39d98a;
            letter-spacing: 2px;
            text-transform: uppercase;
        ">// {title}</div>
        <div style="
            font-family: 'Rajdhani', sans-serif;
            font-size: 13px;
            color: #2a4a6a;
            margin-top: 2px;
        ">{subtitle}</div>
    </div>
    """, unsafe_allow_html=True)


def sub_title(text: str):
    st.markdown(f"""
    <div style="
        font-family: 'Share Tech Mono', monospace;
        font-size: 12px;
        color: #4a7fa5;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin: 16px 0 6px 0;
        border-left: 2px solid #39d98a44;
        padding-left: 8px;
    ">{text}</div>
    """, unsafe_allow_html=True)