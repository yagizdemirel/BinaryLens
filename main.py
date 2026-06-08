import streamlit as st
from ui.components import (
    render_header,
    render_sidebar,
    render_upload_section,
    render_static_tab,
    render_disasm_tab,
    render_entropy_tab,
    render_cfg_tab,
    render_report_tab,
)

st.set_page_config(
    page_title="BinaryLens",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0a0e14;
    color: #c0cfe0;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1e2d3d;
}

/* Tab bar */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: #0d1117;
    padding: 6px 8px;
    border-radius: 8px;
    border: 1px solid #1e2d3d;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: #4a7fa5;
    background: transparent;
    border-radius: 6px;
    padding: 6px 18px;
    border: none;
}
.stTabs [aria-selected="true"] {
    background: #1a2f45 !important;
    color: #39d98a !important;
    border-bottom: 2px solid #39d98a !important;
}

/* Metric kartlar */
[data-testid="metric-container"] {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-left: 3px solid #39d98a;
    border-radius: 8px;
    padding: 12px 16px;
}
[data-testid="metric-container"] label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: #4a7fa5 !important;
    text-transform: uppercase;
    letter-spacing: 1px;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-family: 'Share Tech Mono', monospace;
    color: #39d98a !important;
    font-size: 20px;
}

/* Kod blokları */
code, pre {
    font-family: 'Share Tech Mono', monospace !important;
    background: #0d1117 !important;
    color: #39d98a !important;
    border: 1px solid #1e2d3d;
    border-radius: 6px;
}

/* Butonlar */
.stButton > button {
    font-family: 'Share Tech Mono', monospace;
    background: #0d1117;
    color: #39d98a;
    border: 1px solid #39d98a;
    border-radius: 6px;
    padding: 8px 20px;
    font-size: 13px;
    letter-spacing: 1px;
    transition: all 0.2s;
}
.stButton > button:hover {
    background: #39d98a;
    color: #0a0e14;
}

/* File uploader */
[data-testid="stFileUploader"] {
    background: #0d1117;
    border: 1px dashed #1e2d3d;
    border-radius: 10px;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #1e2d3d;
    border-radius: 8px;
}

/* Expander */
details {
    background: #0d1117 !important;
    border: 1px solid #1e2d3d !important;
    border-radius: 8px !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0e14; }
::-webkit-scrollbar-thumb { background: #1e2d3d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #39d98a44; }

/* Alert / info kutuları */
.stAlert {
    background: #0d1117;
    border: 1px solid #1e2d3d;
    border-radius: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
}

/* Progress bar */
.stProgress > div > div {
    background: linear-gradient(90deg, #39d98a, #1fb069);
}
</style>
""", unsafe_allow_html=True)


def main():
    # Session state başlat
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "uploaded_file_name" not in st.session_state:
        st.session_state.uploaded_file_name = None
    if "file_bytes" not in st.session_state:
        st.session_state.file_bytes = None

    # Header
    render_header()

    # Sidebar
    render_sidebar()

    # Ana içerik
    uploaded_file = render_upload_section()

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        st.session_state.file_bytes = file_bytes
        st.session_state.uploaded_file_name = uploaded_file.name

        st.markdown("---")

        # Sekmeler
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📋  STATİK ANALİZ",
            "⚙️  DİSASSEMBLY",
            "📊  ENTROPİ",
            "🕸️  CFG",
            "📄  RAPOR",
        ])

        with tab1:
            render_static_tab(file_bytes, uploaded_file.name)

        with tab2:
            render_disasm_tab(file_bytes)

        with tab3:
            render_entropy_tab(file_bytes)

        with tab4:
            render_cfg_tab(file_bytes)

        with tab5:
            render_report_tab(file_bytes, uploaded_file.name)

    else:
        # Karşılama ekranı
        st.markdown("""
        <div style="
            text-align: center;
            padding: 80px 20px;
            color: #2a4a6a;
        ">
            <div style="
                font-family: 'Share Tech Mono', monospace;
                font-size: 72px;
                line-height: 1;
                margin-bottom: 16px;
            ">🔬</div>
            <div style="
                font-family: 'Share Tech Mono', monospace;
                font-size: 18px;
                color: #1e3d5a;
                letter-spacing: 4px;
                text-transform: uppercase;
                margin-bottom: 8px;
            ">Analiz için binary yükle</div>
            <div style="
                font-family: 'Rajdhani', sans-serif;
                font-size: 14px;
                color: #1a2f45;
            ">PE (.exe, .dll) · ELF (Linux binary) · Raw binary</div>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()