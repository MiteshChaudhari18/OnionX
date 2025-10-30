import streamlit as st
import os
import base64
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import json
import io
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from core.tor_connector import TorConnector
from core.analysis_tool import TorAnalyzer
from core.deanonymizer import TorDeanonymizer
from core.export_utils import ExportUtils
from utils.validators import URLValidator
from utils.progress_tracker import ProgressTracker

# Page configuration
st.set_page_config(
    page_title="Tor Onion Site De-anonymizer",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Background management
def _apply_background_css(image_data_base64: str, overlay_opacity: float = 0.35, blur_px: int = 0):
    css = f"""
    <style>
    .stApp {{
        background-image: url('data:image;base64,{image_data_base64}');
        background-size: cover;
        background-attachment: fixed;
        background-position: center center;
    }}
    .stApp::before {{
        content: "";
        position: fixed;
        inset: 0;
        /* Subtle green-tinted overlay for a classy dark look */
        background: linear-gradient(180deg,
                    rgba(12, 31, 20, {overlay_opacity + 0.05 if overlay_opacity < 0.95 else overlay_opacity}),
                    rgba(10, 26, 17, {overlay_opacity + 0.10 if overlay_opacity < 0.90 else overlay_opacity})
                  );
        backdrop-filter: blur({blur_px}px);
        z-index: 0;
    }}
    .main .block-container {{
        position: relative;
        z-index: 1;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)

def _maybe_load_permanent_background():
    """Load a permanent background from env var or assets folder."""
    # Environment variable can be URL or local file path
    bg_env = os.getenv('BACKGROUND_IMAGE_URL', '').strip()
    candidates = []
    if bg_env:
        candidates.append(bg_env)
    # Fallback to bundled assets
    for name in [
        'assets/background.jpg',
        'assets/background.jpeg',
        'assets/background.png',
        'assets/background.webp',
        'attached_assets/background.jpg',
        'attached_assets/background.png'
    ]:
        candidates.append(name)

    for candidate in candidates:
        try:
            if candidate.lower().startswith('http'):
                import requests
                r = requests.get(candidate, timeout=10)
                if r.status_code == 200 and r.content:
                    return base64.b64encode(r.content).decode()
            else:
                if os.path.exists(candidate):
                    with open(candidate, 'rb') as f:
                        return base64.b64encode(f.read()).decode()
        except Exception:
            continue
    return None

# Custom CSS for enhanced UI/UX
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    :root {
        --bg-card: rgba(20, 22, 34, 0.6);
        --bg-elev: rgba(17, 19, 28, 0.6);
        --bd-soft: rgba(255, 255, 255, 0.08);
        --txt: rgba(255,255,255,0.92);
        --muted: rgba(255,255,255,0.6);
        --accent: #38bdf8;
        --accent-2: #a78bfa;
    }

    html, body, .stApp { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }

    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1180px;
    }

    .main-header {
        background: var(--bg-elev);
        border: 1px solid var(--bd-soft);
        border-radius: 16px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        text-align: center;
        backdrop-filter: saturate(120%) blur(6px);
        box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }
    .main-header h1 { color: var(--txt); font-size: 2.25rem; font-weight: 700; margin: 0 0 .25rem; letter-spacing: .2px; }
    .main-header p { color: var(--muted); font-size: 1rem; margin: 0; }

    .sidebar-section {
        background: #106a3b; /* solid classy green */
        border: 1px solid rgba(255,255,255,0.08);
        border-left: 4px solid #16a34a; /* brighter green accent */
        border-radius: 12px;
        padding: .75rem 1rem;
        margin: 1rem 0;
        color: #eafff2;
    }

    .status-connected, .status-disconnected {
        padding: .35rem .8rem; border-radius: 999px; font-weight: 600; text-align: center; display: inline-block;
    }
    .status-connected { background: rgba(34,197,94,.18); color: #b6f1c8; border: 1px solid rgba(34,197,94,.28); }
    .status-disconnected { background: rgba(239,68,68,.18); color: #ffd1d1; border: 1px solid rgba(239,68,68,.28); }

    .content-card {
        background: var(--bg-card);
        border: 1px solid var(--bd-soft);
        border-radius: 14px;
        padding: 1.25rem 1.25rem;
        margin-bottom: 1.25rem;
        backdrop-filter: blur(8px);
        box-shadow: 0 12px 26px rgba(0,0,0,.22);
    }

    .stButton > button {
        background: linear-gradient(135deg, #16a34a 0%, #22c55e 25%, #10b981 50%, #059669 75%, #047857 100%);
        border: 1px solid rgba(255,255,255,0.15);
        color: white;
        border-radius: 12px;
        padding: .6rem 1.1rem;
        font-weight: 600;
        transition: transform .12s ease, box-shadow .12s ease, background .2s ease;
        box-shadow: 0 6px 14px rgba(16, 185, 129, 0.3);
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 10px 20px rgba(16, 185, 129, 0.45);
        background: linear-gradient(135deg, #22c55e 0%, #10b981 25%, #059669 50%, #047857 75%, #16a34a 100%);
    }

    .stTabs [data-baseweb="tab-list"] { gap: 6px; background: var(--bg-elev); border: 1px solid var(--bd-soft); border-radius: 12px; padding: .35rem; }
    .stTabs [data-baseweb="tab"] { border-radius: 10px; padding: .55rem 1rem; color: var(--muted); }
    .stTabs [aria-selected="true"] { background: rgba(56,189,248,.16); color: var(--txt); border: 1px solid rgba(56,189,248,.28); }

    .stTextInput > div > div > input, .stTextArea > div > div > textarea { border-radius: 10px; border: 1px solid var(--bd-soft); background: rgba(255,255,255,.04); color: var(--txt); }

    .stProgress > div > div > div { background: linear-gradient(90deg, var(--accent), var(--accent-2)); border-radius: 8px; }

    .metric-container { background: var(--bg-elev); border-radius: 12px; padding: .9rem; text-align: center; border: 1px solid var(--bd-soft); }

    .stDataFrame { border-radius: 10px; overflow: hidden; box-shadow: 0 6px 16px rgba(0,0,0,.2); }

    .risk-low { background: rgba(34,197,94,.16); color: #c8f3d6; padding: .25rem .6rem; border-radius: 999px; font-size: .85rem; font-weight: 600; border: 1px solid rgba(34,197,94,.28); }
    .risk-medium { background: rgba(245,158,11,.16); color: #ffe1b0; padding: .25rem .6rem; border-radius: 999px; font-size: .85rem; font-weight: 600; border: 1px solid rgba(245,158,11,.28); }
    .risk-high { background: rgba(239,68,68,.16); color: #ffd1d1; padding: .25rem .6rem; border-radius: 999px; font-size: .85rem; font-weight: 600; border: 1px solid rgba(239,68,68,.28); }

    /* Sidebar background: deep green to match background image */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0e3723 0%, #0a2418 100%) !important;
        border-right: 1px solid rgba(255,255,255,0.06);
    }
    [data-testid="stSidebar"] .sidebar-content, [data-testid="stSidebar"] .block-container { background: transparent; }
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3, [data-testid="stSidebar"] p, [data-testid="stSidebar"] label, [data-testid="stSidebar"] span { color: rgba(234,255,242,0.92); }
    /* Sidebar-specific colorful accents */
    [data-testid="stSidebar"] .stButton > button {
        background: linear-gradient(135deg, #34d399 0%, #22c55e 40%, #16a34a 70%, #0ea5e9 100%);
        color: #072814;
        border: 1px solid rgba(255,255,255,0.18);
        text-shadow: 0 1px 0 rgba(255,255,255,0.35);
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        background: linear-gradient(135deg, #22c55e 0%, #34d399 30%, #0ea5e9 70%, #16a34a 100%);
        color: #052611;
        box-shadow: 0 8px 18px rgba(14,165,233,0.25);
    }
    [data-testid="stSidebar"] .status-connected { background: rgba(34,197,94,.22); color: #d7fde6; border-color: rgba(34,197,94,.4); }
    [data-testid="stSidebar"] .status-disconnected { background: rgba(239,68,68,.22); color: #ffe3e3; border-color: rgba(239,68,68,.4); }
    [data-testid="stSidebar"] .metric-container { background: rgba(11,33,23,.55); border-color: rgba(255,255,255,.08); }
    [data-testid="stSidebar"] .sidebar-section h2, [data-testid="stSidebar"] .sidebar-section h3 { color: #e9fff3; }
</style>
""", unsafe_allow_html=True)

def init_session_state():
    """Initialize session state variables"""
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = []
    if 'search_history' not in st.session_state:
        st.session_state.search_history = []
    if 'tor_connected' not in st.session_state:
        st.session_state.tor_connected = False
    if 'bg_image_b64' not in st.session_state:
        st.session_state.bg_image_b64 = None
    if 'bg_overlay_opacity' not in st.session_state:
        st.session_state.bg_overlay_opacity = 0.35
    if 'bg_blur_px' not in st.session_state:
        st.session_state.bg_blur_px = 0
    # Initialize from permanent background if present
    if 'bg_initialized' not in st.session_state:
        default_b64 = _maybe_load_permanent_background()
        if default_b64:
            st.session_state.bg_image_b64 = default_b64
        st.session_state.bg_initialized = True
    if 'result_cache' not in st.session_state:
        st.session_state.result_cache = {}

def load_sample_data():
    """Load sample URLs for demonstration"""
    try:
        with open('data/sample_urls.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"sample_urls": []}

def main():
    init_session_state()
    # Apply background if user provided one
    if st.session_state.bg_image_b64:
        _apply_background_css(
            st.session_state.bg_image_b64,
            overlay_opacity=st.session_state.bg_overlay_opacity,
            blur_px=st.session_state.bg_blur_px
        )
    
    # Enhanced Header
    st.markdown("""
    <div class="main-header">
        <h1 style="background: linear-gradient(90deg, #fff, #a5b4fc, #22d3ee); -webkit-background-clip: text; background-clip: text; color: transparent;">🕵️ Tor Onion Site De-anonymizer</h1>
        <p>Advanced OSINT Analysis Tool for Tor Network Entities</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced Sidebar
    with st.sidebar:
        st.markdown('<div class="sidebar-section"><h2>⚙️ Configuration</h2></div>', unsafe_allow_html=True)
        
        # Tor connection status with enhanced styling
        st.markdown('<div class="sidebar-section"><h3>🔌 Tor Connection</h3></div>', unsafe_allow_html=True)
        tor_connector = TorConnector()
        
        if st.button("🔍 Check Tor Connection", key="tor_check_btn"):
            with st.spinner("🔄 Checking Tor connection..."):
                status = tor_connector.check_connection()
                if status:
                    st.success("✅ Tor connection active")
                    st.session_state.tor_connected = True
                else:
                    st.error("❌ Tor connection failed")
                    st.session_state.tor_connected = False

        # Rotate Tor identity
        if st.button("♻️ Rotate Tor Identity", key="tor_rotate_btn"):
            with st.spinner("Requesting new Tor identity..."):
                if tor_connector.new_identity():
                    st.success("✅ New identity requested. Wait a few seconds and re-check.")
                else:
                    st.warning("⚠️ Could not rotate identity. Ensure Tor control port 9051 is open and stem is installed.")

        # Display current proxy diagnostics for deployments
        st.caption(f"Proxy target: {tor_connector.get_proxy_target()} (set TOR_PROXY_HOST / TOR_PROXY_PORT for Render or servers)")
        
        # Enhanced status display
        if st.session_state.tor_connected:
            st.markdown('<div class="status-connected">🟢 Tor Status: Connected</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="status-disconnected">🔴 Tor Status: Disconnected</div>', unsafe_allow_html=True)
        
        # (Appearance controls removed by request)
        
        # Enhanced Analysis options
        st.markdown('<div class="sidebar-section"><h3>🎯 Analysis Options</h3></div>', unsafe_allow_html=True)
        
        with st.container():
            deep_analysis = st.checkbox("🔬 Deep OSINT Analysis", value=True, help="Comprehensive analysis using multiple OSINT sources")
            metadata_extraction = st.checkbox("📋 Metadata Extraction", value=True, help="Extract technical details and fingerprints")
            cross_reference = st.checkbox("🔄 Cross-reference Databases", value=True, help="Check against threat intelligence databases")
        
        st.markdown("---")
        
        # Enhanced Search history
        st.markdown('<div class="sidebar-section"><h3>📚 Search History</h3></div>', unsafe_allow_html=True)
        
        if st.session_state.search_history:
            st.markdown("**Recent searches:**")
            for i, url in enumerate(reversed(st.session_state.search_history[-5:]), 1):
                truncated_url = url[:30] + "..." if len(url) > 30 else url
                st.markdown(f"🔸 `{truncated_url}`")
        else:
            st.info("💡 No search history yet")
        
        if st.button("🗑️ Clear History", key="clear_history_btn"):
            st.session_state.search_history = []
            st.rerun()

    # Enhanced Main content area with modern tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Analysis", "📊 Results", "📥 Export", "📚 Help"])
    
    # Add some spacing
    st.markdown("<br>", unsafe_allow_html=True)
    
    with tab1:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        st.markdown("### 🎯 URL Analysis")
        st.markdown("Enter onion URLs for comprehensive analysis and de-anonymization")
        
        # Enhanced Input methods with better styling
        st.markdown("#### 📝 Choose Input Method")
        input_method = st.radio(
            "Select how you want to provide URLs:",
            ["Single URL", "Multiple URLs", "File Upload"],
            horizontal=True
        )
        
        urls_to_analyze = []
        
        if input_method == "Single URL":
            st.markdown("##### 🔗 Single URL Input")
            url_input = st.text_input(
                "Enter Onion URL:",
                placeholder="http://example.onion",
                help="Enter a single .onion URL for analysis"
            )
            if url_input:
                urls_to_analyze = [url_input]
                
        elif input_method == "Multiple URLs":
            st.markdown("##### 📝 Multiple URLs Input")
            urls_text = st.text_area(
                "Enter URLs (one per line):",
                height=150,
                placeholder="http://example1.onion\nhttp://example2.onion\nhttp://example3.onion",
                help="Enter multiple .onion URLs, one per line"
            )
            if urls_text:
                urls_to_analyze = [url.strip() for url in urls_text.split('\n') if url.strip()]
                
        elif input_method == "File Upload":
            st.markdown("##### 📁 File Upload")
            uploaded_file = st.file_uploader(
                "Upload text file with URLs",
                type=['txt'],
                help="Upload a .txt file containing onion URLs (one per line)"
            )
            if uploaded_file:
                content = uploaded_file.read().decode('utf-8')
                urls_to_analyze = [url.strip() for url in content.split('\n') if url.strip()]
        
        # Enhanced Sample data section
        sample_data = load_sample_data()
        if sample_data.get("sample_urls"):
            st.markdown("---")
            st.markdown("##### 🧪 Sample Data")
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.info("💡 Use sample URLs to test the application functionality")
            
            with col2:
                if st.button("🚀 Load Sample URLs", key="load_samples"):
                    urls_to_analyze = sample_data["sample_urls"]
                    st.success(f"✅ Loaded {len(urls_to_analyze)} sample URLs")
        
        # Enhanced Validation and analysis section
        if urls_to_analyze:
            st.markdown("---")
            st.markdown("### 🔍 URL Validation & Analysis")
            
            # Validate URLs
            validator = URLValidator()
            valid_urls = []
            invalid_urls = []
            
            for url in urls_to_analyze:
                if validator.is_valid_onion_url(url):
                    valid_urls.append(url)
                else:
                    invalid_urls.append(url)
            
            # Enhanced validation results display
            col1, col2, col3 = st.columns([2, 2, 1])
            
            with col1:
                if valid_urls:
                    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
                    st.metric("✅ Valid URLs", len(valid_urls))
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    with st.expander("📋 View Valid URLs", expanded=False):
                        for i, url in enumerate(valid_urls, 1):
                            st.markdown(f"**{i}.** `{url}`")
            
            with col2:
                if invalid_urls:
                    st.markdown('<div class="metric-container">', unsafe_allow_html=True)
                    st.metric("❌ Invalid URLs", len(invalid_urls))
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    with st.expander("⚠️ View Invalid URLs", expanded=False):
                        for i, url in enumerate(invalid_urls, 1):
                            st.markdown(f"**{i}.** `{url}`")
            
            with col3:
                # Enhanced Analysis button
                if valid_urls:
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("🚀 Start Analysis", type="primary", key="start_analysis_btn"):
                        if not st.session_state.tor_connected:
                            st.error("🔒 Please establish Tor connection first!")
                        else:
                            perform_analysis(valid_urls, deep_analysis, metadata_extraction, cross_reference)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab2:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_results()
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab3:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_export_options()
        st.markdown('</div>', unsafe_allow_html=True)
    
    with tab4:
        st.markdown('<div class="content-card">', unsafe_allow_html=True)
        display_help()
        st.markdown('</div>', unsafe_allow_html=True)

def perform_analysis(urls: List[str], deep_analysis: bool, metadata_extraction: bool, cross_reference: bool):
    """Perform the actual analysis of URLs"""
    st.subheader("🔍 Analysis in Progress")
    
    # Initialize components
    analyzer = TorAnalyzer()
    deanonymizer = TorDeanonymizer()
    progress_tracker = ProgressTracker()
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    results = []

    # Respect concurrency limit from env
    max_workers = int(os.getenv('ANALYSIS_MAX_WORKERS', '4'))

    def process_single(url: str, index: int) -> Dict[str, Any]:
        # Cache hit
        if url in st.session_state.result_cache:
            cached = st.session_state.result_cache[url]
            return {**cached, 'analysis_id': f"cached_{int(time.time())}_{index}"}

        basic_result = analyzer.analyze_url(url)
        if deep_analysis:
            osint_result = deanonymizer.perform_osint_analysis(url, basic_result)
            basic_result.update(osint_result)
        if metadata_extraction:
            metadata = analyzer.extract_metadata(url)
            basic_result['metadata'] = metadata
        if cross_reference:
            cross_ref_result = deanonymizer.cross_reference_databases(basic_result)
            basic_result['cross_references'] = cross_ref_result
        basic_result['url'] = url
        basic_result['timestamp'] = datetime.now().isoformat()
        basic_result['analysis_id'] = f"analysis_{int(time.time())}_{index}"
        # Write-through cache
        st.session_state.result_cache[url] = basic_result
        return basic_result

    st.toast("Analysis started. You can navigate to other tabs while it runs.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_meta = {executor.submit(process_single, url, i): (i, url) for i, url in enumerate(urls)}
        completed = 0
        total = len(future_to_meta)
        for future in as_completed(future_to_meta):
            i, url = future_to_meta[future]
            try:
                result = future.result()
            except Exception as e:
                st.error(f"Error analyzing {url}: {str(e)}")
                result = {
                    'url': url,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat(),
                    'analysis_id': f"error_{int(time.time())}_{i}"
                }
            results.append(result)
            completed += 1
            progress_bar.progress(completed / total)
            status_text.text(f"Analyzed {completed}/{total}: {url}")
            if url not in st.session_state.search_history:
                st.session_state.search_history.append(url)
    
    # Store results
    st.session_state.analysis_results.extend(results)
    
    # Complete
    progress_bar.progress(1.0)
    status_text.text("✅ Analysis completed!")
    
    st.success(f"Successfully analyzed {len(results)} URLs. Check the Results tab.")
    st.toast("Analysis completed.")
    time.sleep(2)
    st.rerun()

def display_results():
    """Display analysis results with enhanced styling"""
    st.markdown("### 📊 Analysis Results")
    st.markdown("View comprehensive analysis results and insights")
    
    if not st.session_state.analysis_results:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; background: rgba(255, 255, 255, 0.05); border-radius: 15px; border: 2px dashed rgba(255, 255, 255, 0.2);">
            <h3>🔍 No Results Yet</h3>
            <p>Run an analysis to see comprehensive results here</p>
            <p style="opacity: 0.7;">Go to the Analysis tab to get started</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Enhanced Results overview with modern styling
    total_results = len(st.session_state.analysis_results)
    successful_results = len([r for r in st.session_state.analysis_results if 'error' not in r])
    error_results = total_results - successful_results
    
    st.markdown("#### 📈 Overview")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🎯 Total", total_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("✅ Success", successful_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("❌ Errors", error_results)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        success_rate = (successful_results / total_results * 100) if total_results > 0 else 0
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("📊 Success Rate", f"{success_rate:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Enhanced Results visualization
    if successful_results > 0:
        st.markdown("---")
        st.markdown("#### 📊 Risk Assessment Overview")
        
        # Create enhanced risk assessment chart
        risk_levels = []
        for result in st.session_state.analysis_results:
            if 'error' not in result and 'risk_level' in result:
                risk_levels.append(result['risk_level'])
        
        if risk_levels:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                risk_df = pd.DataFrame({'Risk Level': risk_levels})
                fig = px.histogram(
                    risk_df, 
                    x='Risk Level', 
                    title="Risk Level Distribution",
                    color_discrete_sequence=['#00d4aa', '#f39c12', '#e74c3c']
                )
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='white'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("##### 🏷️ Risk Categories")
                risk_counts = pd.Series(risk_levels).value_counts()
                for risk, count in risk_counts.items():
                    risk_class = f"risk-{risk.lower()}" if risk.lower() in ['low', 'medium', 'high'] else "risk-medium"
                    st.markdown(f'<span class="{risk_class}">{risk.title()}: {count}</span>', unsafe_allow_html=True)
                    st.markdown("<br>", unsafe_allow_html=True)
    
    # Enhanced Detailed results table
    st.markdown("---")
    st.markdown("#### 📋 Detailed Results")
    
    # Create enhanced results dataframe with geolocation info
    results_data = []
    for result in st.session_state.analysis_results:
        # Extract geolocation information
        location_info = "Unknown"
        ip_info = "Not resolved"
        
        if 'location_summary' in result and result['location_summary']:
            loc_summary = result['location_summary']
            most_likely = loc_summary.get('most_likely_location', {})
            if most_likely:
                country = most_likely.get('country', 'Unknown')
                city = most_likely.get('city', '')
                location_info = f"{city}, {country}" if city else country
        
        if 'geolocation_analysis' in result:
            geo_analysis = result['geolocation_analysis']
            resolved_ips = geo_analysis.get('resolved_ips', [])
            exit_nodes = geo_analysis.get('exit_nodes_used', [])
            
            if resolved_ips:
                ip_info = f"{len(resolved_ips)} IPs resolved"
            elif exit_nodes:
                ip_info = f"{len(exit_nodes)} exit nodes"
            else:
                ip_info = "Tor-only (no IP leaks)"
        
        row = {
            'URL': result.get('url', 'Unknown'),
            'Status': '✅ Success' if 'error' not in result else '❌ Error',
            'Location': location_info,
            'IP Status': ip_info,
            'Risk Level': result.get('risk_level', 'Unknown'),
            'Entities Found': len(result.get('entities', [])) if 'entities' in result else 0,
            'Analysis Score': f"{result.get('analysis_score', 0)}%" if 'analysis_score' in result else 'N/A'
        }
        results_data.append(row)
    
    if results_data:
        results_df = pd.DataFrame(results_data)
        
        # Style the dataframe
        styled_df = results_df.style.apply(lambda x: ['background-color: rgba(0, 212, 170, 0.1)' if '✅' in str(x.Status) 
                                                     else 'background-color: rgba(231, 76, 60, 0.1)' for _ in x], axis=1)
        
        st.dataframe(styled_df, use_container_width=True)
        
        # Detailed view selector
        st.subheader("Detailed View")
        selected_analysis = st.selectbox(
            "Select analysis for detailed view:",
            options=range(len(st.session_state.analysis_results)),
            format_func=lambda x: f"{st.session_state.analysis_results[x]['url']} - {st.session_state.analysis_results[x].get('timestamp', 'Unknown')}"
        )
        
        if selected_analysis is not None:
            display_detailed_result(st.session_state.analysis_results[selected_analysis])

def display_detailed_result(result: Dict[str, Any]):
    """Display detailed result for a single analysis"""
    st.subheader(f"Detailed Analysis: {result['url']}")
    
    if 'error' in result:
        st.error(f"Analysis failed: {result['error']}")
        return
    
    # Basic information
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Basic Information**")
        st.write(f"- URL: {result['url']}")
        st.write(f"- Analysis Time: {result.get('timestamp', 'Unknown')}")
        st.write(f"- Risk Level: {result.get('risk_level', 'Unknown')}")
        st.write(f"- Response Code: {result.get('response_code', 'Unknown')}")
    
    with col2:
        st.write("**Technical Details**")
        st.write(f"- Server: {result.get('server_info', 'Unknown')}")
        st.write(f"- Content Type: {result.get('content_type', 'Unknown')}")
        st.write(f"- Page Size: {result.get('page_size', 'Unknown')} bytes")
        st.write(f"- Load Time: {result.get('load_time', 'Unknown')}s")
    
    # Entities found
    if 'entities' in result and result['entities']:
        st.subheader("🎯 Entities Found")
        entities_df = pd.DataFrame(result['entities'])
        st.dataframe(entities_df, use_container_width=True)
    
    # OSINT sources
    if 'osint_sources' in result and result['osint_sources']:
        st.subheader("🔍 OSINT Sources")
        for source in result['osint_sources']:
            with st.expander(f"Source: {source.get('name', 'Unknown')}"):
                st.json(source)
    
    # Geolocation Analysis
    if 'geolocation_analysis' in result:
        display_geolocation_details(result['geolocation_analysis'])
    
    if 'location_summary' in result:
        display_location_summary(result['location_summary'])
    
    # Metadata
    if 'metadata' in result and result['metadata']:
        st.subheader("📋 Metadata")
        st.json(result['metadata'])

def display_export_options():
    """Display enhanced export options"""
    st.markdown("### 📥 Export Results")
    st.markdown("Download your analysis results in multiple formats")
    
    if not st.session_state.analysis_results:
        st.markdown("""
        <div style="text-align: center; padding: 3rem; background: rgba(255, 255, 255, 0.05); border-radius: 15px; border: 2px dashed rgba(255, 255, 255, 0.2);">
            <h3>📄 No Data to Export</h3>
            <p>Run an analysis to generate exportable results</p>
            <p style="opacity: 0.7;">Results will appear here after successful analysis</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    st.markdown("#### 💾 Available Export Formats")
    st.markdown("Choose your preferred format for downloading analysis results")
    
    export_utils = ExportUtils()
    
    # Enhanced export options with better styling
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📊 CSV Export")
        st.markdown("Spreadsheet format for data analysis")
        
        if st.button("📊 Generate CSV", key="csv_export", use_container_width=True):
            csv_data = export_utils.to_csv(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📄 JSON Export")
        st.markdown("Structured data for programming")
        
        if st.button("📄 Generate JSON", key="json_export", use_container_width=True):
            json_data = export_utils.to_json(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download JSON",
                data=json_data,
                file_name=f"tor_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="content-card hover-card" style="text-align: center; padding: 2rem;">', unsafe_allow_html=True)
        st.markdown("#### 📑 PDF Report")
        st.markdown("Professional report format")
        
        if st.button("📑 Generate PDF", key="pdf_export", use_container_width=True):
            pdf_data = export_utils.to_pdf(st.session_state.analysis_results)
            st.download_button(
                label="⬇️ Download PDF",
                data=pdf_data,
                file_name=f"tor_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Enhanced clear results option
    st.markdown("---")
    st.markdown("#### 🗑️ Data Management")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        st.info("⚠️ This will permanently delete all analysis results and search history")
    
    with col2:
        if st.button("🗑️ Clear All Data", type="secondary", key="clear_all_data"):
            st.session_state.analysis_results = []
            st.session_state.search_history = []
            st.success("✅ All data cleared successfully!")
            st.rerun()

def display_help():
    """Display help and documentation"""
    st.header("📚 Help & Documentation")
    
    st.markdown("""
    ## Overview
    This application performs de-anonymization analysis of Tor onion sites using various OSINT techniques.
    
    ## How to Use
    
    ### 1. Setup Tor Connection
    - Ensure Tor is running on your system (usually on port 9050)
    - Click "Check Tor Connection" in the sidebar to verify connectivity
    
    ### 2. Input URLs
    - Enter single or multiple onion URLs
    - Upload a text file with URLs (one per line)
    - Use sample URLs for testing
    
    ### 3. Configure Analysis
    - **Deep OSINT Analysis**: Performs comprehensive analysis using multiple sources
    - **Metadata Extraction**: Extracts and analyzes page metadata
    - **Cross-reference Databases**: Checks against known databases and sources
    
    ### 4. Review Results
    - View summary statistics and risk assessments
    - Examine detailed results for each URL
    - Export results in CSV, JSON, or PDF format
    
    ## Analysis Components
    
    ### Risk Assessment
    - **Low**: Standard onion site with no suspicious indicators
    - **Medium**: Some indicators present, requires further investigation
    - **High**: Multiple red flags, likely compromised or monitored
    - **Critical**: Immediate security concerns identified
    
    ### OSINT Sources
    - Reverse WHOIS lookups
    - Shodan database queries
    - Certificate transparency logs
    - Domain reputation services
    - Social media cross-references
    
    ### Metadata Analysis
    - HTTP headers analysis
    - SSL/TLS certificate information
    - Server fingerprinting
    - Content analysis
    - Link structure mapping
    
    ## Privacy & Security
    - All analysis is performed through Tor proxy
    - No logs are stored permanently
    - Results are kept only in session memory
    - Use responsibly and in accordance with applicable laws
    
    ## Troubleshooting
    
    ### Tor Connection Issues
    - Ensure Tor is installed and running
    - Check that port 9050 is accessible
    - Verify proxy settings
    
    ### Analysis Failures
    - Check URL format (must be valid .onion address)
    - Ensure target site is accessible
    - Some sites may block automated access
    
    ## Disclaimer
    This tool is for educational and research purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations.
    """)

def display_geolocation_details(geo_analysis: Dict[str, Any]):
    """Display detailed geolocation analysis results"""
    st.markdown("---")
    st.markdown("### 🌍 IP Address & Geolocation Analysis")
    
    # Resolution attempts
    if 'resolution_attempts' in geo_analysis:
        st.markdown("#### 🔍 IP Resolution Attempts")
        for attempt in geo_analysis['resolution_attempts']:
            method = attempt.get('method', 'Unknown')
            success = attempt.get('success', False)
            status_icon = "✅" if success else "❌"
            
            with st.expander(f"{status_icon} {method.replace('_', ' ').title()}"):
                st.json(attempt)
    
    # Exit nodes used
    if 'exit_nodes_used' in geo_analysis and geo_analysis['exit_nodes_used']:
        st.markdown("#### 🚪 Tor Exit Nodes Detected")
        exit_nodes_df = pd.DataFrame(geo_analysis['exit_nodes_used'])
        st.dataframe(exit_nodes_df, use_container_width=True)
    
    # Resolved IPs
    if 'resolved_ips' in geo_analysis and geo_analysis['resolved_ips']:
        st.markdown("#### 📍 Resolved IP Addresses")
        for ip in geo_analysis['resolved_ips']:
            st.code(ip)
    
    # Geolocation data
    if 'geolocation_data' in geo_analysis and geo_analysis['geolocation_data']:
        st.markdown("#### 🗺️ Geolocation Details")
        for i, geo_data in enumerate(geo_analysis['geolocation_data']):
            with st.expander(f"🌐 Location Data {i+1} - {geo_data.get('ip_address', 'Unknown IP')}"):
                location = geo_data.get('location_data', {})
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Geographic Information**")
                    st.write(f"🏳️ Country: {location.get('country', 'Unknown')}")
                    st.write(f"🏙️ City: {location.get('city', 'Unknown')}")
                    st.write(f"📍 Region: {location.get('region', 'Unknown')}")
                    st.write(f"📮 ZIP Code: {location.get('zip_code', 'Unknown')}")
                    st.write(f"🌍 Coordinates: {location.get('latitude', 0)}, {location.get('longitude', 0)}")
                
                with col2:
                    st.markdown("**Network Information**")
                    st.write(f"🏢 ISP: {location.get('isp', 'Unknown')}")
                    st.write(f"🌐 Organization: {location.get('org', 'Unknown')}")
                    st.write(f"🔢 AS Number: {location.get('as_number', 'Unknown')}")
                    st.write(f"🕐 Timezone: {location.get('timezone', 'Unknown')}")
                    st.write(f"📊 Provider: {geo_data.get('provider', 'Unknown')}")

def display_location_summary(location_summary: Dict[str, Any]):
    """Display location summary with enhanced styling"""
    st.markdown("---")
    st.markdown("### 📊 Location Intelligence Summary")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🎯 IPs Analyzed", location_summary.get('total_ips_analyzed', 0))
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        countries = location_summary.get('countries_detected', [])
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🌍 Countries", len(countries))
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        confidence = location_summary.get('confidence_score', 0)
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🎯 Confidence", f"{confidence:.0f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Most likely location
    most_likely = location_summary.get('most_likely_location')
    if most_likely:
        st.markdown("#### 📍 Most Likely Location")
        
        country = most_likely.get('country', 'Unknown')
        city = most_likely.get('city', '')
        confidence_level = most_likely.get('confidence', 'unknown')
        
        location_text = f"{city}, {country}" if city else country
        confidence_class = f"risk-{confidence_level.lower()}" if confidence_level.lower() in ['low', 'medium', 'high'] else "risk-medium"
        
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: rgba(0, 212, 170, 0.1); border-radius: 10px; margin: 1rem 0;">
            <h3 style="margin: 0;">🗺️ {location_text}</h3>
            <span class="{confidence_class}">Confidence: {confidence_level.title()}</span>
        </div>
        """, unsafe_allow_html=True)
    
    # Detected entities
    col1, col2 = st.columns(2)
    
    with col1:
        countries = location_summary.get('countries_detected', [])
        if countries:
            st.markdown("##### 🌍 Countries Detected")
            for country in countries:
                st.markdown(f"🏳️ {country}")
    
    with col2:
        isps = location_summary.get('isps_detected', [])
        if isps:
            st.markdown("##### 🏢 ISPs Detected")
            for isp in isps[:5]:  # Show top 5
                st.markdown(f"🌐 {isp}")
    
    # Security indicators
    hosting_detected = location_summary.get('hosting_detected', [])
    proxy_detected = location_summary.get('proxy_detected', [])
    
    if hosting_detected or proxy_detected:
        st.markdown("##### ⚠️ Security Indicators")
        if hosting_detected:
            st.warning(f"🏢 Hosting services detected: {len(hosting_detected)} IPs")
        if proxy_detected:
            st.warning(f"🔒 Proxy services detected: {len(proxy_detected)} IPs")

if __name__ == "__main__":
    main()
