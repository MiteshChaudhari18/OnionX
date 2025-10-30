# Tor Onion Site De-anonymizer

A comprehensive Streamlit-based web application for analyzing and de-anonymizing entities on Tor network onion sites using advanced OSINT (Open Source Intelligence) techniques.

## ⚠️ Legal Disclaimer

This tool is designed for educational, research, and authorized security testing purposes only. Users are solely responsible for ensuring their use complies with applicable laws and regulations. The developers assume no responsibility for misuse of this software.

## 🎯 Features

### Core Analysis Capabilities
- **Comprehensive URL Analysis**: Deep analysis of onion site structure, content, and technical details
- **OSINT Integration**: Cross-reference findings against multiple intelligence sources
- **Metadata Extraction**: Extract and analyze page metadata, headers, and technical fingerprints
- **Risk Assessment**: Automated risk scoring based on multiple security indicators
- **Entity Detection**: Identify emails, cryptocurrency addresses, social media references, and other entities

### Advanced De-anonymization Techniques
- **Certificate Transparency Analysis**: Check SSL certificates against transparency logs
- **Domain Reputation Checking**: Analyze domain patterns and reputation scores
- **Hosting Pattern Analysis**: Identify infrastructure and hosting characteristics
- **Content Fingerprinting**: Generate and compare content signatures
- **Cross-Reference Databases**: Check against threat intelligence and OSINT databases

### User Interface
- **Modern Web Interface**: Clean, responsive Streamlit-based UI
- **Real-time Progress Tracking**: Live updates during analysis operations
- **Interactive Results**: Tables, charts, and detailed analysis views
- **Export Capabilities**: CSV, JSON, and PDF export options
- **Session Management**: Search history and result persistence

## 🚀 Quick Start

### Prerequisites

1. **Tor Installation**: Ensure Tor is installed and running on your system
2. **Python 3.8+**: Required for the application
3. **System Dependencies**: See requirements section below

### Installation

1. **Clone or extract the application files**
2. **Install Python dependencies**:
   ```bash
   pip install streamlit pandas plotly requests beautifulsoup4 trafilatura reportlab
   pip install PySocks  # For SOCKS proxy support
   ```

3. **Start Tor service**:
   ```bash
   # On Ubuntu/Debian
   sudo systemctl start tor
   
   # On macOS with Homebrew
   brew services start tor
   
   # On Windows, start Tor Browser or use Tor service
   ```

4. **Verify Tor is running** (default port 9050):
   ```bash
   netstat -an | grep 9050
   ```

### Running the Application

1. **Start the application**:
   ```bash
   streamlit run app.py --server.port 5000
   ```

2. **Access the web interface**:
   - Open your browser to `http://localhost:5000`
   - The application will be accessible on this address

3. **Initial Setup**:
   - Click "Check Tor Connection" in the sidebar to verify connectivity
   - Configure analysis options as needed
   - Load sample URLs or input your own onion addresses

## 🔧 Configuration

### Environment Variables

Set these environment variables for enhanced functionality:

```bash
# Tor Configuration
export TOR_PROXY_HOST=127.0.0.1
export TOR_PROXY_PORT=9050
export TOR_CONTROL_PORT=9051
export TOR_TIMEOUT=30

# API Keys (optional but recommended)
export SHODAN_API_KEY=your_shodan_api_key
export VIRUSTOTAL_API_KEY=your_virustotal_api_key
export CENSYS_API_ID=your_censys_api_id
export CENSYS_API_SECRET=your_censys_api_secret
export SECURITYTRAILS_API_KEY=your_securitytrails_api_key
