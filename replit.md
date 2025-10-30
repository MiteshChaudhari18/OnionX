# Overview

A comprehensive Streamlit-based web application for analyzing and de-anonymizing entities on Tor network onion sites using advanced OSINT (Open Source Intelligence) techniques. The application provides a modern web interface for security researchers and investigators to perform deep analysis of onion sites, extract metadata, identify potential entities, and correlate findings across multiple intelligence sources. The tool emphasizes educational and authorized security testing use cases.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Web Application Framework
- **Frontend**: Streamlit-based web application providing a modern, responsive interface
- **Backend**: Modular Python architecture with separate core analysis modules
- **Deployment**: Designed for cloud deployment on platforms like Render without GUI dependencies

## Core Analysis Engine
- **TorConnector**: Manages Tor proxy connections (SOCKS5 proxy on port 9050) and validates connectivity
- **TorAnalyzer**: Performs comprehensive onion site analysis including HTTP response analysis, content extraction, and technical fingerprinting
- **TorDeanonymizer**: Advanced de-anonymization using OSINT sources and correlation techniques
- **OSINTTools**: Collection of tools for SSL certificate analysis, domain reputation checks, and threat intelligence

## Data Processing & Export
- **ExportUtils**: Multi-format export capabilities (CSV, JSON, PDF) with comprehensive report generation
- **ProgressTracker**: Real-time progress tracking with threading support for long-running analysis operations
- **URLValidator**: Input validation for onion URLs and domains using regex patterns for v2/v3 onion addresses

## Session Management
- Streamlit session state for analysis results persistence
- Search history tracking and management
- Real-time progress updates during analysis operations

## Security & Validation
- Comprehensive input validation for onion URLs
- Risk assessment scoring based on multiple security indicators
- Rate limiting for OSINT API calls to prevent abuse
- Environment variable configuration for sensitive API keys

# External Dependencies

## Core Web Framework
- **Streamlit**: Main web application framework for UI and user interactions
- **Pandas**: Data manipulation and analysis for results processing
- **Plotly**: Interactive data visualization and charting capabilities

## Web Scraping & Analysis
- **Requests**: HTTP client library with SOCKS proxy support for Tor connections
- **BeautifulSoup4**: HTML parsing and content extraction
- **Trafilatura**: Advanced web content extraction and text analysis
- **PySocks**: SOCKS proxy support for Tor network connectivity

## OSINT & Security APIs
- **Shodan API**: Infrastructure and device intelligence (requires SHODAN_API_KEY)
- **VirusTotal API**: Malware and threat intelligence (requires VIRUSTOTAL_API_KEY)
- **Censys API**: Internet-wide scanning data (requires CENSYS_API_ID and CENSYS_API_SECRET)
- **SecurityTrails API**: DNS and domain intelligence (optional)
- **FullHunt API**: Attack surface intelligence (optional)

## Report Generation
- **ReportLab**: PDF generation for comprehensive analysis reports
- **CSV/JSON**: Native Python support for structured data export

## Tor Network Integration
- **Tor Proxy**: Requires Tor service running locally on port 9050
- **Control Port**: Optional Tor control port access on port 9051
- **Certificate Transparency**: Integration with CT logs for SSL certificate analysis

## Data Storage
- **JSON Files**: Sample data and configuration storage
- **Session State**: In-memory storage for analysis results and user preferences
- **Environment Variables**: Secure storage of API keys and configuration parameters