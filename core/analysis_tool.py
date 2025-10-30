import requests
from bs4 import BeautifulSoup
import trafilatura
import time
import hashlib
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional
import ssl
import socket
from datetime import datetime

from .tor_connector import TorConnector
from .geolocation import GeolocationAnalyzer

class TorAnalyzer:
    """Core analysis tool for Tor onion sites"""
    
    def __init__(self):
        self.tor_connector = TorConnector()
        self.geolocation_analyzer = GeolocationAnalyzer()
        self.session = None
        self.timeout = 30
        
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of an onion URL"""
        
        if not self.session:
            self.session = self.tor_connector.get_session()
        
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'comprehensive'
        }
        
        try:
            # Basic HTTP analysis
            result.update(self._analyze_http_response(url))
            
            # Content analysis
            if result.get('content'):
                result.update(self._analyze_content(result['content']))
            
            # Technical fingerprinting
            result.update(self._analyze_technical_details(url))
            
            # IP and Geolocation analysis
            geo_analysis = self.geolocation_analyzer.resolve_onion_to_ip(url)
            result['geolocation_analysis'] = geo_analysis
            
            # Generate location summary
            if geo_analysis.get('geolocation_data'):
                result['location_summary'] = self.geolocation_analyzer.generate_location_summary(
                    geo_analysis['geolocation_data']
                )
            
            # Risk assessment
            result['risk_level'] = self._assess_risk(result)
            
            # Generate analysis score
            result['analysis_score'] = self._calculate_analysis_score(result)
            
        except Exception as e:
            result['error'] = str(e)
            result['risk_level'] = 'unknown'
        
        return result
    
    def _analyze_http_response(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP response and headers"""
        result = {}
        
        try:
            start_time = time.time()
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            load_time = time.time() - start_time
            
            result.update({
                'response_code': response.status_code,
                'load_time': round(load_time, 2),
                'final_url': response.url,
                'redirects': len(response.history),
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'server_info': response.headers.get('server', 'unknown'),
                'headers': dict(response.headers),
                'content': response.text if response.status_code == 200 else None
            })
            
            # Analyze security headers
            result['security_headers'] = self._analyze_security_headers(response.headers)
            
            # Check for common frameworks/technologies
            result['technologies'] = self._detect_technologies(response)
            
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error'
        except Exception as e:
            result['error'] = f'HTTP analysis failed: {str(e)}'
        
        return result
    
    def _analyze_content(self, content: str) -> Dict[str, Any]:
        """Analyze page content for patterns and information"""
        result = {}
        
        try:
            # Parse with BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract basic page info
            result['title'] = soup.title.string if soup.title else None
            result['meta_description'] = self._get_meta_content(soup, 'description')
            result['meta_keywords'] = self._get_meta_content(soup, 'keywords')
            
            # Extract text content
            text_content = trafilatura.extract(content) if content else ""
            result['text_content_length'] = len(text_content) if text_content else 0
            
            # Analyze links
            result['links'] = self._analyze_links(soup)
            
            # Look for forms
            result['forms'] = self._analyze_forms(soup)
            
            # Search for email addresses
            result['emails'] = self._extract_emails(content)
            
            # Search for cryptocurrency addresses
            result['crypto_addresses'] = self._extract_crypto_addresses(content)
            
            # Language detection
            result['language'] = self._detect_language(soup)
            
            # Look for social media references
            result['social_media'] = self._extract_social_media(content)
            
            # Search for onion addresses
            result['onion_links'] = self._extract_onion_links(content)
            
            # Content fingerprinting
            result['content_hash'] = hashlib.sha256(content.encode()).hexdigest()
            
        except Exception as e:
            result['content_analysis_error'] = str(e)
        
        return result
    
    def _analyze_technical_details(self, url: str) -> Dict[str, Any]:
        """Analyze technical aspects of the service"""
        result = {}
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # SSL/TLS analysis for HTTPS
            if parsed_url.scheme == 'https':
                result['ssl_info'] = self._analyze_ssl(hostname, port)
            
            # Server response timing analysis
            result['timing_analysis'] = self._analyze_timing(url)
            
            # Check for common admin/test pages
            result['admin_pages'] = self._check_admin_pages(url)
            
        except Exception as e:
            result['technical_analysis_error'] = str(e)
        
        return result
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security-related HTTP headers"""
        security_headers = {
            'strict-transport-security': headers.get('strict-transport-security'),
            'content-security-policy': headers.get('content-security-policy'),
            'x-frame-options': headers.get('x-frame-options'),
            'x-content-type-options': headers.get('x-content-type-options'),
            'x-xss-protection': headers.get('x-xss-protection'),
            'referrer-policy': headers.get('referrer-policy'),
            'permissions-policy': headers.get('permissions-policy')
        }
        
        # Count present security headers
        present_headers = sum(1 for v in security_headers.values() if v is not None)
        security_score = (present_headers / len(security_headers)) * 100
        
        return {
            'headers': security_headers,
            'score': round(security_score, 2),
            'missing_count': len(security_headers) - present_headers
        }
    
    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies used by the site"""
        technologies = []
        
        # Server header analysis
        server = response.headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Framework detection from headers
        if 'x-powered-by' in response.headers:
            technologies.append(f"Powered by: {response.headers['x-powered-by']}")
        
        # Content-based detection
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append('WordPress')
        elif 'drupal' in content:
            technologies.append('Drupal')
        elif 'joomla' in content:
            technologies.append('Joomla')
        
        return technologies
    
    def _get_meta_content(self, soup: BeautifulSoup, name: str) -> Optional[str]:
        """Extract meta tag content"""
        meta_tag = soup.find('meta', attrs={'name': name})
        return meta_tag.get('content') if meta_tag else None
    
    def _analyze_links(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze all links on the page"""
        links = soup.find_all('a', href=True)
        
        internal_links = []
        external_links = []
        onion_links = []
        
        for link in links:
            href = link['href']
            if href.startswith('http'):
                if '.onion' in href:
                    onion_links.append(href)
                else:
                    external_links.append(href)
            else:
                internal_links.append(href)
        
        return {
            'total_links': len(links),
            'internal_links': internal_links[:20],  # Limit for performance
            'external_links': external_links[:20],
            'onion_links': onion_links,
            'internal_count': len(internal_links),
            'external_count': len(external_links),
            'onion_count': len(onion_links)
        }
    
    def _analyze_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Analyze forms on the page"""
        forms = soup.find_all('form')
        form_data = []
        
        for form in forms:
            form_info = {
                'method': form.get('method', 'get').upper(),
                'action': form.get('action', ''),
                'inputs': []
            }
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_info = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'placeholder': inp.get('placeholder', '')
                }
                form_info['inputs'].append(input_info)
            
            form_data.append(form_info)
        
        return form_data
    
    def _extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        return list(set(emails))  # Remove duplicates
    
    def _extract_crypto_addresses(self, content: str) -> Dict[str, List[str]]:
        """Extract cryptocurrency addresses"""
        patterns = {
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b',
            'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
            'monero': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        }
        
        results = {}
        for crypto, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                results[crypto] = list(set(matches))
        
        return results
    
    def _detect_language(self, soup: BeautifulSoup) -> Optional[str]:
        """Detect page language"""
        html_tag = soup.find('html')
        if html_tag and html_tag.get('lang'):
            return html_tag['lang']
        return None
    
    def _extract_social_media(self, content: str) -> List[str]:
        """Extract social media references"""
        social_patterns = [
            r'twitter\.com/\w+',
            r'facebook\.com/\w+',
            r'instagram\.com/\w+',
            r'linkedin\.com/in/\w+',
            r'github\.com/\w+',
            r'telegram\.me/\w+',
            r't\.me/\w+'
        ]
        
        social_links = []
        for pattern in social_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            social_links.extend(matches)
        
        return list(set(social_links))
    
    def _extract_onion_links(self, content: str) -> List[str]:
        """Extract other onion site references"""
        onion_pattern = r'https?://[a-z2-7]{16,56}\.onion[^\s<>"\']*'
        onion_links = re.findall(onion_pattern, content, re.IGNORECASE)
        return list(set(onion_links))
    
    def _analyze_ssl(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'unknown')
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_timing(self, url: str) -> Dict[str, float]:
        """Analyze response timing patterns"""
        times = []
        
        for _ in range(3):  # Test 3 times
            try:
                start_time = time.time()
                response = self.session.get(url, timeout=self.timeout)
                end_time = time.time()
                times.append(end_time - start_time)
            except Exception:
                continue
        
        if times:
            return {
                'average_time': round(sum(times) / len(times), 3),
                'min_time': round(min(times), 3),
                'max_time': round(max(times), 3),
                'samples': len(times)
            }
        
        return {'error': 'No timing data available'}
    
    def _check_admin_pages(self, base_url: str) -> Dict[str, bool]:
        """Check for common admin/test pages"""
        admin_paths = [
            '/admin',
            '/admin.php',
            '/administrator',
            '/wp-admin',
            '/phpinfo.php',
            '/robots.txt',
            '/sitemap.xml',
            '/.git',
            '/.svn'
        ]
        
        results = {}
        for path in admin_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5)
                results[path] = response.status_code == 200
            except Exception:
                results[path] = False
        
        return results
    
    def _assess_risk(self, analysis_result: Dict[str, Any]) -> str:
        """Assess overall risk level based on analysis"""
        risk_score = 0
        
        # Security headers assessment
        security_headers = analysis_result.get('security_headers', {})
        if security_headers.get('score', 0) < 30:
            risk_score += 2
        elif security_headers.get('score', 0) < 60:
            risk_score += 1
        
        # Admin pages accessible
        admin_pages = analysis_result.get('admin_pages', {})
        accessible_admin_pages = sum(1 for accessible in admin_pages.values() if accessible)
        if accessible_admin_pages > 2:
            risk_score += 3
        elif accessible_admin_pages > 0:
            risk_score += 1
        
        # Crypto addresses found
        crypto_addresses = analysis_result.get('crypto_addresses', {})
        if crypto_addresses:
            risk_score += 1
        
        # External links to clearnet
        links_data = analysis_result.get('links', {})
        if links_data.get('external_count', 0) > 5:
            risk_score += 2
        
        # Forms present (potential data collection)
        forms = analysis_result.get('forms', [])
        if len(forms) > 3:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 6:
            return 'critical'
        elif risk_score >= 4:
            return 'high'
        elif risk_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_analysis_score(self, result: Dict[str, Any]) -> float:
        """Calculate overall analysis completeness score"""
        max_score = 10
        current_score = 0
        
        # Basic HTTP analysis
        if result.get('response_code'):
            current_score += 1
        
        # Content analysis
        if result.get('content'):
            current_score += 2
        
        # Links analysis
        if result.get('links'):
            current_score += 1
        
        # Forms analysis
        if 'forms' in result:
            current_score += 1
        
        # Security headers
        if result.get('security_headers'):
            current_score += 1
        
        # Technology detection
        if result.get('technologies'):
            current_score += 1
        
        # SSL analysis
        if result.get('ssl_info'):
            current_score += 1
        
        # Timing analysis
        if result.get('timing_analysis'):
            current_score += 1
        
        # Admin pages check
        if result.get('admin_pages'):
            current_score += 1
        
        return round((current_score / max_score) * 100, 2)
    
    def extract_metadata(self, url: str) -> Dict[str, Any]:
        """Extract comprehensive metadata from the site"""
        metadata = {
            'extraction_time': datetime.now().isoformat(),
            'url': url
        }
        
        try:
            if not self.session:
                self.session = self.tor_connector.get_session()
            
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all meta tags
            meta_tags = soup.find_all('meta')
            metadata['meta_tags'] = []
            
            for meta in meta_tags:
                meta_info = {}
                for attr in ['name', 'property', 'http-equiv', 'content']:
                    if meta.get(attr):
                        meta_info[attr] = meta[attr]
                if meta_info:
                    metadata['meta_tags'].append(meta_info)
            
            # Extract structured data (JSON-LD, microdata)
            json_ld_scripts = soup.find_all('script', type='application/ld+json')
            if json_ld_scripts:
                metadata['structured_data'] = []
                for script in json_ld_scripts:
                    try:
                        import json
                        structured_data = json.loads(script.string)
                        metadata['structured_data'].append(structured_data)
                    except Exception:
                        continue
            
            # Extract Open Graph data
            og_data = {}
            og_tags = soup.find_all('meta', property=lambda x: x and x.startswith('og:'))
            for tag in og_tags:
                property_name = tag.get('property', '').replace('og:', '')
                og_data[property_name] = tag.get('content', '')
            
            if og_data:
                metadata['open_graph'] = og_data
            
            # Extract Twitter Card data
            twitter_data = {}
            twitter_tags = soup.find_all('meta', attrs={'name': lambda x: x and x.startswith('twitter:')})
            for tag in twitter_tags:
                name = tag.get('name', '').replace('twitter:', '')
                twitter_data[name] = tag.get('content', '')
            
            if twitter_data:
                metadata['twitter_card'] = twitter_data
            
        except Exception as e:
            metadata['extraction_error'] = str(e)
        
        return metadata
