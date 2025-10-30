import requests
import json
import hashlib
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
import time
import os

class OSINTTools:
    """Collection of OSINT tools and utilities"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # API configurations
        self.api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY', ''),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'censys_id': os.getenv('CENSYS_API_ID', ''),
            'censys_secret': os.getenv('CENSYS_API_SECRET', ''),
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY', ''),
            'fullhunt': os.getenv('FULLHUNT_API_KEY', '')
        }
        
        self.rate_limits = {
            'default': 1,  # seconds between requests
            'shodan': 1,
            'virustotal': 15,  # VT has strict rate limits
            'censys': 2
        }
        
        self.last_request_times = {}
    
    def analyze_ssl_certificate(self, cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL certificate for OSINT indicators"""
        analysis = {
            'certificate_analysis': {
                'timestamp': datetime.now().isoformat(),
                'findings': [],
                'risk_indicators': []
            }
        }
        
        try:
            # Extract certificate details
            subject = cert_data.get('subject', {})
            issuer = cert_data.get('issuer', {})
            
            # Analyze subject information
            if 'CN' in subject:
                cn = subject['CN']
                analysis['certificate_analysis']['findings'].append({
                    'type': 'common_name',
                    'value': cn,
                    'analysis': self._analyze_common_name(cn)
                })
            
            # Analyze issuer
            if 'CN' in issuer:
                issuer_cn = issuer['CN']
                analysis['certificate_analysis']['findings'].append({
                    'type': 'issuer',
                    'value': issuer_cn,
                    'analysis': self._analyze_certificate_issuer(issuer_cn)
                })
            
            # Check certificate validity period
            not_before = cert_data.get('not_before', '')
            not_after = cert_data.get('not_after', '')
            
            if not_before and not_after:
                validity_analysis = self._analyze_certificate_validity(not_before, not_after)
                analysis['certificate_analysis']['findings'].append({
                    'type': 'validity_period',
                    'not_before': not_before,
                    'not_after': not_after,
                    'analysis': validity_analysis
                })
            
            # Check for self-signed certificates
            if subject == issuer:
                analysis['certificate_analysis']['risk_indicators'].append({
                    'type': 'self_signed',
                    'severity': 'medium',
                    'description': 'Certificate is self-signed'
                })
            
        except Exception as e:
            analysis['certificate_analysis']['error'] = str(e)
        
        return analysis
    
    def reverse_whois_lookup(self, email: str) -> Dict[str, Any]:
        """Perform reverse WHOIS lookup on email addresses"""
        result = {
            'reverse_whois': {
                'email': email,
                'timestamp': datetime.now().isoformat(),
                'domains_found': [],
                'registrar_patterns': []
            }
        }
        
        try:
            # In a real implementation, this would query WHOIS databases
            # For now, we'll simulate the analysis
            
            # Analyze email domain
            email_domain = email.split('@')[-1] if '@' in email else None
            
            if email_domain:
                result['reverse_whois']['email_domain'] = email_domain
                result['reverse_whois']['domain_analysis'] = self._analyze_email_domain(email_domain)
            
            # Simulate domain findings (would come from actual WHOIS data)
            result['reverse_whois']['note'] = 'Reverse WHOIS lookup would be performed here'
            
        except Exception as e:
            result['reverse_whois']['error'] = str(e)
        
        return result
    
    def analyze_bitcoin_address(self, address: str) -> Dict[str, Any]:
        """Analyze Bitcoin address for transaction patterns"""
        result = {
            'bitcoin_analysis': {
                'address': address,
                'timestamp': datetime.now().isoformat(),
                'address_type': self._identify_bitcoin_address_type(address),
                'transaction_analysis': {}
            }
        }
        
        try:
            # Check address format
            if self._validate_bitcoin_address(address):
                result['bitcoin_analysis']['valid_format'] = True
                
                # In a real implementation, this would query blockchain APIs
                # like blockchain.info, blockchair.com, etc.
                result['bitcoin_analysis']['note'] = 'Blockchain API queries would be performed here'
                
                # Simulate transaction analysis
                result['bitcoin_analysis']['transaction_analysis'] = {
                    'total_transactions': 'unknown',
                    'total_received': 'unknown',
                    'total_sent': 'unknown',
                    'first_seen': 'unknown',
                    'last_seen': 'unknown'
                }
            else:
                result['bitcoin_analysis']['valid_format'] = False
                
        except Exception as e:
            result['bitcoin_analysis']['error'] = str(e)
        
        return result
    
    def search_social_media_mentions(self, identifier: str) -> Dict[str, Any]:
        """Search for social media mentions of identifiers"""
        result = {
            'social_media_search': {
                'identifier': identifier,
                'timestamp': datetime.now().isoformat(),
                'platforms_searched': [],
                'mentions_found': []
            }
        }
        
        try:
            # Define search patterns for different platforms
            platforms = {
                'twitter': f'site:twitter.com "{identifier}"',
                'reddit': f'site:reddit.com "{identifier}"',
                'github': f'site:github.com "{identifier}"',
                'telegram': f'site:t.me "{identifier}"'
            }
            
            result['social_media_search']['platforms_searched'] = list(platforms.keys())
            
            # In a real implementation, this would use Google Search API
            # or platform-specific APIs to search for mentions
            result['social_media_search']['note'] = 'Social media API searches would be performed here'
            
        except Exception as e:
            result['social_media_search']['error'] = str(e)
        
        return result
    
    def check_paste_sites(self, identifier: str) -> Dict[str, Any]:
        """Check paste sites for leaked information"""
        result = {
            'paste_search': {
                'identifier': identifier,
                'timestamp': datetime.now().isoformat(),
                'sites_checked': ['pastebin.com', 'hastebin.com', 'ghostbin.com'],
                'leaks_found': []
            }
        }
        
        try:
            # In a real implementation, this would search paste sites
            # Note: Many paste sites don't offer search APIs
            result['paste_search']['note'] = 'Paste site searches would be performed here'
            
        except Exception as e:
            result['paste_search']['error'] = str(e)
        
        return result
    
    def analyze_domain_history(self, domain: str) -> Dict[str, Any]:
        """Analyze domain history and changes"""
        result = {
            'domain_history': {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'historical_records': [],
                'dns_changes': []
            }
        }
        
        try:
            # In a real implementation, this would use SecurityTrails API
            # or similar services to get domain history
            if self.api_keys.get('securitytrails'):
                result['domain_history']['note'] = 'SecurityTrails API would be used here'
            else:
                result['domain_history']['note'] = 'Domain history analysis requires API key'
            
        except Exception as e:
            result['domain_history']['error'] = str(e)
        
        return result
    
    def search_code_repositories(self, identifier: str) -> Dict[str, Any]:
        """Search code repositories for identifiers"""
        result = {
            'code_search': {
                'identifier': identifier,
                'timestamp': datetime.now().isoformat(),
                'repositories_searched': ['github.com', 'gitlab.com', 'bitbucket.org'],
                'matches_found': []
            }
        }
        
        try:
            # In a real implementation, this would use GitHub API, GitLab API, etc.
            result['code_search']['note'] = 'Code repository searches would be performed here'
            
        except Exception as e:
            result['code_search']['error'] = str(e)
        
        return result
    
    def check_threat_intelligence_feeds(self, indicators: List[str]) -> Dict[str, Any]:
        """Check indicators against threat intelligence feeds"""
        result = {
            'threat_intelligence': {
                'indicators_checked': indicators,
                'timestamp': datetime.now().isoformat(),
                'feeds_consulted': [],
                'matches': []
            }
        }
        
        try:
            # Simulate threat intelligence checks
            feeds = [
                'AlienVault OTX',
                'VirusTotal Intelligence',
                'Shodan',
                'Censys',
                'ThreatMiner'
            ]
            
            result['threat_intelligence']['feeds_consulted'] = feeds
            result['threat_intelligence']['note'] = 'Threat intelligence API queries would be performed here'
            
        except Exception as e:
            result['threat_intelligence']['error'] = str(e)
        
        return result
    
    def _rate_limit(self, api_name: str = 'default'):
        """Implement rate limiting for API requests"""
        delay = self.rate_limits.get(api_name, self.rate_limits['default'])
        current_time = time.time()
        
        if api_name in self.last_request_times:
            time_since_last = current_time - self.last_request_times[api_name]
            if time_since_last < delay:
                time.sleep(delay - time_since_last)
        
        self.last_request_times[api_name] = time.time()
    
    def _analyze_common_name(self, cn: str) -> Dict[str, Any]:
        """Analyze certificate common name"""
        analysis = {
            'is_onion': '.onion' in cn,
            'is_wildcard': cn.startswith('*'),
            'length': len(cn),
            'suspicious_patterns': []
        }
        
        # Check for suspicious patterns
        suspicious_keywords = ['temp', 'test', 'fake', 'invalid']
        for keyword in suspicious_keywords:
            if keyword in cn.lower():
                analysis['suspicious_patterns'].append(keyword)
        
        return analysis
    
    def _analyze_certificate_issuer(self, issuer_cn: str) -> Dict[str, Any]:
        """Analyze certificate issuer"""
        analysis = {
            'issuer_name': issuer_cn,
            'is_known_ca': False,
            'is_self_signed_indicator': False
        }
        
        # Known Certificate Authorities
        known_cas = [
            'Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust',
            'VeriSign', 'Symantec', 'GlobalSign', 'Thawte'
        ]
        
        for ca in known_cas:
            if ca.lower() in issuer_cn.lower():
                analysis['is_known_ca'] = True
                analysis['ca_name'] = ca
                break
        
        return analysis
    
    def _analyze_certificate_validity(self, not_before: str, not_after: str) -> Dict[str, Any]:
        """Analyze certificate validity period"""
        try:
            # Parse dates (simplified - would need proper date parsing)
            analysis = {
                'validity_period': f"{not_before} to {not_after}",
                'analysis_note': 'Date parsing would be implemented here'
            }
            
            return analysis
        except Exception:
            return {'error': 'Could not parse certificate dates'}
    
    def _analyze_email_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze email domain for patterns"""
        analysis = {
            'domain': domain,
            'is_disposable': False,
            'is_suspicious': False,
            'provider_type': 'unknown'
        }
        
        # Check for common email providers
        common_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'protonmail.com', 'tutanota.com'
        ]
        
        if domain.lower() in common_providers:
            analysis['provider_type'] = 'common'
        
        # Check for disposable email patterns
        disposable_indicators = ['temp', '10minute', 'guerrilla', 'mailinator']
        for indicator in disposable_indicators:
            if indicator in domain.lower():
                analysis['is_disposable'] = True
                break
        
        return analysis
    
    def _identify_bitcoin_address_type(self, address: str) -> str:
        """Identify Bitcoin address type"""
        if address.startswith('1'):
            return 'P2PKH (Legacy)'
        elif address.startswith('3'):
            return 'P2SH (Script Hash)'
        elif address.startswith('bc1'):
            return 'Bech32 (Segwit)'
        else:
            return 'Unknown'
    
    def _validate_bitcoin_address(self, address: str) -> bool:
        """Validate Bitcoin address format"""
        # Simplified validation - would use proper Bitcoin address validation
        bitcoin_patterns = [
            r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Legacy and P2SH
            r'^bc1[a-z0-9]{39,59}$'  # Bech32
        ]
        
        for pattern in bitcoin_patterns:
            if re.match(pattern, address):
                return True
        
        return False

class ThreatIntelligence:
    """Threat intelligence analysis tools"""
    
    def __init__(self):
        self.osint_tools = OSINTTools()
    
    def analyze_indicators(self, indicators: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze all indicators for threat intelligence"""
        result = {
            'threat_analysis': {
                'timestamp': datetime.now().isoformat(),
                'indicators_analyzed': 0,
                'threats_identified': [],
                'risk_score': 0
            }
        }
        
        total_indicators = 0
        threat_score = 0
        
        try:
            # Analyze each type of indicator
            for indicator_type, indicator_list in indicators.items():
                total_indicators += len(indicator_list)
                
                if indicator_type == 'emails':
                    for email in indicator_list:
                        threat_score += self._assess_email_threat(email)
                
                elif indicator_type == 'crypto_addresses':
                    for address in indicator_list:
                        threat_score += self._assess_crypto_threat(address)
                
                elif indicator_type == 'onion_links':
                    for link in indicator_list:
                        threat_score += self._assess_onion_threat(link)
            
            result['threat_analysis']['indicators_analyzed'] = total_indicators
            
            if total_indicators > 0:
                result['threat_analysis']['risk_score'] = min(threat_score / total_indicators, 10)
            
        except Exception as e:
            result['threat_analysis']['error'] = str(e)
        
        return result
    
    def _assess_email_threat(self, email: str) -> float:
        """Assess threat level of email address"""
        threat_score = 0
        
        # Check domain reputation
        domain = email.split('@')[-1] if '@' in email else ''
        
        # Suspicious domains get higher scores
        suspicious_domains = ['guerrillamail', 'tempmail', '10minutemail']
        if any(sus in domain.lower() for sus in suspicious_domains):
            threat_score += 3
        
        return threat_score
    
    def _assess_crypto_threat(self, address: str) -> float:
        """Assess threat level of cryptocurrency address"""
        # In real implementation, would check against known malicious addresses
        return 1  # Base threat score
    
    def _assess_onion_threat(self, onion_link: str) -> float:
        """Assess threat level of onion link"""
        threat_score = 0
        
        # Check for suspicious patterns in URL
        suspicious_patterns = ['hack', 'illegal', 'fraud', 'stolen']
        for pattern in suspicious_patterns:
            if pattern in onion_link.lower():
                threat_score += 2
        
        return threat_score
