import requests
import json
import hashlib
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
import os

from .tor_connector import TorConnector

class TorDeanonymizer:
    """Advanced de-anonymization techniques using OSINT sources"""
    
    def __init__(self):
        self.tor_connector = TorConnector()
        self.session = None
        
        # API keys from environment variables
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.censys_api_id = os.getenv('CENSYS_API_ID', '')
        self.censys_api_secret = os.getenv('CENSYS_API_SECRET', '')
        
        # Rate limiting
        self.request_delay = 1  # seconds between requests
        self.last_request_time = 0
        self.vt_through_tor = os.getenv('VT_THROUGH_TOR', 'false').lower() in ['1', 'true', 'yes']
    
    def perform_osint_analysis(self, url: str, basic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive OSINT analysis"""
        
        if not self.session:
            self.session = self.tor_connector.get_session()
        
        osint_results = {
            'osint_timestamp': datetime.now().isoformat(),
            'analyzed_url': url,
            'osint_sources': [],
            'entities': [],
            'correlations': []
        }
        
        try:
            # Extract identifiers from basic analysis
            identifiers = self._extract_identifiers(basic_analysis)
            osint_results['extracted_identifiers'] = identifiers
            
            # Perform various OSINT checks
            osint_results.update(self._check_certificate_transparency(identifiers))
            osint_results.update(self._check_domain_reputation(identifiers))
            osint_results.update(self._analyze_hosting_patterns(basic_analysis))
            osint_results.update(self._check_similar_sites(basic_analysis))
            osint_results.update(self._analyze_content_fingerprints(basic_analysis))
            
            # If API keys are available, perform advanced analysis
            if self.shodan_api_key:
                osint_results.update(self._shodan_analysis(identifiers, basic_analysis))
            
            if self.virustotal_api_key:
                osint_results.update(self._virustotal_analysis(url, identifiers))
            
            # Generate entity correlations
            osint_results['entity_correlations'] = self._correlate_entities(osint_results)
            
        except Exception as e:
            osint_results['osint_error'] = str(e)
        
        return osint_results
    
    def _extract_identifiers(self, basic_analysis: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract various identifiers from basic analysis"""
        identifiers = {
            'emails': basic_analysis.get('emails', []),
            'crypto_addresses': [],
            'ssl_fingerprints': [],
            'server_signatures': [],
            'content_hashes': [],
            'social_media': basic_analysis.get('social_media', []),
            'onion_links': basic_analysis.get('onion_links', [])
        }
        
        # Extract crypto addresses
        crypto_data = basic_analysis.get('crypto_addresses', {})
        for crypto_type, addresses in crypto_data.items():
            identifiers['crypto_addresses'].extend(addresses)
        
        # SSL certificate fingerprints
        ssl_info = basic_analysis.get('ssl_info', {})
        if 'serial_number' in ssl_info:
            identifiers['ssl_fingerprints'].append(ssl_info['serial_number'])
        
        # Server signatures
        server_info = basic_analysis.get('server_info', '')
        if server_info and server_info != 'unknown':
            identifiers['server_signatures'].append(server_info)
        
        # Content hash
        content_hash = basic_analysis.get('content_hash')
        if content_hash:
            identifiers['content_hashes'].append(content_hash)
        
        return identifiers
    
    def _check_certificate_transparency(self, identifiers: Dict[str, List[str]]) -> Dict[str, Any]:
        """Check certificate transparency logs"""
        ct_results = {
            'certificate_transparency': {
                'checked': True,
                'findings': []
            }
        }
        
        try:
            # Check crt.sh for certificate transparency
            for ssl_fingerprint in identifiers.get('ssl_fingerprints', []):
                self._rate_limit()
                
                ct_url = f"https://crt.sh/?q={ssl_fingerprint}&output=json"
                response = requests.get(ct_url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        ct_data = response.json()
                        if ct_data:
                            ct_results['certificate_transparency']['findings'].append({
                                'fingerprint': ssl_fingerprint,
                                'certificates': ct_data[:10]  # Limit results
                            })
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            ct_results['certificate_transparency']['error'] = str(e)
        
        return ct_results
    
    def _check_domain_reputation(self, identifiers: Dict[str, List[str]]) -> Dict[str, Any]:
        """Check domain and URL reputation"""
        reputation_results = {
            'reputation_analysis': {
                'checked': True,
                'findings': []
            }
        }
        
        try:
            # Analyze patterns in onion addresses
            onion_links = identifiers.get('onion_links', [])
            
            for onion_url in onion_links:
                # Extract onion address
                onion_match = re.search(r'([a-z2-7]{16,56}\.onion)', onion_url)
                if onion_match:
                    onion_address = onion_match.group(1)
                    
                    # Check against known bad onion lists (simulated)
                    reputation_score = self._calculate_onion_reputation(onion_address)
                    
                    reputation_results['reputation_analysis']['findings'].append({
                        'onion_address': onion_address,
                        'reputation_score': reputation_score,
                        'risk_factors': self._identify_risk_factors(onion_address)
                    })
                    
        except Exception as e:
            reputation_results['reputation_analysis']['error'] = str(e)
        
        return reputation_results
    
    def _analyze_hosting_patterns(self, basic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze hosting patterns and infrastructure"""
        hosting_results = {
            'hosting_analysis': {
                'patterns': [],
                'infrastructure_fingerprints': []
            }
        }
        
        try:
            # Analyze server headers
            headers = basic_analysis.get('headers', {})
            server_info = headers.get('server', '')
            
            if server_info:
                hosting_results['hosting_analysis']['patterns'].append({
                    'type': 'server_signature',
                    'value': server_info,
                    'analysis': self._analyze_server_signature(server_info)
                })
            
            # Analyze security headers patterns
            security_headers = basic_analysis.get('security_headers', {})
            if security_headers:
                hosting_results['hosting_analysis']['patterns'].append({
                    'type': 'security_configuration',
                    'score': security_headers.get('score', 0),
                    'missing_headers': security_headers.get('missing_count', 0)
                })
            
            # Analyze response timing patterns
            timing_data = basic_analysis.get('timing_analysis', {})
            if timing_data and 'average_time' in timing_data:
                hosting_results['hosting_analysis']['infrastructure_fingerprints'].append({
                    'type': 'response_timing',
                    'average_time': timing_data['average_time'],
                    'consistency': self._calculate_timing_consistency(timing_data)
                })
                
        except Exception as e:
            hosting_results['hosting_analysis']['error'] = str(e)
        
        return hosting_results
    
    def _check_similar_sites(self, basic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Check for similar sites based on content and structure"""
        similarity_results = {
            'similarity_analysis': {
                'content_similarities': [],
                'structural_similarities': []
            }
        }
        
        try:
            content_hash = basic_analysis.get('content_hash')
            if content_hash:
                # In a real implementation, this would check against a database
                # of known site hashes or use fuzzy matching
                similarity_results['similarity_analysis']['content_similarities'].append({
                    'hash': content_hash,
                    'hash_type': 'sha256',
                    'potential_matches': []  # Would be populated from database
                })
            
            # Analyze structural patterns
            title = basic_analysis.get('title', '')
            if title:
                # Check for common template patterns
                template_indicators = self._identify_template_patterns(title, basic_analysis)
                if template_indicators:
                    similarity_results['similarity_analysis']['structural_similarities'].extend(template_indicators)
                    
        except Exception as e:
            similarity_results['similarity_analysis']['error'] = str(e)
        
        return similarity_results
    
    def _analyze_content_fingerprints(self, basic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content fingerprints for identification"""
        fingerprint_results = {
            'content_fingerprints': {
                'css_fingerprints': [],
                'js_fingerprints': [],
                'image_fingerprints': [],
                'text_patterns': []
            }
        }
        
        try:
            content = basic_analysis.get('content', '')
            if content:
                # Extract CSS patterns
                css_patterns = re.findall(r'<style[^>]*>(.*?)</style>', content, re.DOTALL)
                for css in css_patterns:
                    css_hash = hashlib.md5(css.encode()).hexdigest()
                    fingerprint_results['content_fingerprints']['css_fingerprints'].append({
                        'hash': css_hash,
                        'size': len(css)
                    })
                
                # Extract JavaScript patterns
                js_patterns = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
                for js in js_patterns:
                    if js.strip():  # Skip empty scripts
                        js_hash = hashlib.md5(js.encode()).hexdigest()
                        fingerprint_results['content_fingerprints']['js_fingerprints'].append({
                            'hash': js_hash,
                            'size': len(js)
                        })
                
                # Analyze text patterns
                text_patterns = self._extract_text_patterns(content)
                fingerprint_results['content_fingerprints']['text_patterns'] = text_patterns
                
        except Exception as e:
            fingerprint_results['content_fingerprints']['error'] = str(e)
        
        return fingerprint_results
    
    def _shodan_analysis(self, identifiers: Dict[str, List[str]], basic_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Shodan API analysis if API key is available"""
        shodan_results = {
            'shodan_analysis': {
                'api_available': True,
                'findings': []
            }
        }
        
        try:
            geodata = basic_analysis.get('geolocation_analysis', {})
            resolved_ips = geodata.get('resolved_ips', [])
            # Query Shodan for any resolved public IPs
            findings = []
            for ip in resolved_ips[:3]:  # limit to first 3 to avoid rate hits
                self._rate_limit()
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    findings.append({
                        'ip': ip,
                        'org': data.get('org'),
                        'isp': data.get('isp'),
                        'hostnames': data.get('hostnames', [])[:5],
                        'ports': data.get('ports', [])[:10],
                        'country': data.get('country_name')
                    })
            if findings:
                shodan_results['shodan_analysis']['findings'] = findings
            
        except Exception as e:
            shodan_results['shodan_analysis']['error'] = str(e)
        
        return shodan_results
    
    def _virustotal_analysis(self, url: str, identifiers: Dict[str, List[str]]) -> Dict[str, Any]:
        """Perform VirusTotal analysis if API key is available"""
        vt_results = {
            'virustotal_analysis': {
                'api_available': True,
                'url_analysis': {},
                'hash_analysis': []
            }
        }
        
        try:
            if not self.virustotal_api_key:
                return vt_results

            headers = {
                'x-apikey': self.virustotal_api_key
            }

            # Use Tor session optionally; else direct
            http = self.tor_connector.get_session() if self.vt_through_tor else requests.Session()

            # Submit URL for analysis
            self._rate_limit()
            submit = http.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url}, timeout=25)
            if submit.status_code in (200, 202):
                data = submit.json()
                analysis_id = data.get('data', {}).get('id')
                vt_results['virustotal_analysis']['url_submission'] = {'status_code': submit.status_code, 'id': analysis_id}
                if analysis_id:
                    # fetch analysis result
                    self._rate_limit()
                    analysis = http.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers, timeout=25)
                    if analysis.status_code == 200:
                        vt_results['virustotal_analysis']['url_analysis'] = analysis.json()

            # Hash analysis for content hashes
            for content_hash in identifiers.get('content_hashes', [])[:3]:
                self._rate_limit()
                hash_resp = http.get(f'https://www.virustotal.com/api/v3/files/{content_hash}', headers=headers, timeout=25)
                if hash_resp.status_code == 200:
                    vt_results['virustotal_analysis']['hash_analysis'].append(hash_resp.json())
                
        except Exception as e:
            vt_results['virustotal_analysis']['error'] = str(e)
        
        return vt_results
    
    def _correlate_entities(self, osint_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate entities across different OSINT sources"""
        correlations = []
        
        try:
            # Extract all entities from different sources
            all_entities = []
            
            # From identifiers
            identifiers = osint_results.get('extracted_identifiers', {})
            for id_type, id_list in identifiers.items():
                for identifier in id_list:
                    all_entities.append({
                        'type': id_type,
                        'value': identifier,
                        'source': 'basic_analysis'
                    })
            
            # From certificate transparency
            ct_findings = osint_results.get('certificate_transparency', {}).get('findings', [])
            for finding in ct_findings:
                all_entities.append({
                    'type': 'ssl_certificate',
                    'value': finding.get('fingerprint', ''),
                    'source': 'certificate_transparency'
                })
            
            # Group similar entities
            entity_groups = self._group_similar_entities(all_entities)
            
            for group in entity_groups:
                if len(group) > 1:  # Only correlations with multiple sources
                    correlations.append({
                        'entity_type': group[0]['type'],
                        'entities': group,
                        'correlation_strength': self._calculate_correlation_strength(group)
                    })
                    
        except Exception as e:
            correlations.append({'error': str(e)})
        
        return correlations
    
    def cross_reference_databases(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Cross-reference findings against known databases"""
        cross_ref_results = {
            'cross_reference_timestamp': datetime.now().isoformat(),
            'databases_checked': [],
            'matches_found': [],
            'risk_indicators': []
        }
        
        try:
            # Simulate database cross-referencing
            # In a real implementation, this would check against:
            # - Known malicious onion databases
            # - Law enforcement databases (if authorized)
            # - Academic research databases
            # - Threat intelligence feeds
            
            url = analysis_result.get('url', '')
            entities = analysis_result.get('entities', [])
            
            # Check URL patterns
            risk_indicators = self._check_risk_indicators(url, analysis_result)
            cross_ref_results['risk_indicators'] = risk_indicators
            
            # Simulate database checks
            cross_ref_results['databases_checked'] = [
                'simulated_malicious_onions_db',
                'simulated_threat_intel_feed',
                'simulated_research_database'
            ]
            
            # Generate matches based on risk indicators
            if risk_indicators:
                cross_ref_results['matches_found'] = [
                    {
                        'database': 'threat_intelligence',
                        'match_type': 'pattern_match',
                        'confidence': 0.7,
                        'details': 'Similar hosting patterns detected'
                    }
                ]
                
        except Exception as e:
            cross_ref_results['cross_reference_error'] = str(e)
        
        return cross_ref_results
    
    def _rate_limit(self):
        """Implement rate limiting for API requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.request_delay:
            time.sleep(self.request_delay - time_since_last_request)
        
        self.last_request_time = time.time()
    
    def _calculate_onion_reputation(self, onion_address: str) -> float:
        """Calculate reputation score for onion address"""
        # Simplified reputation calculation
        score = 0.5  # Neutral starting point
        
        # Check address length (v3 onions are longer and generally more legitimate)
        if len(onion_address.replace('.onion', '')) >= 56:
            score += 0.2
        
        # Check for dictionary words (often indicates vanity address)
        # This is a simplified check
        if any(word in onion_address for word in ['admin', 'shop', 'market', 'forum']):
            score += 0.1
        
        return min(score, 1.0)
    
    def _identify_risk_factors(self, onion_address: str) -> List[str]:
        """Identify risk factors for an onion address"""
        risk_factors = []
        
        # Short address (potentially v2 onion, deprecated)
        if len(onion_address.replace('.onion', '')) == 16:
            risk_factors.append('deprecated_v2_onion')
        
        # Suspicious patterns
        suspicious_patterns = ['darkweb', 'illegal', 'hack', 'exploit']
        for pattern in suspicious_patterns:
            if pattern in onion_address.lower():
                risk_factors.append(f'suspicious_pattern_{pattern}')
        
        return risk_factors
    
    def _analyze_server_signature(self, server_info: str) -> Dict[str, Any]:
        """Analyze server signature for hosting patterns"""
        analysis = {
            'server_type': 'unknown',
            'version_info': None,
            'hosting_indicators': []
        }
        
        server_lower = server_info.lower()
        
        if 'nginx' in server_lower:
            analysis['server_type'] = 'nginx'
            version_match = re.search(r'nginx/([0-9.]+)', server_lower)
            if version_match:
                analysis['version_info'] = version_match.group(1)
        elif 'apache' in server_lower:
            analysis['server_type'] = 'apache'
            version_match = re.search(r'apache/([0-9.]+)', server_lower)
            if version_match:
                analysis['version_info'] = version_match.group(1)
        
        # Check for hosting provider indicators
        if 'cloudflare' in server_lower:
            analysis['hosting_indicators'].append('cloudflare_cdn')
        
        return analysis
    
    def _calculate_timing_consistency(self, timing_data: Dict[str, Any]) -> float:
        """Calculate timing consistency score"""
        if 'min_time' in timing_data and 'max_time' in timing_data and 'average_time' in timing_data:
            min_time = timing_data['min_time']
            max_time = timing_data['max_time']
            avg_time = timing_data['average_time']
            
            if avg_time > 0:
                variance = (max_time - min_time) / avg_time
                consistency = max(0, 1 - variance)
                return round(consistency, 3)
        
        return 0.0
    
    def _identify_template_patterns(self, title: str, basic_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify common template patterns"""
        patterns = []
        
        # Common CMS patterns
        cms_indicators = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'index.php?option=com_']
        }
        
        content = basic_analysis.get('content', '').lower()
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in content for indicator in indicators):
                patterns.append({
                    'template_type': cms,
                    'confidence': 0.8,
                    'indicators_found': [ind for ind in indicators if ind in content]
                })
        
        return patterns
    
    def _extract_text_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Extract characteristic text patterns"""
        patterns = []
        
        # Common phrases that might indicate site type
        pattern_indicators = {
            'marketplace': ['buy', 'sell', 'product', 'cart', 'checkout', 'payment'],
            'forum': ['reply', 'thread', 'post', 'member', 'register', 'login'],
            'blog': ['article', 'comment', 'author', 'published', 'category'],
            'service': ['contact', 'about', 'service', 'professional', 'business']
        }
        
        content_lower = content.lower()
        
        for category, keywords in pattern_indicators.items():
            matches = sum(1 for keyword in keywords if keyword in content_lower)
            if matches >= 3:  # Threshold for pattern recognition
                patterns.append({
                    'pattern_type': category,
                    'matches': matches,
                    'total_keywords': len(keywords),
                    'confidence': matches / len(keywords)
                })
        
        return patterns
    
    def _group_similar_entities(self, entities: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group similar entities together"""
        groups = []
        processed = set()
        
        for i, entity in enumerate(entities):
            if i in processed:
                continue
            
            group = [entity]
            processed.add(i)
            
            for j, other_entity in enumerate(entities[i+1:], i+1):
                if j in processed:
                    continue
                
                if self._entities_similar(entity, other_entity):
                    group.append(other_entity)
                    processed.add(j)
            
            groups.append(group)
        
        return groups
    
    def _entities_similar(self, entity1: Dict[str, Any], entity2: Dict[str, Any]) -> bool:
        """Check if two entities are similar"""
        # Same type
        if entity1['type'] == entity2['type']:
            return True
        
        # Related types
        related_types = [
            ['emails', 'social_media'],
            ['crypto_addresses', 'onion_links'],
            ['ssl_fingerprints', 'server_signatures']
        ]
        
        for related_group in related_types:
            if entity1['type'] in related_group and entity2['type'] in related_group:
                return True
        
        return False
    
    def _calculate_correlation_strength(self, entity_group: List[Dict[str, Any]]) -> float:
        """Calculate correlation strength for entity group"""
        # Base strength on number of entities and source diversity
        entity_count = len(entity_group)
        unique_sources = len(set(entity['source'] for entity in entity_group))
        
        # More entities and more diverse sources = stronger correlation
        strength = (entity_count * 0.3) + (unique_sources * 0.7)
        
        return min(strength, 1.0)
    
    def _check_risk_indicators(self, url: str, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for various risk indicators"""
        risk_indicators = []
        
        # Check for high-risk content patterns
        content = analysis_result.get('content', '').lower()
        high_risk_keywords = [
            'illegal', 'drugs', 'weapons', 'hacking', 'fraud', 'stolen',
            'credit card', 'identity', 'passport', 'documents'
        ]
        
        for keyword in high_risk_keywords:
            if keyword in content:
                risk_indicators.append({
                    'type': 'content_keyword',
                    'indicator': keyword,
                    'severity': 'high',
                    'description': f'High-risk keyword "{keyword}" found in content'
                })
        
        # Check for suspicious forms
        forms = analysis_result.get('forms', [])
        for form in forms:
            sensitive_inputs = ['password', 'credit', 'ssn', 'passport']
            form_inputs = [inp.get('name', '').lower() for inp in form.get('inputs', [])]
            
            for sensitive in sensitive_inputs:
                if any(sensitive in inp for inp in form_inputs):
                    risk_indicators.append({
                        'type': 'sensitive_form',
                        'indicator': sensitive,
                        'severity': 'medium',
                        'description': f'Form requesting sensitive information: {sensitive}'
                    })
        
        # Check crypto addresses
        crypto_addresses = analysis_result.get('crypto_addresses', {})
        if crypto_addresses:
            risk_indicators.append({
                'type': 'crypto_addresses',
                'indicator': f"{sum(len(addrs) for addrs in crypto_addresses.values())} addresses found",
                'severity': 'medium',
                'description': 'Cryptocurrency addresses detected'
            })
        
        return risk_indicators
