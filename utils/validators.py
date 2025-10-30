import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

class URLValidator:
    """Validation utilities for URLs and input data"""
    
    def __init__(self):
        # Onion address patterns
        self.onion_v2_pattern = r'[a-z2-7]{16}\.onion'
        self.onion_v3_pattern = r'[a-z2-7]{56}\.onion'
        self.onion_patterns = [self.onion_v2_pattern, self.onion_v3_pattern]
        
        # Common URL schemes
        self.valid_schemes = ['http', 'https']
    
    def is_valid_onion_url(self, url: str) -> bool:
        """Check if URL is a valid onion address"""
        try:
            parsed = urlparse(url.strip())
            
            # Check scheme
            if parsed.scheme not in self.valid_schemes:
                return False
            
            # Check if hostname matches onion pattern
            if not parsed.hostname:
                return False
            
            hostname = parsed.hostname.lower()
            
            # Check against onion patterns
            for pattern in self.onion_patterns:
                if re.match(f'^{pattern}$', hostname):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def is_valid_onion_domain(self, domain: str) -> bool:
        """Check if domain is a valid onion address (without scheme)"""
        domain = domain.strip().lower()
        
        for pattern in self.onion_patterns:
            if re.match(f'^{pattern}$', domain):
                return True
        
        return False
    
    def get_onion_version(self, url_or_domain: str) -> Optional[str]:
        """Determine onion address version"""
        # Extract domain if full URL provided
        if url_or_domain.startswith('http'):
            parsed = urlparse(url_or_domain)
            domain = parsed.hostname
        else:
            domain = url_or_domain.strip().lower()
        
        if not domain:
            return None
        
        # Remove .onion suffix for pattern matching
        onion_address = domain.replace('.onion', '')
        
        if len(onion_address) == 16:
            return 'v2'
        elif len(onion_address) == 56:
            return 'v3'
        else:
            return None
    
    def validate_url_list(self, urls: List[str]) -> Dict[str, List[str]]:
        """Validate a list of URLs and categorize them"""
        result = {
            'valid': [],
            'invalid': [],
            'duplicates': [],
            'v2_onions': [],
            'v3_onions': []
        }
        
        seen_urls = set()
        
        for url in urls:
            url = url.strip()
            
            if not url:
                continue
            
            # Check for duplicates
            if url in seen_urls:
                result['duplicates'].append(url)
                continue
            
            seen_urls.add(url)
            
            # Validate URL
            if self.is_valid_onion_url(url):
                result['valid'].append(url)
                
                # Categorize by version
                version = self.get_onion_version(url)
                if version == 'v2':
                    result['v2_onions'].append(url)
                elif version == 'v3':
                    result['v3_onions'].append(url)
            else:
                result['invalid'].append(url)
        
        return result
    
    def sanitize_url(self, url: str) -> str:
        """Sanitize and normalize URL"""
        url = url.strip()
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            # Default to http for onion sites
            url = 'http://' + url
        
        # Parse and reconstruct to normalize
        parsed = urlparse(url)
        
        # Normalize hostname
        if parsed.hostname:
            hostname = parsed.hostname.lower()
            
            # Reconstruct URL with normalized hostname
            port_part = f':{parsed.port}' if parsed.port else ''
            path_part = parsed.path if parsed.path else ''
            query_part = f'?{parsed.query}' if parsed.query else ''
            fragment_part = f'#{parsed.fragment}' if parsed.fragment else ''
            
            normalized_url = f'{parsed.scheme}://{hostname}{port_part}{path_part}{query_part}{fragment_part}'
            return normalized_url
        
        return url
    
    def extract_onion_addresses(self, text: str) -> List[str]:
        """Extract onion addresses from text"""
        onion_addresses = []
        
        # Pattern to match onion URLs
        url_pattern = r'https?://[a-z2-7]{16,56}\.onion[^\s<>"\'\)]*'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        for url in urls:
            if self.is_valid_onion_url(url):
                onion_addresses.append(url)
        
        # Pattern to match standalone onion domains
        domain_pattern = r'\b[a-z2-7]{16,56}\.onion\b'
        domains = re.findall(domain_pattern, text, re.IGNORECASE)
        
        for domain in domains:
            if self.is_valid_onion_domain(domain):
                # Convert to full URL
                full_url = f'http://{domain}'
                if full_url not in onion_addresses:
                    onion_addresses.append(full_url)
        
        return list(set(onion_addresses))  # Remove duplicates
    
    def validate_analysis_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate input data for analysis"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'processed_data': {}
        }
        
        try:
            # Validate URLs
            urls = data.get('urls', [])
            if not urls:
                validation_result['errors'].append('No URLs provided for analysis')
                validation_result['valid'] = False
                return validation_result
            
            url_validation = self.validate_url_list(urls)
            
            if not url_validation['valid']:
                validation_result['errors'].append('No valid onion URLs found')
                validation_result['valid'] = False
                return validation_result
            
            # Add warnings for v2 onions (deprecated)
            if url_validation['v2_onions']:
                validation_result['warnings'].append(
                    f"Found {len(url_validation['v2_onions'])} v2 onion addresses. "
                    "v2 onions are deprecated and may not be accessible."
                )
            
            # Add warnings for duplicates
            if url_validation['duplicates']:
                validation_result['warnings'].append(
                    f"Found {len(url_validation['duplicates'])} duplicate URLs. "
                    "Duplicates will be ignored."
                )
            
            # Add warnings for invalid URLs
            if url_validation['invalid']:
                validation_result['warnings'].append(
                    f"Found {len(url_validation['invalid'])} invalid URLs. "
                    "These will be skipped."
                )
            
            validation_result['processed_data'] = {
                'valid_urls': url_validation['valid'],
                'url_stats': {
                    'total_provided': len(urls),
                    'valid_count': len(url_validation['valid']),
                    'invalid_count': len(url_validation['invalid']),
                    'duplicate_count': len(url_validation['duplicates']),
                    'v2_count': len(url_validation['v2_onions']),
                    'v3_count': len(url_validation['v3_onions'])
                }
            }
            
            # Validate analysis options
            analysis_options = data.get('analysis_options', {})
            validation_result['processed_data']['analysis_options'] = self._validate_analysis_options(analysis_options)
            
        except Exception as e:
            validation_result['valid'] = False
            validation_result['errors'].append(f'Validation error: {str(e)}')
        
        return validation_result
    
    def _validate_analysis_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate analysis options"""
        default_options = {
            'deep_analysis': True,
            'metadata_extraction': True,
            'cross_reference': True,
            'timeout': 30,
            'user_agent': 'TorAnalyzer/1.0'
        }
        
        validated_options = default_options.copy()
        
        # Override with provided options
        for key, value in options.items():
            if key in default_options:
                # Type validation
                if key in ['deep_analysis', 'metadata_extraction', 'cross_reference']:
                    validated_options[key] = bool(value)
                elif key == 'timeout':
                    try:
                        timeout = int(value)
                        validated_options[key] = max(5, min(timeout, 120))  # Clamp between 5-120 seconds
                    except (ValueError, TypeError):
                        pass  # Keep default
                elif key == 'user_agent':
                    if isinstance(value, str) and value.strip():
                        validated_options[key] = value.strip()
        
        return validated_options

class InputSanitizer:
    """Sanitize various types of input data"""
    
    @staticmethod
    def sanitize_text_input(text: str, max_length: int = 10000) -> str:
        """Sanitize text input"""
        if not isinstance(text, str):
            return ""
        
        # Strip whitespace
        text = text.strip()
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        # Remove potentially dangerous characters for file operations
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\x00']
        for char in dangerous_chars:
            text = text.replace(char, '')
        
        return text
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe file operations"""
        if not isinstance(filename, str):
            return "default_filename"
        
        # Remove path separators and dangerous characters
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        
        # Ensure filename is not empty
        if not filename:
            filename = "default_filename"
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        return filename
    
    @staticmethod
    def sanitize_url_list(url_text: str) -> List[str]:
        """Sanitize and extract URLs from text"""
        if not isinstance(url_text, str):
            return []
        
        # Split by common separators
        separators = ['\n', '\r\n', ',', ';', ' ', '\t']
        urls = [url_text]
        
        for sep in separators:
            new_urls = []
            for url in urls:
                new_urls.extend(url.split(sep))
            urls = new_urls
        
        # Clean and filter URLs
        clean_urls = []
        for url in urls:
            url = url.strip()
            if url and len(url) > 0:
                # Basic URL sanitization
                url = InputSanitizer.sanitize_text_input(url, max_length=500)
                if url:
                    clean_urls.append(url)
        
        return clean_urls

class SecurityValidator:
    """Security-focused validation utilities"""
    
    @staticmethod
    def check_suspicious_patterns(text: str) -> List[Dict[str, str]]:
        """Check for suspicious patterns in text input"""
        suspicious_patterns = []
        
        # SQL injection patterns
        sql_patterns = [
            r"(?i)(union\s+select)",
            r"(?i)(drop\s+table)",
            r"(?i)(insert\s+into)",
            r"(?i)(delete\s+from)",
            r"(?i)(exec\s*\()",
            r"(?i)(script\s*>)",
            r"[\';]--",
            r"1=1",
            r"or\s+1=1"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, text):
                suspicious_patterns.append({
                    'type': 'sql_injection',
                    'pattern': pattern,
                    'description': 'Potential SQL injection attempt detected'
                })
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious_patterns.append({
                    'type': 'xss',
                    'pattern': pattern,
                    'description': 'Potential XSS attempt detected'
                })
        
        # Command injection patterns
        cmd_patterns = [
            r"[;&|`]",
            r"\$\(",
            r">\s*/",
            r"<\s*/",
            r"\|\s*nc",
            r"\|\s*sh",
            r"\|\s*bash"
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, text):
                suspicious_patterns.append({
                    'type': 'command_injection',
                    'pattern': pattern,
                    'description': 'Potential command injection attempt detected'
                })
        
        return suspicious_patterns
    
    @staticmethod
    def validate_file_upload(file_content: bytes, filename: str) -> Dict[str, Any]:
        """Validate uploaded file content"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'file_info': {}
        }
        
        try:
            # Check file size (limit to 10MB)
            max_size = 10 * 1024 * 1024
            if len(file_content) > max_size:
                validation_result['valid'] = False
                validation_result['errors'].append(f'File too large. Maximum size: {max_size} bytes')
                return validation_result
            
            # Check filename
            sanitized_filename = InputSanitizer.sanitize_filename(filename)
            if sanitized_filename != filename:
                validation_result['warnings'].append('Filename was sanitized for security')
            
            # Try to decode as text
            try:
                text_content = file_content.decode('utf-8')
                validation_result['file_info']['encoding'] = 'utf-8'
                validation_result['file_info']['is_text'] = True
                
                # Check for suspicious patterns
                suspicious_patterns = SecurityValidator.check_suspicious_patterns(text_content)
                if suspicious_patterns:
                    validation_result['warnings'].append(f'Found {len(suspicious_patterns)} suspicious patterns')
                    validation_result['file_info']['suspicious_patterns'] = suspicious_patterns
                
            except UnicodeDecodeError:
                validation_result['valid'] = False
                validation_result['errors'].append('File must be valid UTF-8 text')
                return validation_result
            
            validation_result['file_info']['size'] = len(file_content)
            validation_result['file_info']['filename'] = sanitized_filename
            
        except Exception as e:
            validation_result['valid'] = False
            validation_result['errors'].append(f'File validation error: {str(e)}')
        
        return validation_result
