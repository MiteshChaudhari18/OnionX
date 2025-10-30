import csv
import json
import io
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

class ExportUtils:
    """Utilities for exporting analysis results in various formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=18,
            spaceAfter=30
        )
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=14,
            spaceAfter=12
        )
    
    def to_csv(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Export results to CSV format"""
        if not analysis_results:
            return ""
        
        output = io.StringIO()
        
        # Flatten the nested data for CSV export
        flattened_results = []
        for result in analysis_results:
            flattened = self._flatten_result(result)
            flattened_results.append(flattened)
        
        if flattened_results:
            # Get all possible field names
            fieldnames = set()
            for result in flattened_results:
                fieldnames.update(result.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_results)
        
        return output.getvalue()
    
    def to_json(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Export results to JSON format"""
        export_data = {
            'export_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_analyses': len(analysis_results),
                'export_format': 'json',
                'version': '1.0'
            },
            'analyses': analysis_results
        }
        
        return json.dumps(export_data, indent=2, default=str)
    
    def to_pdf(self, analysis_results: List[Dict[str, Any]]) -> bytes:
        """Export results to PDF format"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        
        # Title
        title = Paragraph("Tor Onion Site Analysis Report", self.title_style)
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Report metadata
        metadata_text = f"""
        <b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Total Analyses:</b> {len(analysis_results)}<br/>
        <b>Report Type:</b> Comprehensive Tor De-anonymization Analysis
        """
        metadata = Paragraph(metadata_text, self.styles['Normal'])
        story.append(metadata)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        # Calculate summary statistics
        successful_analyses = len([r for r in analysis_results if 'error' not in r])
        failed_analyses = len(analysis_results) - successful_analyses
        
        risk_levels = {}
        for result in analysis_results:
            if 'error' not in result:
                risk_level = result.get('risk_level', 'unknown')
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        
        summary_text = f"""
        This report contains analysis results for {len(analysis_results)} onion sites.
        <br/><br/>
        <b>Analysis Results:</b><br/>
        • Successful analyses: {successful_analyses}<br/>
        • Failed analyses: {failed_analyses}<br/>
        <br/>
        <b>Risk Level Distribution:</b><br/>
        """
        
        for risk_level, count in risk_levels.items():
            summary_text += f"• {risk_level.title()}: {count}<br/>"
        
        summary = Paragraph(summary_text, self.styles['Normal'])
        story.append(summary)
        story.append(Spacer(1, 20))
        
        # Table of Contents
        story.append(Spacer(1, 16))
        toc_data = [["#", "URL", "Risk", "Status"]]
        for i, result in enumerate(analysis_results, 1):
            status = 'Success' if 'error' not in result else 'Error'
            toc_data.append([
                str(i),
                result.get('url', 'Unknown'),
                str(result.get('risk_level', 'Unknown')).title(),
                status
            ])
        toc_table = Table(toc_data, colWidths=[20, 280, 80, 60])
        toc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.Color(0.1,0.15,0.18)),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.Color(0.95,0.95,0.95)),
            ('GRID', (0,0), (-1,-1), 0.25, colors.gray)
        ]))
        story.append(toc_table)
        story.append(Spacer(1, 20))

        # Detailed Results
        story.append(Paragraph("Detailed Analysis Results", self.heading_style))
        
        for i, result in enumerate(analysis_results, 1):
            story.append(self._create_result_section(result, i))
            story.append(Spacer(1, 15))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _flatten_result(self, result: Dict[str, Any]) -> Dict[str, str]:
        """Flatten nested dictionary for CSV export"""
        flattened = {}
        
        def flatten_dict(d, parent_key='', sep='_'):
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                
                if isinstance(v, dict):
                    flatten_dict(v, new_key, sep)
                elif isinstance(v, list):
                    if v and isinstance(v[0], dict):
                        # For list of dicts, create a summary
                        flattened[new_key + '_count'] = str(len(v))
                        if len(v) > 0:
                            flattened[new_key + '_sample'] = str(v[0])[:100] + '...' if len(str(v[0])) > 100 else str(v[0])
                    else:
                        # For simple lists, join with semicolons
                        flattened[new_key] = '; '.join(str(item) for item in v)
                else:
                    flattened[new_key] = str(v) if v is not None else ''
        
        flatten_dict(result)
        return flattened
    
    def _create_result_section(self, result: Dict[str, Any], index: int) -> Paragraph:
        """Create a PDF section for a single analysis result"""
        url = result.get('url', 'Unknown URL')
        
        section_text = f"<b>Analysis {index}: {url}</b><br/><br/>"
        
        if 'error' in result:
            section_text += f"<b>Status:</b> Failed<br/>"
            section_text += f"<b>Error:</b> {result['error']}<br/>"
        else:
            # Basic information
            section_text += f"<b>Status:</b> Successful<br/>"
            section_text += f"<b>Risk Level:</b> {result.get('risk_level', 'Unknown').title()}<br/>"
            section_text += f"<b>Response Code:</b> {result.get('response_code', 'Unknown')}<br/>"
            section_text += f"<b>Analysis Score:</b> {result.get('analysis_score', 'Unknown')}%<br/>"
            section_text += f"<b>Load Time:</b> {result.get('load_time', 'Unknown')}s<br/><br/>"
            
            # Technical details
            section_text += "<b>Technical Details:</b><br/>"
            section_text += f"• Server: {result.get('server_info', 'Unknown')}<br/>"
            section_text += f"• Content Type: {result.get('content_type', 'Unknown')}<br/>"
            section_text += f"• Content Length: {result.get('content_length', 'Unknown')} bytes<br/>"
            
            # Security information
            security_headers = result.get('security_headers', {})
            if security_headers:
                section_text += f"• Security Headers Score: {security_headers.get('score', 'Unknown')}%<br/>"
            
            section_text += "<br/>"
            
            # Entities found
            entities = result.get('entities', [])
            if entities:
                section_text += f"<b>Entities Found:</b> {len(entities)}<br/>"
            
            # OSINT sources
            osint_sources = result.get('osint_sources', [])
            if osint_sources:
                section_text += f"<b>OSINT Sources:</b> {len(osint_sources)}<br/>"
            
            # Links analysis
            links_data = result.get('links', {})
            if links_data:
                section_text += f"<b>Links Analysis:</b><br/>"
                section_text += f"• Total links: {links_data.get('total_links', 0)}<br/>"
                section_text += f"• External links: {links_data.get('external_count', 0)}<br/>"
                section_text += f"• Onion links: {links_data.get('onion_count', 0)}<br/>"
            
            # Cryptocurrency addresses
            crypto_addresses = result.get('crypto_addresses', {})
            if crypto_addresses:
                section_text += f"<b>Cryptocurrency Addresses:</b><br/>"
                for crypto_type, addresses in crypto_addresses.items():
                    section_text += f"• {crypto_type.title()}: {len(addresses)} addresses<br/>"
            
            # Forms
            forms = result.get('forms', [])
            if forms:
                section_text += f"<b>Forms Found:</b> {len(forms)}<br/>"
        
        return Paragraph(section_text, self.styles['Normal'])
    
    def create_summary_report(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a summary report of all analyses"""
        summary = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_analyses': len(analysis_results),
                'successful_analyses': 0,
                'failed_analyses': 0
            },
            'risk_distribution': {},
            'technical_summary': {
                'server_types': {},
                'content_types': {},
                'response_codes': {}
            },
            'osint_summary': {
                'total_entities': 0,
                'total_osint_sources': 0,
                'crypto_addresses': {},
                'email_domains': {},
                'social_media_references': 0
            },
            'security_analysis': {
                'avg_security_score': 0,
                'sites_with_ssl': 0,
                'sites_with_forms': 0
            }
        }
        
        successful_results = []
        
        for result in analysis_results:
            if 'error' in result:
                summary['report_metadata']['failed_analyses'] += 1
            else:
                summary['report_metadata']['successful_analyses'] += 1
                successful_results.append(result)
                
                # Risk distribution
                risk_level = result.get('risk_level', 'unknown')
                summary['risk_distribution'][risk_level] = summary['risk_distribution'].get(risk_level, 0) + 1
                
                # Technical summary
                server_info = result.get('server_info', 'unknown')
                summary['technical_summary']['server_types'][server_info] = \
                    summary['technical_summary']['server_types'].get(server_info, 0) + 1
                
                content_type = result.get('content_type', 'unknown')
                summary['technical_summary']['content_types'][content_type] = \
                    summary['technical_summary']['content_types'].get(content_type, 0) + 1
                
                response_code = result.get('response_code', 'unknown')
                summary['technical_summary']['response_codes'][str(response_code)] = \
                    summary['technical_summary']['response_codes'].get(str(response_code), 0) + 1
                
                # OSINT summary
                entities = result.get('entities', [])
                summary['osint_summary']['total_entities'] += len(entities)
                
                osint_sources = result.get('osint_sources', [])
                summary['osint_summary']['total_osint_sources'] += len(osint_sources)
                
                # Crypto addresses
                crypto_addresses = result.get('crypto_addresses', {})
                for crypto_type, addresses in crypto_addresses.items():
                    summary['osint_summary']['crypto_addresses'][crypto_type] = \
                        summary['osint_summary']['crypto_addresses'].get(crypto_type, 0) + len(addresses)
                
                # Email domains
                emails = result.get('emails', [])
                for email in emails:
                    domain = email.split('@')[-1] if '@' in email else 'unknown'
                    summary['osint_summary']['email_domains'][domain] = \
                        summary['osint_summary']['email_domains'].get(domain, 0) + 1
                
                # Social media
                social_media = result.get('social_media', [])
                summary['osint_summary']['social_media_references'] += len(social_media)
                
                # Security analysis
                if result.get('ssl_info'):
                    summary['security_analysis']['sites_with_ssl'] += 1
                
                forms = result.get('forms', [])
                if forms:
                    summary['security_analysis']['sites_with_forms'] += 1
        
        # Calculate averages
        if successful_results:
            security_scores = [r.get('security_headers', {}).get('score', 0) for r in successful_results]
            if security_scores:
                summary['security_analysis']['avg_security_score'] = \
                    round(sum(security_scores) / len(security_scores), 2)
        
        return summary
    
    def export_summary_csv(self, analysis_results: List[Dict[str, Any]]) -> str:
        """Export summary statistics as CSV"""
        summary = self.create_summary_report(analysis_results)
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Category', 'Metric', 'Value'])
        
        # Report metadata
        writer.writerow(['Report', 'Total Analyses', summary['report_metadata']['total_analyses']])
        writer.writerow(['Report', 'Successful Analyses', summary['report_metadata']['successful_analyses']])
        writer.writerow(['Report', 'Failed Analyses', summary['report_metadata']['failed_analyses']])
        
        # Risk distribution
        for risk_level, count in summary['risk_distribution'].items():
            writer.writerow(['Risk Distribution', risk_level.title(), count])
        
        # Technical summary
        for server_type, count in summary['technical_summary']['server_types'].items():
            writer.writerow(['Server Types', server_type, count])
        
        # OSINT summary
        writer.writerow(['OSINT', 'Total Entities', summary['osint_summary']['total_entities']])
        writer.writerow(['OSINT', 'Total Sources', summary['osint_summary']['total_osint_sources']])
        writer.writerow(['OSINT', 'Social Media References', summary['osint_summary']['social_media_references']])
        
        for crypto_type, count in summary['osint_summary']['crypto_addresses'].items():
            writer.writerow(['Crypto Addresses', crypto_type.title(), count])
        
        # Security analysis
        writer.writerow(['Security', 'Average Security Score', summary['security_analysis']['avg_security_score']])
        writer.writerow(['Security', 'Sites with SSL', summary['security_analysis']['sites_with_ssl']])
        writer.writerow(['Security', 'Sites with Forms', summary['security_analysis']['sites_with_forms']])
        
        return output.getvalue()
