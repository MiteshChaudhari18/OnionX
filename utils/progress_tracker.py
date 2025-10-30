import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import threading

class ProgressTracker:
    """Track progress of analysis operations with threading support"""
    
    def __init__(self):
        self.current_progress = 0.0
        self.total_items = 0
        self.completed_items = 0
        self.current_item = ""
        self.status_message = ""
        self.start_time = None
        self.estimated_completion = None
        self.is_active = False
        self.error_count = 0
        self.success_count = 0
        self.results = []
        
        # Threading support
        self._lock = threading.Lock()
        self._callback = None
    
    def start_tracking(self, total_items: int, callback: Optional[Callable] = None):
        """Initialize tracking for a new analysis session"""
        with self._lock:
            self.total_items = total_items
            self.completed_items = 0
            self.current_progress = 0.0
            self.current_item = ""
            self.status_message = "Initializing analysis..."
            self.start_time = time.time()
            self.estimated_completion = None
            self.is_active = True
            self.error_count = 0
            self.success_count = 0
            self.results = []
            self._callback = callback
    
    def update_progress(self, completed_items: int, current_item: str = "", status_message: str = ""):
        """Update progress with current status"""
        with self._lock:
            self.completed_items = completed_items
            self.current_progress = (completed_items / self.total_items) if self.total_items > 0 else 0.0
            
            if current_item:
                self.current_item = current_item
            
            if status_message:
                self.status_message = status_message
            
            # Calculate estimated completion time
            if self.start_time and completed_items > 0:
                elapsed_time = time.time() - self.start_time
                avg_time_per_item = elapsed_time / completed_items
                remaining_items = self.total_items - completed_items
                
                if remaining_items > 0:
                    estimated_remaining_seconds = remaining_items * avg_time_per_item
                    self.estimated_completion = time.time() + estimated_remaining_seconds
                else:
                    self.estimated_completion = time.time()
            
            # Trigger callback if provided
            if self._callback:
                self._callback(self.get_status())
    
    def increment_progress(self, current_item: str = "", status_message: str = ""):
        """Increment progress by one item"""
        self.update_progress(self.completed_items + 1, current_item, status_message)
    
    def add_result(self, result: Dict[str, Any], is_success: bool = True):
        """Add a result to the tracking"""
        with self._lock:
            self.results.append(result)
            
            if is_success:
                self.success_count += 1
            else:
                self.error_count += 1
    
    def complete_tracking(self, final_message: str = "Analysis completed"):
        """Mark tracking as complete"""
        with self._lock:
            self.is_active = False
            self.current_progress = 1.0
            self.status_message = final_message
            self.estimated_completion = time.time()
            
            if self._callback:
                self._callback(self.get_status())
    
    def get_status(self) -> Dict[str, Any]:
        """Get current tracking status"""
        with self._lock:
            elapsed_time = time.time() - self.start_time if self.start_time else 0
            
            status = {
                'progress_percentage': round(self.current_progress * 100, 1),
                'completed_items': self.completed_items,
                'total_items': self.total_items,
                'current_item': self.current_item,
                'status_message': self.status_message,
                'is_active': self.is_active,
                'elapsed_time': round(elapsed_time, 1),
                'success_count': self.success_count,
                'error_count': self.error_count,
                'results_count': len(self.results)
            }
            
            # Add estimated completion info
            if self.estimated_completion:
                remaining_time = max(0, self.estimated_completion - time.time())
                status['estimated_remaining_seconds'] = round(remaining_time, 1)
                status['estimated_completion_time'] = datetime.fromtimestamp(
                    self.estimated_completion
                ).strftime('%H:%M:%S')
            
            # Add rate information
            if elapsed_time > 0 and self.completed_items > 0:
                status['items_per_second'] = round(self.completed_items / elapsed_time, 2)
            else:
                status['items_per_second'] = 0
            
            return status
    
    def get_formatted_status(self) -> str:
        """Get a formatted status string for display"""
        status = self.get_status()
        
        progress_bar = self._create_text_progress_bar(status['progress_percentage'])
        
        formatted_status = f"""
        Progress: {progress_bar} {status['progress_percentage']}%
        
        Status: {status['status_message']}
        Current: {status['current_item'][:50]}{'...' if len(status['current_item']) > 50 else ''}
        
        Items: {status['completed_items']}/{status['total_items']}
        Success: {status['success_count']} | Errors: {status['error_count']}
        
        Elapsed: {self._format_time(status['elapsed_time'])}
        Rate: {status['items_per_second']} items/sec
        """
        
        if 'estimated_remaining_seconds' in status:
            formatted_status += f"\nETA: {self._format_time(status['estimated_remaining_seconds'])}"
        
        return formatted_status.strip()
    
    def _create_text_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create a text-based progress bar"""
        filled_length = int(width * percentage // 100)
        bar = '█' * filled_length + '░' * (width - filled_length)
        return f'[{bar}]'
    
    def _format_time(self, seconds: float) -> str:
        """Format time in seconds to readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def get_results(self) -> list:
        """Get all results collected during tracking"""
        with self._lock:
            return self.results.copy()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        status = self.get_status()
        
        summary = {
            'total_processed': self.completed_items,
            'success_rate': (self.success_count / max(1, self.completed_items)) * 100,
            'error_rate': (self.error_count / max(1, self.completed_items)) * 100,
            'total_time': status['elapsed_time'],
            'average_time_per_item': status['elapsed_time'] / max(1, self.completed_items),
            'processing_rate': status['items_per_second']
        }
        
        return summary
    
    def reset(self):
        """Reset the progress tracker"""
        with self._lock:
            self.current_progress = 0.0
            self.total_items = 0
            self.completed_items = 0
            self.current_item = ""
            self.status_message = ""
            self.start_time = None
            self.estimated_completion = None
            self.is_active = False
            self.error_count = 0
            self.success_count = 0
            self.results = []
            self._callback = None

class BatchProgressTracker:
    """Track progress for batch operations with multiple concurrent tasks"""
    
    def __init__(self):
        self.batch_trackers = {}
        self.overall_progress = 0.0
        self.batch_count = 0
        self._lock = threading.Lock()
    
    def create_batch_tracker(self, batch_id: str, total_items: int) -> ProgressTracker:
        """Create a new progress tracker for a batch"""
        with self._lock:
            tracker = ProgressTracker()
            tracker.start_tracking(total_items)
            self.batch_trackers[batch_id] = tracker
            self.batch_count = len(self.batch_trackers)
            return tracker
    
    def get_batch_tracker(self, batch_id: str) -> Optional[ProgressTracker]:
        """Get a specific batch tracker"""
        with self._lock:
            return self.batch_trackers.get(batch_id)
    
    def get_overall_progress(self) -> Dict[str, Any]:
        """Get overall progress across all batches"""
        with self._lock:
            if not self.batch_trackers:
                return {
                    'overall_percentage': 0.0,
                    'total_batches': 0,
                    'completed_batches': 0,
                    'active_batches': 0
                }
            
            total_progress = 0.0
            completed_batches = 0
            active_batches = 0
            
            for tracker in self.batch_trackers.values():
                status = tracker.get_status()
                total_progress += status['progress_percentage']
                
                if not status['is_active']:
                    completed_batches += 1
                else:
                    active_batches += 1
            
            overall_percentage = total_progress / len(self.batch_trackers)
            
            return {
                'overall_percentage': round(overall_percentage, 1),
                'total_batches': len(self.batch_trackers),
                'completed_batches': completed_batches,
                'active_batches': active_batches,
                'batch_details': {
                    batch_id: tracker.get_status() 
                    for batch_id, tracker in self.batch_trackers.items()
                }
            }
    
    def remove_batch(self, batch_id: str):
        """Remove a completed batch tracker"""
        with self._lock:
            if batch_id in self.batch_trackers:
                del self.batch_trackers[batch_id]
                self.batch_count = len(self.batch_trackers)
    
    def clear_all_batches(self):
        """Clear all batch trackers"""
        with self._lock:
            self.batch_trackers.clear()
            self.batch_count = 0
            self.overall_progress = 0.0

class AnalysisProgressManager:
    """High-level progress manager for analysis operations"""
    
    def __init__(self):
        self.current_analysis = None
        self.analysis_history = []
        self.max_history = 10
    
    def start_analysis(self, analysis_id: str, urls: list) -> ProgressTracker:
        """Start a new analysis with progress tracking"""
        tracker = ProgressTracker()
        tracker.start_tracking(len(urls))
        
        analysis_info = {
            'id': analysis_id,
            'start_time': datetime.now(),
            'url_count': len(urls),
            'tracker': tracker
        }
        
        self.current_analysis = analysis_info
        return tracker
    
    def complete_analysis(self):
        """Complete current analysis and add to history"""
        if self.current_analysis:
            self.current_analysis['tracker'].complete_tracking()
            self.current_analysis['end_time'] = datetime.now()
            
            # Add to history
            self.analysis_history.append(self.current_analysis)
            
            # Limit history size
            if len(self.analysis_history) > self.max_history:
                self.analysis_history = self.analysis_history[-self.max_history:]
            
            self.current_analysis = None
    
    def get_current_analysis(self) -> Optional[Dict[str, Any]]:
        """Get current analysis information"""
        return self.current_analysis
    
    def get_analysis_history(self) -> list:
        """Get analysis history"""
        return self.analysis_history.copy()
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get statistics from analysis history"""
        if not self.analysis_history:
            return {'no_data': True}
        
        total_analyses = len(self.analysis_history)
        total_urls = sum(analysis['url_count'] for analysis in self.analysis_history)
        
        # Calculate average analysis time
        completed_analyses = [
            analysis for analysis in self.analysis_history 
            if 'end_time' in analysis
        ]
        
        if completed_analyses:
            total_time = sum(
                (analysis['end_time'] - analysis['start_time']).total_seconds()
                for analysis in completed_analyses
            )
            avg_time = total_time / len(completed_analyses)
        else:
            avg_time = 0
        
        return {
            'total_analyses': total_analyses,
            'total_urls_analyzed': total_urls,
            'average_analysis_time': round(avg_time, 2),
            'average_urls_per_analysis': round(total_urls / total_analyses, 1)
        }
