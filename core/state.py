#!/usr/bin/env python3
"""
CHOMBEZA - Scan State Persistence Module
Handles saving and loading scan states for resume capability
"""

import os
import json
import time
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger("CHOMBEZA.State")

@dataclass
class ScanState:
    """Represents a saved scan state"""
    target: str
    scan_type: str
    start_time: float
    completed_tasks: int
    total_tasks: int
    stats: Dict[str, int]
    vulnerabilities: List[Dict]
    scanned_urls: List[str]
    config: Dict[str, Any]
    queue_snapshot: List[Dict]
    version: str = "2.0"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanState':
        """Create from dictionary"""
        return cls(**data)

class StateManager:
    """
    Manages scan state persistence
    """
    
    def __init__(self, state_dir: str = "scans"):
        self.state_dir = Path(state_dir)
        self.lock = threading.RLock()
        self.current_state: Optional[ScanState] = None
        self.autosave_enabled = True
        self.autosave_interval = 60  # seconds
        self.last_autosave = time.time()
        
        # Ensure directory exists
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create state directory: {e}")
    
    def save_state(self, state: ScanState, filename: Optional[str] = None) -> Optional[str]:
        """
        Save scan state to file
        
        Args:
            state: ScanState object
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            Path to saved file or None if failed
        """
        with self.lock:
            try:
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    # Clean target for filename
                    safe_target = state.target.replace('://', '_').replace('/', '_')
                    safe_target = safe_target.replace('?', '_').replace('=', '_').replace('&', '_')
                    safe_target = safe_target.replace(':', '_').replace('*', '_').replace('"', '_')
                    safe_target = safe_target.replace('<', '_').replace('>', '_').replace('|', '_')
                    safe_target = safe_target[:50]
                    filename = f"scan_{safe_target}_{timestamp}.json"
                
                filepath = self.state_dir / filename
                
                # Ensure directory exists
                try:
                    filepath.parent.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    logger.error(f"Failed to create directory: {e}")
                    # Try current directory as fallback
                    filepath = Path(filename)
                
                # Prepare data for serialization
                data = state.to_dict()
                
                # Add metadata
                data['saved_at'] = time.time()
                data['saved_at_str'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                data['version'] = getattr(state, 'version', '2.0')
                
                # Save to file with error handling
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, default=str)
                    logger.info(f"Scan state saved to {filepath}")
                    return str(filepath)
                    
                except OSError as e:
                    logger.error(f"Failed to write state file {filepath}: {e}")
                    # Try with a simpler filename as fallback
                    fallback_filename = f"scan_{int(time.time())}.json"
                    fallback_path = self.state_dir / fallback_filename
                    
                    try:
                        with open(fallback_path, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2, default=str)
                        logger.info(f"Scan state saved to fallback location: {fallback_path}")
                        return str(fallback_path)
                    except Exception as e2:
                        logger.error(f"Fallback save also failed: {e2}")
                        return None
                        
            except Exception as e:
                logger.error(f"Failed to save scan state: {e}")
                return None
    
    def load_state(self, filepath: str) -> Optional[ScanState]:
        """
        Load scan state from file
        
        Args:
            filepath: Path to state file
            
        Returns:
            ScanState object or None if loading failed
        """
        try:
            path = Path(filepath)
            if not path.exists():
                logger.error(f"State file not found: {filepath}")
                return None
            
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate version
            if data.get('version') != '2.0':
                logger.warning(f"State file version mismatch: {data.get('version')} != 2.0")
            
            state = ScanState.from_dict(data)
            self.current_state = state
            
            logger.info(f"Scan state loaded from {filepath}")
            return state
            
        except Exception as e:
            logger.error(f"Failed to load scan state: {e}")
            return None
    
    def list_states(self) -> List[Dict]:
        """List all available scan states"""
        states = []
        
        try:
            for filepath in self.state_dir.glob("scan_*.json"):
                try:
                    stat = filepath.stat()
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    states.append({
                        "filename": filepath.name,
                        "path": str(filepath),
                        "target": data.get('target', 'Unknown'),
                        "scan_type": data.get('scan_type', 'Unknown'),
                        "saved_at": data.get('saved_at_str', 'Unknown'),
                        "size": stat.st_size,
                        "total_vulns": data.get('stats', {}).get('total', 0),
                        "progress": (data.get('completed_tasks', 0) / max(data.get('total_tasks', 1), 1)) * 100
                    })
                except Exception as e:
                    logger.debug(f"Failed to read state file {filepath}: {e}")
        except Exception as e:
            logger.error(f"Failed to list states: {e}")
        
        # Sort by saved time (newest first)
        states.sort(key=lambda x: x.get('saved_at', ''), reverse=True)
        return states
    
    def delete_state(self, filename: str) -> bool:
        """Delete a state file"""
        try:
            filepath = self.state_dir / filename
            if filepath.exists():
                filepath.unlink()
                logger.info(f"Deleted state file: {filename}")
                return True
        except Exception as e:
            logger.error(f"Failed to delete state file: {e}")
        return False
    
    def auto_save(self, scanner) -> bool:
        """
        Automatically save state if interval has passed
        
        Args:
            scanner: Scanner instance
            
        Returns:
            True if state was saved
        """
        if not self.autosave_enabled:
            return False
        
        now = time.time()
        if now - self.last_autosave < self.autosave_interval:
            return False
        
        try:
            # Create state from scanner
            state = ScanState(
                target=scanner.target,
                scan_type=scanner.scan_type,
                start_time=scanner.start_time or now,
                completed_tasks=scanner.completed_tasks,
                total_tasks=scanner.total_tasks,
                stats=scanner.stats,
                vulnerabilities=[v.to_dict() for v in scanner.vulnerabilities],
                scanned_urls=list(scanner.scanned_urls),
                config=scanner.config,
                queue_snapshot=[]  # Queue can't be easily serialized
            )
            
            # Save with autosave prefix
            filename = f"autosave_{int(now)}.json"
            self.save_state(state, filename)
            
            # Clean up old autosaves (keep last 5)
            self._cleanup_autosaves()
            
            self.last_autosave = now
            return True
            
        except Exception as e:
            logger.error(f"Auto-save failed: {e}")
            return False
    
    def _cleanup_autosaves(self, keep: int = 5):
        """Keep only the most recent autosaves"""
        try:
            autosaves = sorted(
                [f for f in self.state_dir.glob("autosave_*.json")],
                key=lambda f: f.stat().st_mtime,
                reverse=True
            )
            
            for old_file in autosaves[keep:]:
                try:
                    old_file.unlink()
                    logger.debug(f"Removed old autosave: {old_file.name}")
                except:
                    pass
        except Exception as e:
            logger.error(f"Failed to cleanup autosaves: {e}")
    
    def get_state_info(self, filename: str) -> Optional[Dict]:
        """Get metadata about a state file without loading it"""
        try:
            filepath = self.state_dir / filename
            if not filepath.exists():
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return {
                "filename": filename,
                "target": data.get('target'),
                "scan_type": data.get('scan_type'),
                "saved_at": data.get('saved_at_str'),
                "total_vulns": data.get('stats', {}).get('total', 0),
                "critical": data.get('stats', {}).get('critical', 0),
                "high": data.get('stats', {}).get('high', 0),
                "medium": data.get('stats', {}).get('medium', 0),
                "low": data.get('stats', {}).get('low', 0),
                "info": data.get('stats', {}).get('info', 0),
                "progress": (data.get('completed_tasks', 0) / max(data.get('total_tasks', 1), 1)) * 100
            }
        except Exception as e:
            logger.error(f"Failed to read state info: {e}")
            return None

# Global state manager
_state_manager = None

def get_state_manager() -> StateManager:
    """Get or create global state manager"""
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager()
    return _state_manager