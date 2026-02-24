#!/usr/bin/env python3
"""
Professional Screenshot Capture Module for CHOMBEZA
Supports multiple backends with automatic fallback
"""

import os
import time
import base64
import logging
import tempfile
import subprocess
from typing import Optional, Dict, List
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CHOMBEZA.Screenshot")

# Try to import various screenshot libraries
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import WebDriverException, TimeoutException
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False
    logger.debug("Selenium not available")

try:
    from PIL import Image
    import io
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.debug("PIL not available")

try:
    import pyautogui
    HAS_PYAUTOGUI = True
except Exception as e:
    # pyautogui may fail on headless systems (no display)
    HAS_PYAUTOGUI = False
    logger.debug(f"PyAutoGUI not available: {e}")

try:
    import pyscreenshot as ImageGrab
    HAS_PYSCREENSHOT = True
except ImportError:
    HAS_PYSCREENSHOT = False
    logger.debug("Pyscreenshot not available")

try:
    import mss
    HAS_MSS = True
except ImportError:
    HAS_MSS = False
    logger.debug("MSS not available")

class ScreenshotCapture:
    """Professional screenshot capture with multiple backends"""
    
    def __init__(self, output_dir: str = "reports/screenshots"):
        self.output_dir = output_dir
        self._ensure_output_dir()
        self.driver = None
        self.last_screenshot = None
        
    def _ensure_output_dir(self):
        """Ensure screenshot directory exists"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.debug(f"Screenshot directory: {self.output_dir}")
        except Exception as e:
            logger.error(f"Failed to create screenshot directory: {e}")
    
    def capture_url(self, url: str, caption: str = "") -> Optional[Dict]:
        """
        Capture screenshot of a URL using available method
        Returns dictionary with screenshot data and metadata
        """
        methods = [
            self._capture_with_selenium,
            self._capture_with_playwright,
            self._capture_with_webkit2png,
            self._capture_with_cutycapt,
            self._capture_with_wkhtmltoimage,
            self._capture_with_requests_html
        ]
        
        for method in methods:
            try:
                result = method(url, caption)
                if result:
                    logger.info(f"Screenshot captured via {method.__name__}: {url}")
                    return result
            except Exception as e:
                logger.debug(f"Method {method.__name__} failed: {e}")
                continue
        
        logger.warning(f"All screenshot methods failed for: {url}")
        return self._create_placeholder_screenshot(url, caption)
    
    def _capture_with_selenium(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using Selenium with Chrome"""
        if not HAS_SELENIUM:
            return None
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--allow-insecure-localhost')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            
            # Try to find Chrome in common locations
            chrome_paths = [
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
                '/usr/bin/google-chrome',
                '/usr/bin/chromium-browser',
                '/usr/bin/chromium'
            ]
            
            for path in chrome_paths:
                if os.path.exists(path):
                    chrome_options.binary_location = path
                    break
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            self.driver.get(url)
            time.sleep(3)  # Wait for page to load
            
            # Take screenshot
            timestamp = int(time.time())
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            self.driver.save_screenshot(filepath)
            self.driver.quit()
            self.driver = None
            
            # Optimize and encode
            return self._process_image(filepath, caption, url)
            
        except Exception as e:
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            logger.debug(f"Selenium screenshot failed: {e}")
            return None
    
    def _capture_with_playwright(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using Playwright (if installed)"""
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={'width': 1920, 'height': 1080})
                page.goto(url, timeout=30000, wait_until='networkidle')
                
                timestamp = int(time.time())
                filename = f"screenshot_{timestamp}.png"
                filepath = os.path.join(self.output_dir, filename)
                
                page.screenshot(path=filepath, full_page=True)
                browser.close()
                
                return self._process_image(filepath, caption, url)
                
        except Exception as e:
            logger.debug(f"Playwright screenshot failed: {e}")
            return None
    
    def _capture_with_webkit2png(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using webkit2png (macOS)"""
        try:
            timestamp = int(time.time())
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            # Use webkit2png command line tool
            cmd = [
                'webkit2png',
                '-F',  # Full screen
                '-o', filepath.replace('.png', ''),
                '--delay=3',
                url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # webkit2png creates files with -full.png suffix
                actual_file = filepath.replace('.png', '-full.png')
                if os.path.exists(actual_file):
                    os.rename(actual_file, filepath)
                    return self._process_image(filepath, caption, url)
                    
        except Exception as e:
            logger.debug(f"webkit2png failed: {e}")
        return None
    
    def _capture_with_cutycapt(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using CutyCapt"""
        try:
            timestamp = int(time.time())
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            cmd = [
                'xvfb-run',
                'CutyCapt',
                f'--url={url}',
                f'--out={filepath}',
                '--min-width=1920',
                '--min-height=1080',
                '--delay=3000'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and os.path.exists(filepath):
                return self._process_image(filepath, caption, url)
                
        except Exception as e:
            logger.debug(f"CutyCapt failed: {e}")
        return None
    
    def _capture_with_wkhtmltoimage(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using wkhtmltoimage"""
        try:
            timestamp = int(time.time())
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            cmd = [
                'wkhtmltoimage',
                '--width', '1920',
                '--height', '1080',
                '--quality', '94',
                '--enable-javascript',
                '--javascript-delay', '3000',
                url,
                filepath
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and os.path.exists(filepath):
                return self._process_image(filepath, caption, url)
                
        except Exception as e:
            logger.debug(f"wkhtmltoimage failed: {e}")
        return None
    
    def _capture_with_requests_html(self, url: str, caption: str) -> Optional[Dict]:
        """Capture screenshot using requests-html"""
        try:
            from requests_html import HTMLSession
            
            session = HTMLSession()
            response = session.get(url)
            response.html.render(timeout=30, sleep=3, keep_page=True)
            
            # Get screenshot as bytes
            screenshot_bytes = response.html.page.screenshot({'path': None})
            
            timestamp = int(time.time())
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(screenshot_bytes)
            
            session.close()
            return self._process_image(filepath, caption, url)
            
        except Exception as e:
            logger.debug(f"Requests-HTML screenshot failed: {e}")
        return None
    
    def capture_full_page(self, url: str, caption: str = "") -> Optional[Dict]:
        """Capture full page screenshot (scroll and stitch)"""
        if not HAS_SELENIUM:
            return self.capture_url(url, caption)
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.get(url)
            time.sleep(3)
            
            # Get page dimensions
            total_height = self.driver.execute_script("return document.body.scrollHeight")
            viewport_height = self.driver.execute_script("return window.innerHeight")
            
            # Take screenshots of each section
            screenshots = []
            for i in range(0, total_height, viewport_height):
                self.driver.execute_script(f"window.scrollTo(0, {i});")
                time.sleep(0.5)
                
                screenshot = self.driver.get_screenshot_as_png()
                screenshots.append(Image.open(io.BytesIO(screenshot)))
            
            self.driver.quit()
            self.driver = None
            
            # Stitch screenshots together
            if screenshots and HAS_PIL:
                total_width = screenshots[0].width
                stitched = Image.new('RGB', (total_width, total_height))
                
                y_offset = 0
                for img in screenshots:
                    stitched.paste(img, (0, y_offset))
                    y_offset += img.height
                
                timestamp = int(time.time())
                filename = f"fullpage_{timestamp}.png"
                filepath = os.path.join(self.output_dir, filename)
                
                stitched.save(filepath, 'PNG', optimize=True)
                return self._process_image(filepath, caption, url)
            
        except Exception as e:
            logger.debug(f"Full page screenshot failed: {e}")
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            return self.capture_url(url, caption)
    
    def _process_image(self, filepath: str, caption: str, url: str) -> Dict:
        """Process image: optimize and encode to base64"""
        result = {
            'path': filepath,
            'caption': caption or f"Screenshot of {url}",
            'url': url,
            'timestamp': time.time(),
            'data': None,
            'data_b64': None
        }
        
        # Optimize image if PIL is available
        if HAS_PIL and os.path.exists(filepath):
            try:
                with Image.open(filepath) as img:
                    # Resize if too large
                    max_size = (1200, 900)
                    img.thumbnail(max_size, Image.Resampling.LANCZOS)
                    
                    # Convert to RGB if necessary
                    if img.mode in ('RGBA', 'LA', 'P'):
                        bg = Image.new('RGB', img.size, (255, 255, 255))
                        if img.mode == 'P':
                            img = img.convert('RGBA')
                        bg.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                        img = bg
                    
                    # Save optimized version
                    img.save(filepath, 'PNG', optimize=True, quality=85)
                    
                    # Encode to base64
                    with open(filepath, 'rb') as f:
                        b64 = base64.b64encode(f.read()).decode('utf-8')

                        result['data_b64'] = b64

                        result['data'] = f"data:image/png;base64,{b64}"
                        
            except Exception as e:
                logger.error(f"Image optimization failed: {e}")
                # Fallback: read raw file
                try:
                    with open(filepath, 'rb') as f:
                        b64 = base64.b64encode(f.read()).decode('utf-8')

                        result['data_b64'] = b64

                        result['data'] = f"data:image/png;base64,{b64}"
                except:
                    pass
        else:
            # Read raw file
            try:
                with open(filepath, 'rb') as f:
                    b64 = base64.b64encode(f.read()).decode('utf-8')

                    result['data_b64'] = b64

                    result['data'] = f"data:image/png;base64,{b64}"
            except:
                pass
        
        self.last_screenshot = result
        return result
    
    
    def _create_placeholder_screenshot(self, url: str, caption: str) -> Dict:
        """Create a PNG placeholder screenshot when all methods fail."""
        timestamp = int(time.time())
        filename = f"placeholder_{timestamp}.png"
        filepath = os.path.join(self.output_dir, filename)

        lines = [
            "SCREENSHOT UNAVAILABLE",
            f"URL: {url[:90]}",
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Capture failed (missing browser deps / timeout / network).",
            "See request/response evidence in the report."
        ]

        data_uri = None
        try:
            if HAS_PIL:
                from PIL import Image, ImageDraw
                W, H = 1200, 675
                img = Image.new("RGB", (W, H), (15, 23, 42))  # dark
                draw = ImageDraw.Draw(img)

                # Header bar
                draw.rectangle([0, 0, W, 80], fill=(2, 6, 23))
                draw.text((24, 24), "CHOMBEZA PoC", fill=(0, 255, 0))

                y = 120
                for line in lines:
                    draw.text((40, y), line, fill=(230, 230, 230))
                    y += 40

                img.save(filepath, "PNG", optimize=True)
                with open(filepath, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode("utf-8")
                data_uri = f"data:image/png;base64,{b64}"
            else:
                # Embedded 1x1 transparent PNG
                tiny = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+q3RsAAAAASUVORK5CYII="
                with open(filepath, "wb") as f:
                    f.write(base64.b64decode(tiny))
                data_uri = f"data:image/png;base64,{tiny}"
        except Exception as e:
            logger.debug(f"Placeholder image generation failed: {e}")

        return {
            "path": filepath,
            "caption": caption or f"Placeholder for {url}",
            "url": url,
            "timestamp": time.time(),
            "data": data_uri,
            "data_b64": None if not data_uri else data_uri.split(",", 1)[1],
            "placeholder": True
        }

    def capture_element(self, url: str, selector: str, caption: str = "") -> Optional[Dict]:
        """Capture a specific element on the page"""
        if not HAS_SELENIUM:
            return None
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.get(url)
            time.sleep(2)
            
            element = self.driver.find_element_by_css_selector(selector)
            
            timestamp = int(time.time())
            filename = f"element_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)
            
            element.screenshot(filepath)
            self.driver.quit()
            self.driver = None
            
            return self._process_image(filepath, caption, url)
            
        except Exception as e:
            logger.debug(f"Element screenshot failed: {e}")
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
            return None
    
    def get_base64(self, filepath: str) -> Optional[str]:
        """Get base64 encoded image from file"""
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'rb') as f:
                return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encode image: {e}")
            return None

# Singleton instance
screenshot_capturer = ScreenshotCapture()