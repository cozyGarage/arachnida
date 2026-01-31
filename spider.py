#!/usr/bin/env python3
"""
Spider - Web image scraper
Extracts images from websites recursively.

Usage: python spider.py [-rlp] URL
"""

import argparse
import os
import re
import sys
from urllib.parse import urljoin, urlparse
from collections import deque
import requests
from bs4 import BeautifulSoup


# Supported image extensions
SUPPORTED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}

# Default values
DEFAULT_DEPTH = 5
DEFAULT_PATH = './data/'

# Request headers to mimic a browser
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def get_extension(url: str) -> str:
    """Extract file extension from URL."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    # Remove query parameters from path
    path = path.split('?')[0]
    for ext in SUPPORTED_EXTENSIONS:
        if path.endswith(ext):
            return ext
    return ''


def is_image_url(url: str) -> bool:
    """Check if URL points to a supported image."""
    return get_extension(url) != ''


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def sanitize_filename(url: str) -> str:
    """Create a safe filename from URL."""
    parsed = urlparse(url)
    filename = os.path.basename(parsed.path)
    # Remove query parameters
    filename = filename.split('?')[0]
    # Replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    if not filename:
        filename = 'image'
    return filename


def download_image(url: str, save_path: str, downloaded: set) -> bool:
    """Download an image from URL."""
    if url in downloaded:
        return False
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=10, stream=True)
        response.raise_for_status()
        
        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        if 'image' not in content_type and not is_image_url(url):
            return False
        
        filename = sanitize_filename(url)
        filepath = os.path.join(save_path, filename)
        
        # Handle duplicate filenames
        base, ext = os.path.splitext(filepath)
        counter = 1
        while os.path.exists(filepath):
            filepath = f"{base}_{counter}{ext}"
            counter += 1
        
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        downloaded.add(url)
        print(f"[+] Downloaded: {filename}")
        return True
    
    except requests.RequestException as e:
        print(f"[-] Failed to download {url}: {e}", file=sys.stderr)
        return False


def extract_images_from_page(html: str, base_url: str) -> set:
    """Extract all image URLs from HTML content."""
    images = set()
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find all <img> tags
    for img in soup.find_all('img'):
        src = img.get('src') or img.get('data-src')
        if src:
            full_url = urljoin(base_url, src)
            if is_image_url(full_url):
                images.add(full_url)
    
    # Find images in <a> tags (direct links to images)
    for a in soup.find_all('a', href=True):
        href = a['href']
        full_url = urljoin(base_url, href)
        if is_image_url(full_url):
            images.add(full_url)
    
    # Find images in CSS background-image
    for tag in soup.find_all(style=True):
        style = tag['style']
        urls = re.findall(r'url\(["\']?([^"\'()]+)["\']?\)', style)
        for url in urls:
            full_url = urljoin(base_url, url)
            if is_image_url(full_url):
                images.add(full_url)
    
    # Find images in <picture> source tags
    for source in soup.find_all('source'):
        srcset = source.get('srcset')
        if srcset:
            # Parse srcset which may contain multiple URLs
            for src_entry in srcset.split(','):
                src = src_entry.strip().split()[0]
                full_url = urljoin(base_url, src)
                if is_image_url(full_url):
                    images.add(full_url)
    
    return images


def extract_links_from_page(html: str, base_url: str, same_domain: bool = True) -> set:
    """Extract all links from HTML content."""
    links = set()
    soup = BeautifulSoup(html, 'html.parser')
    base_domain = get_domain(base_url)
    
    for a in soup.find_all('a', href=True):
        href = a['href']
        full_url = urljoin(base_url, href)
        
        # Skip non-http(s) links
        if not full_url.startswith(('http://', 'https://')):
            continue
        
        # Skip image links (we handle those separately)
        if is_image_url(full_url):
            continue
        
        # Optionally restrict to same domain
        if same_domain and not full_url.startswith(base_domain):
            continue
        
        # Remove fragments
        full_url = full_url.split('#')[0]
        
        if full_url:
            links.add(full_url)
    
    return links


def fetch_page(url: str) -> str | None:
    """Fetch HTML content from URL."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def spider(url: str, recursive: bool, max_depth: int, save_path: str):
    """Main spider function to crawl and download images."""
    
    # Create save directory if it doesn't exist
    os.makedirs(save_path, exist_ok=True)
    
    if not is_valid_url(url):
        print(f"[-] Invalid URL: {url}", file=sys.stderr)
        sys.exit(1)
    
    downloaded_images = set()
    visited_pages = set()
    
    # Queue contains tuples of (url, depth)
    queue = deque([(url, 0)])
    
    print(f"[*] Starting spider on: {url}")
    print(f"[*] Recursive: {recursive}, Max depth: {max_depth}")
    print(f"[*] Save path: {os.path.abspath(save_path)}")
    print("-" * 50)
    
    while queue:
        current_url, depth = queue.popleft()
        
        if current_url in visited_pages:
            continue
        
        if recursive and depth > max_depth:
            continue
        
        visited_pages.add(current_url)
        print(f"[*] Crawling (depth {depth}): {current_url}")
        
        html = fetch_page(current_url)
        if not html:
            continue
        
        # Extract and download images
        images = extract_images_from_page(html, current_url)
        for img_url in images:
            download_image(img_url, save_path, downloaded_images)
        
        # If recursive, add links to queue
        if recursive and depth < max_depth:
            links = extract_links_from_page(html, current_url)
            for link in links:
                if link not in visited_pages:
                    queue.append((link, depth + 1))
    
    print("-" * 50)
    print(f"[*] Spider finished!")
    print(f"[*] Pages visited: {len(visited_pages)}")
    print(f"[*] Images downloaded: {len(downloaded_images)}")


def main():
    parser = argparse.ArgumentParser(
        description='Spider - Extract images from websites recursively',
        usage='%(prog)s [-rlp] URL'
    )
    parser.add_argument('url', metavar='URL', help='URL to scrape')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Recursively download images')
    parser.add_argument('-l', '--level', type=int, default=DEFAULT_DEPTH,
                        help=f'Maximum depth level for recursive download (default: {DEFAULT_DEPTH})')
    parser.add_argument('-p', '--path', type=str, default=DEFAULT_PATH,
                        help=f'Path to save downloaded files (default: {DEFAULT_PATH})')
    
    args = parser.parse_args()
    
    # Validate depth level
    if args.level < 0:
        print("[-] Error: Depth level must be non-negative", file=sys.stderr)
        sys.exit(1)
    
    spider(
        url=args.url,
        recursive=args.recursive,
        max_depth=args.level,
        save_path=args.path
    )


if __name__ == '__main__':
    main()
