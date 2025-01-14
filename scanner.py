import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set


"""
So this class WebSecScanner will serve as our main class
handling the web security scanning functionality. It will
track our visited pages and also store our findings.
"""
class WebSecScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        

        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls : Set[str] = set()
        self.vulnerabilities : List[Dict] = []
        self.session = requests.Session()

        colorama.init()

    def normalize_url(self, url:str) -> str:
        """Normalize the url to prevent duplicate checks"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def crawl(self, url: str, depth: int = 0) -> None:
        """
        so this function here will discover pages and URLs in
        a given target application.
        """
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        try:
            self.visited_urls.add(url)
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a',href = True)
            for link in links:
                next_url = urllib.parse.urljoin(url ,link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url,depth+1)
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")
        
        
        """
        Crawl function implements depth first crawl of a website. It will explore
        all explore pages of a website while staying within the specified domain.
        """
        
        
        