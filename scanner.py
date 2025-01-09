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