import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set



class WebSecScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        