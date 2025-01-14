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
        
    def check_sql_injec(self, url: str) -> None:
        """Test for potential SQL injection vulnerabilities"""
        sql_payloads = ["'","1' OR '1' = '1", "' OR 1=1--","' UNION SELECT NULL--"]

        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(
                        f"{param} = {params[param][0]}",
                        f"{param} = {payload}"
                    )
                    response = self.session.get(test_url)

                    if any(error in response.text.lower() for error in ['sql','mysql','sqlite','postgresql','oracle']):
                        self.report_vulnerability({
                            'type':'SQL Injection',
                            'url' : url,
                            'parameter':param,
                            'payload':payload
                        })
            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")
        """This function performs sql injection checks by testing URL against
        common SQL injection payloads and looking for error messages that might
        hint a security vulnerability"""

    def check_xss(self, url:str) -> None:
        """Test for potential Cross-site scripting vulnerabilities"""
        xss_payload = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in xss_payload:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param[0]]}", f"{param} = {urllib.parse.quote(payload)}")
                    response = self.session.get(test_url)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type':'Cross-Site Scripting (XSS)',
                            'url':url,
                            'parameter':param,
                            'payload':payload
                        })
            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")
        """Here we use a set of common XSS payloads and applies the same idea.
        But the key difference here is that we are looking for our injected payload
        to appear unmodified in our response rather than looking for an error message.""" 
       
    def check_pii(self, url:str) -> None:
        """Check for exposed sensitive information"""
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type':'Sensitive Information Exposure',
                        'url':url,
                        'info_type':info_type,
                        'pattern':pattern
                    })
        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")
        """This function uses a set of predefined Regex patterns to
        search for PII like emails, phone numbers, SSNs and API keys."""
    
    def scan(self) -> List[Dict]:
        """
        Main scanning method that coordinates the security checks

        Returns:
            List of discovered vulnerabilities
        """
        print(f"n{colorama.Fore.BLUE}Starting security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")

        self.crawl(self.target_url)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injec, url)
                executor.submit(self.check_xss,url)
                executor.submit(self.check_pii, url)
        return self.vulnerabilities
    
    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Record and display found vulnerabilities"""
        self.vulnerabilities.append(vulnerability)
        print(f"{colorama.Fore.RED}[VULNERABILITY FOUND]{colorama.Style.RESET_ALL}")
        for key, value in vulnerability.items():
            print(f"{key}:{value}")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = WebSecScanner(target_url)
    vulnerabilities = scanner.scan()

    print(f"\n{colorama.Fore.GREEN}Scan Complete!{colorama.Style.RESET_ALL}")
    print(f"Total URLs scanned: {len(scanner.visited_urls)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")