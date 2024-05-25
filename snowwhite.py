#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Snow White Web Scanner 
A simple scanner for common web vulnerabilities

Version: 2.0                 
Author: sparwol
Last Edited: 05/25/24

'''

import argparse
import os
import requests
import socket
import sys
import time
import validators
from bs4 import BeautifulSoup as bs
from bs4 import Comment
from pprint import pprint
from textblob import TextBlob
from urllib.parse import urlparse, urljoin

# Main definitions
parser = argparse.ArgumentParser(description='Snow White Web Scanner Version 2.0')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('port', type=int, help="The port to be used")
args = parser.parse_args()
url = args.url
port = args.port 
outfilename = urlparse(url).netloc.replace('.', '_')
menu_actions = {}

# =======================
#     MENU FUNCTIONS
# =======================

def clrscn():
    os.system('clear' if os.name == 'posix' else 'cls')

def main_menu():
    print('\n#================== MENU ==================#')
    print('Select a scan to begin:')
    print('[s]: Scraper')
    print('[i]: SQL Injection Vulnerability Scan')
    print('[x]: Cross-Site Scripting (XSS) Vulnerability Scan')
    print('[p]: PHP Vulnerability')
    print('[v]: Verb Tampering Vulnerability Scan')
    print('[f]: Form Field Fuzzer')
    print('[q]: Quit')
    choice = input(" >>  ").lower()
    exec_menu(choice)

def exec_menu(choice):
    clrscn()
    menu_actions.get(choice, invalid_choice)()

def invalid_choice():
    print('Invalid selection, please try again.\n')
    main_menu()

def back():
    main_menu()

def ex():
    sys.exit()

#==========================================#
#                VULN SCANS                #
#==========================================#

class Vuln:
    def __init__(self, url, port):
        self.url = url
        self.port = port

    def vuln_scan(self):
        print(f'Vulnerabilities for {self.url}')
        try:
            tic = time.perf_counter()
            # Placeholder for actual scan logic
            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')
        except Exception as e:
            print(f'Could not complete Scan: {e}')
        finally:
            main_menu()

#=============== HTTP Scraper ==============#

class Scraper(Vuln):
    
    def __init__(self, url):
        super().__init__(url, None)
        self.result_html = bs(requests.get(url).text, "html.parser")

    def scan(self):
        print(f'Scraping {self.url}')
        try:
            tic = time.perf_counter()
            password_inputs = self.result_html.find_all('input', {'name': 'password'})
            comments = self.result_html.find_all(string=lambda text: isinstance(text, Comment))
            parwords = TextBlob(requests.get(self.url).text)

            with open('./plaintext.txt') as f:
                keywords = [line.strip() for line in f]

            for keyword in keywords:
                count = parwords.word_counts[keyword]
                print(f'[{"+" if count > 0 else "-"}] Instances of {keyword}: {count}')

            toc = time.perf_counter()
            print(f'Scrape completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_s.txt", 'w') as f:
                    f.write(str(self.result_html))
                print(f'Results saved to {outfilename}_s.txt')

        except Exception as e:
            print(f'Could not complete HTTP scrape: {e}')
        finally:
            main_menu()

#========== SQL Injection Vulns ===========#

class Sqlinject(Vuln):

    @staticmethod
    def get_all_forms(url):
        return bs(requests.get(url).content, "html.parser").find_all("form")

    @staticmethod
    def get_form_details(form):
        details = {
            "action": form.attrs.get("action"),
            "method": form.attrs.get("method", "get"),
            "inputs": [{"type": input_tag.attrs.get("type", "text"), "name": input_tag.attrs.get("name")}
                       for input_tag in form.find_all("input")]
        }
        return details

    @staticmethod
    def is_vulnerable(response):
        errors = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        }
        return any(error in response.content.decode().lower() for error in errors)

    def scan(self):
        print(f'SQL Injection scan for {self.url}')
        try:
            tic = time.perf_counter()
            s = requests.Session()
            for char in "\"'":
                new_url = f"{self.url}{char}"
                res = s.get(new_url)
                if self.is_vulnerable(res):
                    print(f"[+] SQL Injection vulnerability detected, link: {new_url}")
                    return

            forms = self.get_all_forms(self.url)
            print(f"[+] Detected {len(forms)} forms on {self.url}.")

            for form in forms:
                form_details = self.get_form_details(form)
                for char in "\"'":
                    data = {input_tag["name"]: input_tag.get("value", f"test{char}") for input_tag in form_details["inputs"]}
                    target_url = urljoin(self.url, form_details["action"])
                    if form_details["method"] == "post":
                        res = s.post(target_url, data=data)
                    else:
                        res = s.get(target_url, params=data)
                    if self.is_vulnerable(res):
                        print(f"[+] SQL Injection vulnerability detected, link: {target_url}")
                        print("[*] Form details:")
                        pprint(form_details)
                        break

            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_i.txt", 'w') as f:
                    f.write(f"Detected {len(forms)} forms on {self.url}.\n")
                    for form in forms:
                        f.write(str(self.get_form_details(form)) + "\n")
                print(f'Results saved to {outfilename}_i.txt')

        except Exception as e:
            print(f'No forms to scan: {e}')
        finally:
            main_menu()

#=================XSS Vulns================#

class Xss(Vuln):

    @staticmethod
    def submit_form(form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        data = {input_tag["name"]: value if input_tag["type"] in ["text", "search"] else input_tag.get("value")
                for input_tag in form_details["inputs"]}
        return requests.post(target_url, data=data) if form_details["method"] == "post" else requests.get(target_url, params=data)

    def scan(self):
        print(f'XSS scan for {self.url}')
        try:
            tic = time.perf_counter()
            forms = Sqlinject.get_all_forms(self.url)
            if not forms:
                print(f"[ - ] Detected 0 forms on {self.url}.")
            else:
                print(f"[+] Detected {len(forms)} forms on {self.url}.")

            js_script = "<script>alert('This is a test.')</script>"
            for form in forms:
                form_details = Sqlinject.get_form_details(form)
                content = self.submit_form(form_details, self.url, js_script).content.decode()
                if js_script in content:
                    print(f"[+] XSS Detected on {self.url}")
                    print(f"[*] Form details:")
                    pprint(form_details)
                else:
                    print(f"[-] No vulnerable forms detected.")

            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_x.txt", 'w') as f:
                    f.write(f"Detected {len(forms)} forms on {self.url}.\n")
                    for form in forms:
                        f.write(str(form_details) + "\n")
                print(f'Results saved to {outfilename}_x.txt')

        except Exception as e:
            print(f'Could not complete XSS scan: {e}')
        finally:
            main_menu()

#=================PHP Vulns================#

class Php(Vuln):

    def scan(self):
        print(f'PHP vulnerability scan for {self.url}')
        try:
            tic = time.perf_counter()
            result_html = bs(requests.get(self.url).content, "html.parser")
            phptext = TextBlob(result_html.text)
            include_count = phptext.word_counts['php?include=']
            redir_count = phptext.word_counts['php?redir=']
            print(f"[{'+' if include_count > 0 else '-'}] PHP Include URL Parameter found: {include_count}")
            print(f"[{'+' if redir_count > 0 else '-'}] PHP Redir URL Parameter found: {redir_count}")

            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_p.txt", 'w') as f:
                    f.write(f"PHP Include URL Parameter count: {include_count}\n")
                    f.write(f"PHP Redir URL Parameter count: {redir_count}\n")
                print(f'Results saved to {outfilename}_p.txt')

        except Exception as e:
            print(f'Could not complete PHP vulnerability scan: {e}')
        finally:
            main_menu()

#===========HTTP Verb Tampering============#

class Verb(Vuln):

    def scan(self):
        print(f'HTTP Verb Tampering scan for {self.url}')
        try:
            tic = time.perf_counter()
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH']
            for method in methods:
                req = requests.request(method, self.url)
                print(f'[{req.status_code}] {method} {req.url}')

            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_v.txt", 'w') as f:
                    for method in methods:
                        req = requests.request(method, self.url)
                        f.write(f'[{req.status_code}] {method} {req.url}\n')
                print(f'Results saved to {outfilename}_v.txt')

        except Exception as e:
            print(f'Could not complete Verb Tampering scan: {e}')
        finally:
            main_menu()

#===========Form Field Fuzzer==============#

class Fuzzer(Vuln):

    def scan(self):
        print(f'Form Field Fuzzer scan for {self.url}')
        try:
            tic = time.perf_counter()
            fuzz = 'FUZZ'
            forms = Sqlinject.get_all_forms(self.url)
            print(f"[+] Detected {len(forms)} forms on {self.url}.")

            for form in forms:
                form_details = Sqlinject.get_form_details(form)
                print(f"[+] Fuzzing form details:")
                pprint(form_details)
                for input_tag in form_details["inputs"]:
                    input_name = input_tag["name"]
                    data = {input_name: fuzz}
                    res = requests.post(urljoin(self.url, form_details["action"]), data=data) if form_details["method"] == "post" else requests.get(urljoin(self.url, form_details["action"]), params=data)
                    print(f"[*] Fuzzing input: {input_name}, Status: {res.status_code}")

            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')

            if input('Save to file? (yes/no): ').lower() == 'yes':
                with open(f"{outfilename}_f.txt", 'w') as f:
                    f.write(f"Detected {len(forms)} forms on {self.url}.\n")
                    for form in forms:
                        f.write(str(form_details) + "\n")
                        for input_tag in form_details["inputs"]:
                            f.write(f"Fuzzing input: {input_tag['name']}\n")
                print(f'Results saved to {outfilename}_f.txt')

        except Exception as e:
            print(f'Could not complete Form Field Fuzzer scan: {e}')
        finally:
            main_menu()

# =======================
#     MENUS DEFINITIONS
# =======================

menu_actions = {
    's': Scraper(url).scan,
    'i': Sqlinject(url, port).scan,
    'x': Xss(url, port).scan,
    'p': Php(url, port).scan,
    'v': Verb(url, port).scan,
    'f': Fuzzer(url, port).scan,
    'q': ex,
}

# =======================
#      MAIN PROGRAM
# =======================

if __name__ == "__main__":
    if validators.url(url):
        main_menu()
    else:
        print('Invalid URL. Please enter a valid URL and try again.')
        sys.exit(1)
