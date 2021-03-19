#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#==========================================#
#                                          #
#           Snow White Web Scanner         #
#                  v. 1.0                  #
#                                          #
#==========================================#

# Imports
import argparse
import mechanize
import requests
import sys, os
import time
import validators

from bs4 import BeautifulSoup as bs
from bs4 import Comment
from pprint import pprint
from pyfiglet import Figlet
from textblob import TextBlob
from urllib.parse import urlparse, urljoin

# Main definitions
parser = argparse.ArgumentParser(description='Snow White Web Scanner Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")

args = parser.parse_args()
url = args.url
menu_actions  = {}

# Banner
f = Figlet(font='slant')
print(f.renderText('Snow White'))

print('#==========================================#\n'
'#                                          #\n'
'#           Snow White Web Scanner         #\n'
'#                  v. 1.0                  #\n'
'#                                          #\n'
'#==========================================#')

# =======================
#     MENUS FUNCTIONS
# =======================

# Clear Screen
def clrscn():
  if(os.name =='posix'):
    _ = os.system('clear')
  else:
    _ = os.system('cls')

# Main menu
def main_menu():
    print('\n#==============  MAIN MENU  ===============#')
    print('Select a scan to begin:')
    print('[s]: HTTP Scraper')
    print('[i]: SQL Injection Vulnerability Scan')
    print('[x]: Cross-Site Scripting (XXS) Vulnerability Scan')
    print('[p]: PHP Vulnerability')
    print('\n[q]: Quit')
    choice = input(" >>  ")
    exec_menu(choice)

    return

# Execute menu
def exec_menu(choice):
    clrscn()
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print('Invalid selection, please try again.\n')
            menu_actions['main_menu']()
    return

# Back to main menu
def back():
    menu_actions['main_menu']()

# Exit program
def ex():
    sys.exit()




#==========================================#
#                VULN SCANS                #
#==========================================#

#=============== HTTP Scraper ==============#

def scraper():
    report = ''
    tally = 0
    if(validators.url(url)):
        print('Validating URL...')
        result_html = bs(requests.get(url).text, "html.parser")
        password_inputs = result_html.find_all('input', { 'name' : 'password'})  
        comments = result_html.find_all(string=lambda text:isinstance(text,Comment)) 
        parwords = TextBlob(requests.get(url).text)
        for comment in comments:
            if(comment.find('key: ') > -1 ):
                report += 'Comment Issue: Plaintext key found.\n'

        for password_input in password_inputs:
            if(password_input.get('type') != 'password'):
                report += 'Input Issue: Plaintext password input found.\n'
    
        print('URL validated')
        #print(report)
        wordlist = ['administrator', 'admin', 'root', 'key', 'login', 'password', 'shadow', 'secret', 'submit', 'username', 'serial']
        for keyword in wordlist:
            print( '[ + ] Instances of \'' + keyword + '\': ' + str(parwords.word_counts[keyword]))
    
    else:
        print('Invalud URL. URLs must be in the form \'http://www.mydomain.com\'. Try Again.')

def scrape():
    print('Plaintext Vulnerabilities for ' + url)
    try:
        tic = time.perf_counter()
        scraper()
        toc = time.perf_counter()
        print(f'Scan completed in {toc - tic:0.4f} seconds')
    except:
        print('Could not complete HTTP scrape')
        print(sys.exc_info()[0])
    finally:
        main_menu()
 
#========== SQL Injection Vulns ===========#

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    # get the form action
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL
            print("[ + ] SQL Injection vulnerability detected, link:", new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[ + ] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[ + ] SQL Injection vulnerability detected, link:", url)
                print("[ + ] Form:")
                pprint(form_details)
                break   

def sqli():
    tic = time.perf_counter()
    print('SQLi Vulnerabilities for ' + url)
    try:
        scan_sql_injection(url)
        toc = time.perf_counter()
        print(f'Scan completed in {toc - tic:0.4f} seconds')
    except:
        print('No forms to scan.')
    finally:
        main_menu()


#=================XSS Vulns================#

def get_all_forms(url):
    #Given a `url`, it returns all forms from the HTML content
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    #This function extracts all possible useful information about an HTML `form`
    details = {}
    # get the form action (target url)
    action = form.attrs.get("action")
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get")
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    # construct the full URL 
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

def scan_xss(url):
    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[ + ] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('This is a test.')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[ + ] XSS Detected on {url}")
            print(f"[ * ] Form details:")
            pprint(form_details)
            is_vulnerable = True
        else:
            print('No vulnerable forms detected.')

def xss():
    tic = time.perf_counter()
    print('XSS Vulnerabilities for ' + url)
    try:
        print(scan_xss(url))  
        toc = time.perf_counter()
        print(f'Scan completed in {toc - tic:0.4f} seconds')
    except:
        print('Could not complete XSS scan')
        print(sys.exc_info()[0])
    finally:
        main_menu()

#=================PHP Vulns================#

def php_scan(url):
    result_html = bs(requests.get(url).content, "html.parser")
    phptext = TextBlob(requests.get(url).text)
    include_count = phptext.word_counts['php\?include']
    red_count = phptext.word_counts['php\?redirect']
    dirobj_count = phptext.word_counts['php\?documentID']
    print('[ + ] Instances of file inclusions: ' + str(include_count))
    print('[ + ] Instances of potentially unvalidated redirects: ' + str(red_count))
    print('[ + ] Instances of direct object reference: ' + str(dirobj_count))
  
def php():
    tic = time.perf_counter()
    print('PHP Vulnerabilities for ' + url)
    try: 
        php_scan(url)
        toc = time.perf_counter()
        print(f'Scan completed in {toc - tic:0.4f} seconds')
    except:
        print('Could not complete PHP scan')
        print(sys.exc_info()[0])
    finally:
      main_menu()

# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definition
menu_actions = {
    'main_menu': main_menu,
    's': scrape,
    'i': sqli,
    'x': xss,
    'p': php,
    'b': back,
    'q': ex,
}

# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    if(validators.url(url)):
        # Launch main menu
        print('Using ' + url)
        main_menu()
    else:
        print('Invalud URL. URLs must be in the form \'http://www.mydomain.com\'. Try Again.')