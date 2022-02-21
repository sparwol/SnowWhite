#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Snow White Web Scanner 
A simple scanner for common web vulnerabilities

Version: 1.0                 
Author: sparwol
Last Edited: 01/16/22


'''             

# Imports
import argparse, os, requests, socket, sys, time, validators

from bs4 import BeautifulSoup as bs
from bs4 import Comment
from pprint import pprint
from textblob import TextBlob
from urllib.parse import urlparse, urljoin

# Main definitions
parser = argparse.ArgumentParser(description='Snow White Web Scanner Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('port', type=int, help="The port to be used")

args = parser.parse_args()
url = args.url
port = args.port 
outfilename = url.replace('http://', '').replace('https://', '').rstrip('/')
menu_actions  = {}
print(outfilename)
original_stdout = sys.stdout # Save a reference to the original standard output


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
    print('\n#================== MENU ==================#')
    print('Select a scan to begin:')
    print('[s]: Scraper')
    print('[i]: SQL Injection Vulnerability Scan')
    print('[x]: Cross-Site Scripting (XXS) Vulnerability Scan')
    print('[p]: PHP Vulnerability')
    print('[v]: Verb Tampering Vulnerability Scan')
    print('[f]: Form Field Fuzzer')
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

class Vuln:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        

    def vuln_scan(self):
        print('Vulnerabilities for ' + url)
        try:
            tic = time.perf_counter()
    
            toc = time.perf_counter()
            print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
            print('Could not complete Scan')
            print(sys.exc_info()[0])
        finally:
            main_menu()
        return None


#=============== HTTP Scraper ==============#

class Scraper(Vuln):
    
    def __init__(host):
        result_html = bs(requests.get(host).text, "html.parser")
        password_inputs = result_html.find_all('input', { 'name' : 'password'})  
        comments = result_html.find_all(string=lambda text:isinstance(text,Comment)) 
        parwords = TextBlob(requests.get(host).text)

        print('URL validated')

        with open('./plaintext.txt') as f: 
            lines = [line.strip() for line in f]
        for keyword in lines:
            if parwords.word_counts[keyword] == 0:
                print('[ - ] Instances of ' + keyword + ': 0')
            else:
                print( '[ + ] Instances of ' + keyword + ': ' + str(parwords.word_counts[keyword]))
    
    def vuln_scan():
        tic = time.perf_counter()
        print('Plaintext Vulnerabilities for ' + url)
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_s.txt", 'w+') as s:
                    s.write(str(Scraper.__init__(url)))
                    s.close
            else:
                Scraper.__init__(url)
                toc = time.perf_counter()
                print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
            print('Could not complete HTTP scrape')
            print(sys.exc_info())
        finally:
            main_menu()
 
#========== SQL Injection Vulns ===========#

class Sqlinject(Vuln):

    def get_all_forms(url):
        soup = bs(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(form):
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
        s = requests.Session()
        #s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        for c in "\"'":
            # add quote/double quote character to the URL
            new_url = f"{url}{c}"
            # make the HTTP request
            res = s.get(new_url)
            if Sqlinject.is_vulnerable(res):
                # SQL Injection detected on the URL
                print("[ + ] SQL Injection vulnerability detected, link:", new_url)
                return
        # test on HTML forms
        forms = Sqlinject.get_all_forms(url)
        print(f"[ + ] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = Sqlinject.get_form_details(form)
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
                if Sqlinject.is_vulnerable(res):
                    print("[ + ] SQL Injection vulnerability detected, link:", url)
                    print("[ + ] Form:")
                    pprint(form_details)
                    break   

    def vuln_scan():
        tic = time.perf_counter()
        print('SQLi Vulnerabilities for ' + url)
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_i.txt", 'w+') as i:
                    i.write(str(Sqlinject.scan_sql_injection(url)))
                    i.close
            else:
                Sqlinject.scan_sql_injection(url)
                toc = time.perf_counter()
                print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
            print('No forms to scan.')
        finally:
            main_menu()

#=================XSS Vulns================#

class Xss(Vuln):

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

    def __init__(url):
        # get all the forms from the URL
        forms = Sqlinject.get_all_forms(url)
        if len(forms) == 0:
            print(f"[ - ] Detected 0 forms on {url}.")
        else:
            print(f"[ + ] Detected {len(forms)} forms on {url}.")
        js_script = "<script>alert('This is a test.')</script>"
        # returning value
        is_vulnerable = False
        # iterate over all forms
        for form in forms:
            form_details = Sqlinject.get_form_details(form)
            content = Xss.submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                print(f"[ + ] XSS Detected on {url}")
                print(f"[ * ] Form details:")
                pprint(form_details)
                is_vulnerable = True
            else:
                print('No vulnerable forms detected.')

    def vuln_scan():
        tic = time.perf_counter()
        print('XSS Vulnerabilities for ' + url)
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_x.txt", 'w+') as x:
                    x.write(str(Xss.__init__(url)))
                    x.close
            else:
                print(Xss.__init__(url))  
                toc = time.perf_counter()
                print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
           print('Could not complete XSS scan')
           print(sys.exc_info()[0])
        finally:
           main_menu()

#=================PHP Vulns================#

class Php(Vuln):

    def __init__(url):
        result_html = bs(requests.get(url).content, "html.parser")
        phptext = TextBlob(requests.get(url).text)
        include_count = phptext.word_counts['php?include=']
        red_count = phptext.word_counts['php?redirect=']
        dirobj_count = phptext.word_counts['php?documentID=']
        file_count = phptext.word_counts['php?file=']
        print('[ + ] Instances of file inclusions: ' + str(include_count + file_count))
        print('[ + ] Instances of potentially unvalidated redirects: ' + str(red_count))
        print('[ + ] Instances of direct object reference: ' + str(dirobj_count))
        
    
    def vuln_scan():
        tic = time.perf_counter()
        print('PHP Vulnerabilities for ' + url)
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_p.txt", 'w+') as p:
                    p.write(str(Php.__init__(url)))
                    p.close
            else: 
                Php.__init__(url)
                toc = time.perf_counter()
                print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
            print('Could not complete PHP scan')
            print(sys.exc_info()[0])
        finally:
            main_menu()

#================HTTP Verbs================#

class Verbtamp(Vuln):

    def __init__(host, port, content):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_noscheme = host.replace('http://', '').replace('https://', '').rstrip('/')    
        sock.connect((host_noscheme, port))
        sock.sendall(content)
        time.sleep(0.5)
        sock.shutdown(socket.SHUT_WR)
        rsv = ''
        while True:
            data = sock.recv(1024)
            if(not data):
                break
            rsv += data.decode()
        print(rsv)
        sock.close()

    def vuln_scan():
        verbs = ['GET', 'POST', 'PUT', 'TRACE', 'CONNECT', 'OPTIONS', 'PROPFIND']
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_v.txt", 'w+') as v:
                    for webservmethod in verbs:
                        v.write(str(webservmethod))
                        content = webservmethod + '/ HTTP/1.1 Host: ' + url 
                        v.write(str(Verbtamp.__init__(url, port, content.encode())))
                    v.close
                    
            else: 
                Php.__init__(url)
                toc = time.perf_counter()
                print(f'Scan completed in {toc - tic:0.4f} seconds')
        except:
            print('Could not complete verb tampering scan')
            print(sys.exc_info()[0])
        finally:
            main_menu()

#=============== Fuzzer ===============#

class Fuzzer(Vuln):
    def __init__(url):
        data = {}
        for form in Sqlinject.get_all_forms(url):
            for input_tag in Sqlinject.get_form_details(form)["inputs"]:
                if input_tag["type"] == "hidden":
                    # if it's hidden, use the default value
                    data[input_tag["name"]] = input_tag["value"]
                elif input_tag["type"] != "submit":
                    # all others except submit, prompt the user to set it
                    i=1
                    while i <= 10000:
                        print('Trying ' + str(i) + ' characters')
                        value = 'A' * i
                        data[input_tag["name"]] = value
                        i += 1
                    break

    def vuln_scan():
        answer = input('Save to file? ')
        try:
            if answer.lower() in 'yes': 
                with open(outfilename+"_p.txt", 'w+') as p:
                    p.write(str(Fuzzer.__init__(url)))
                    p.close
            else: 
                print('No buffer overflow found.')
        except:
            print('Could not complete fuzzer scan')
            print(sys.exc_info()[0])
        main_menu()

# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definition
menu_actions = {
    'main_menu': main_menu,
    's': Scraper.vuln_scan,
    'i': Sqlinject.vuln_scan,
    'x': Xss.vuln_scan,
    'p': Php.vuln_scan,
    'v': Verbtamp.vuln_scan,
    'f': Fuzzer.vuln_scan,
    'q': ex,
}

# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    if(validators.url(url)):
        if(0 < port < 65536):
            # Launch main menu
            # Banner
            banner = '''
            #===========================================================================================#
            #                                                                                           #
            #      ______                                ______        ______      (_)   /|             #
            #     / /  \/  ___  __    _____ ____        __ \ \    __    / | | __   ___ _|_|_  ____      #
            #     \_\____   | |/\ \  / | | \ \ \   /\   /   \ \   /\   /  | |/\ \  | |  | |  /\ \/      #
            #    ____  \ \  | |  | ||  | |  | \ \ /\ \ /     \ \ /\ \ /   | |  | | | |  | |  \ \/  /    #
            #     \_\__/_/ _|_|_ |_|_\_|_|_/   \_/  \_/       \_/  \_/   _|_|_ |_|_|_|_  \|_  \_\_/     #
            #                                                                                           #
            #                                   Vulnerability Scanner                                   #
            #                                                                                           #
            #===========================================================================================#
            '''
            print(banner)
            print('Using ' + url + ' on port ' + str(port))
            main_menu()
        else: 
            print('Invalid port.')
    else:
        print('Invalud URL. URLs must be in the form \'http://www.example.com\'. Try Again.')
