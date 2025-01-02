#!/usr/bin/python
from time import sleep
from secrets import SystemRandom
from re import compile as regex_compile, IGNORECASE as regex_IGNORECASE, MULTILINE as regex_MULTILINE
from requests import Session, packages, adapters
from requests.adapters import TimeoutSauce
from requests.exceptions import Timeout
from multiprocessing import Pool, cpu_count
import dns.resolver
import smtplib
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import warnings
import urllib3
warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
import argparse

MAX_TIMEOUT_SECONDS = 6
DOMAINS_FILE = 'domains.txt'
INCLUDE_SUBDOMAINS = False
# Number of processes to use (default to CPU count)
MAX_PROCESSES = cpu_count()

class CustomTimeout(TimeoutSauce):
    def __init__(self, *args, **kwargs):
        if kwargs["connect"] is None:
            kwargs["connect"] = MAX_TIMEOUT_SECONDS
        if kwargs["read"] is None:
            kwargs["read"] = MAX_TIMEOUT_SECONDS
        super().__init__(*args, **kwargs)

adapters.TimeoutSauce = CustomTimeout
#stackoverflow.com/questions/45267003/python-requests-hanging-freezing

def rand_int(min_:int, max_:int):
  rng = SystemRandom()
  return rng.randrange(min_, max_ + 1)

def get_headers():
  # Try to get the most white-listed user-agent
  
  random_platform = rand_int(1, 3)
  is_mobile = False
  
  if random_platform == 1:
    platform = 'Windows'
  elif random_platform == 2:
    platform = 'macOS'
  else:
    platform = 'iOS'
    is_mobile = True
  
  if platform == 'Windows':
    rand_win_vers = rand_int(1, 3)
    if rand_win_vers == 1:    #8.1
      win_ver = '6.3'
      platform_version = '0.3.0'
    elif rand_win_vers == 2:   #10
      win_ver = '10.0'
      r_major = rand_int(1, 3)
      if r_major == 1:
        platform_version = '7.0.0' #Windows 10 1809
      elif r_major == 2:
        platform_version = '8.0.0' #Windows 10 1903 | 1909
      elif r_major == 3:
        platform_version = '10.0.0' #Windows 10 2004 | 20H2 | 21H1
        
    elif rand_win_vers == 3:   #11
      win_ver = '10.0' 
      platform_version = '15.0.0'
    else:
      win_ver = '10.0' #11
      platform_version = '15.0.0'
    
    chrome_agent = f"Mozilla/5.0 (Windows NT {win_ver}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
  elif platform == 'macOS':
    r_macos = rand_int(1, 4)
    if r_macos == 1:
      macos_version = '10_15_7'
      
      r_big = rand_int(1, 2)
      if r_big == 1:
        platform_version = '12.5.1' #monterey
      else:
        platform_version = '11.6.2' #big sur
    elif r_macos == 2:
      macos_version = '10_15_6' #Catalina
      platform_version = '10.15.6'
    elif r_macos == 3:
      macos_version = '10_14_6' #Mojave
      platform_version = '10.14.6'
    elif r_macos == 4:
      macos_version = '10_13_6' #High Sierra
      platform_version = '10.13.6'
    else:
      macos_version = '10_15_7'
      platform_version = '12.5.1'
      
    chrome_agent = f"Mozilla/5.0 (Macintosh; Intel Mac OS X {macos_version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
  else:
    r_device = rand_int(1, 2)
    if r_device == 1:
      ios_device = 'iPhone; CPU iPhone'
    else:
      ios_device = 'iPad; CPU'
    
    r_ios = rand_int(1, 4)
    if r_ios == 1:
      ios_version = '16_1'
    elif r_ios == 2:
      ios_version = '16_0'
    elif r_ios == 3:
      ios_version = '15_7'
    elif r_ios == 4:
      ios_version = '15_6'
    else:
      ios_version = '16_1'
    
    chrome_agent = f"Mozilla/5.0 ({ios_device} OS {ios_version} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.109 Mobile/15E148 Safari/604.1"

  if not is_mobile:
    c_headers = {'Upgrade-Insecure-Requests': '1',
    'User-Agent': chrome_agent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'sec-ch-ua': '"Google Chrome";v="109", "Chromium";v="109", "Not=A?Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-full-version': '"109.0.5414.94"',
    'sec-ch-ua-arch': '"x86"',
    'sec-ch-ua-platform': f'"{platform}"',
    'sec-ch-ua-platform-version': f'"{platform_version}"',
    'sec-ch-ua-model': '""',
    'sec-ch-ua-bitness': '"64"',
    'sec-ch-ua-wow64': '?0',
    'sec-ch-ua-full-version-list': '"Google Chrome";v="109.0.5414.94", "Chromium";v="109.0.5414.94", "Not=A?Brand";v="24.0.0.0"',
    'sec-ch-prefers-color-scheme': 'light',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9'}
  else:
    c_headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate',
    'User-Agent': chrome_agent}
    
  return c_headers

def do_get(session, get_url:str, proxy:dict, headers:dict):
   
   if headers:
     session.headers.update(headers)
   
   try:
     resp = session.get(get_url, verify=False, allow_redirects=True, proxies=proxy)
     
     if resp.status_code == 429: #Too Many Requests
       retry_after = int(resp.headers.get('Retry-After'))
       print(f'[-] Retry-After: {str(retry_after)} - {get_url}')
       sleep(retry_after + 10)
       resp = session.get(get_url, verify=False, allow_redirects=True, proxies=proxy)
     
     if resp.status_code == 200:
       return resp
   except ConnectionError:
     print(f'[-] {get_url} (ConnectionError)')
   except Timeout:
      print(f'[-] {get_url} (Timeout)')
   except Exception as e:
     print(f'[-] {str(e)} on: {get_url}')
   
   return False

def get_page_links(base_url:str, domain:str, resp, disallowed:tuple, regex_href):
  
  # Search only on html pages.
  content_type = resp.headers.get('Content-Type')
  if content_type is None or content_type.startswith('text/html') is False:
    return False
  
  links = set()
  regex_links = regex_href.findall(resp.text)
  
  for href in regex_links:
    
    href = href[1]
    if href == "" or href is None or href == '#':
      continue
    
    #Full link
    if href.startswith((base_url)):
      links.add(href)
      continue
      
    #Absolute link
    if href.startswith("/"):
      
      #Check if it's Disallowed in robots.txt
      if href.startswith(disallowed):
        continue
      
      links.add(base_url + href)
      continue
    
    if INCLUDE_SUBDOMAINS:
      #Check if it's really current domain subdomain
      sp1 = href.split('://')
      if len(sp1) != 1:
        sp2 = sp1[1].split('/')
        if len(sp2) != 1:
          hostname = sp2[0]
          sp3 = hostname.split('.' + domain)
          if len(sp3) != 1: #subdomain = sp3[0]
            links.add(href)
  
  return list(links)

def verify_email_address(email):
    """
    Verify an email address by checking domain and mail server
    Returns: (bool, str) - (is_valid, message)
    """
    # Get the domain name
    domain = email.split('@')[1]
    
    try:
        # Verify domain has MX record
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        
        # Verify server response
        with smtplib.SMTP(timeout=MAX_TIMEOUT_SECONDS) as smtp:
            smtp.connect(mx_record)
            status = smtp.helo()[0]
            if status != 250:
                return False, "Server check failed"
            return True, "Valid email"
            
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False, "Domain does not exist"
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        return False, "Server connection failed"
    except smtplib.SMTPServerDisconnected:
        return False, "Server disconnected"
    except Exception as e:
        return False, f"Verification failed: {str(e)}"

def verify_emails_batch(emails):
    """
    Verify a batch of emails using parallel processing
    """
    valid_emails = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_email = {executor.submit(verify_email_address, email): email for email in emails}
        for future in as_completed(future_to_email):
            email = future_to_email[future]
            try:
                is_valid, message = future.result()
                if is_valid:
                    valid_emails.add(email)
                else:
                    print(f"[-] {email}: {message}")
            except Exception as e:
                print(f"[-] Error verifying {email}: {str(e)}")
    
    return valid_emails
  
def extract_emails(file, regex_emails, text:str, domain_emails:set, tlds):
  all_emails = set(regex_emails.findall(text))
  parsed_emails = set()
  
  for email in all_emails:
    email = email.lower()
    if email not in domain_emails:
      if tlds:
        last_dot = email.rfind('.')
        
        if not last_dot:
          continue
          
        tld = email[last_dot + 1:]
        if tld not in tlds:
          continue

      parsed_emails.add(email)
  
  # Verify the new batch of emails
  if parsed_emails:
    verified_emails = verify_emails_batch(parsed_emails)
    
    # Write only verified emails to file
    for email in verified_emails:
      file.write(email + '\n')
      domain_emails.add(email)
    
    file.flush()
  
  return domain_emails
        
def parse_domain(domain:str, regex_emails, regex_robots, regex_href, headers:dict, tlds, initial_only=False):

  session = Session()
  
  #Firstly try to crawl via HTTP, as it's faster
  base_url = f'http://{domain}'
  main_resp = do_get(session, base_url, None, headers)
  
  if main_resp:
    if main_resp.url.startswith('https://'):
      base_url = f'https://{domain}'
  else:
    base_url = f'https://{domain}'
    main_resp = do_get(session, base_url, None, headers)

  if main_resp is False:
    return False
  
  resp = do_get(session, base_url + '/robots.txt', None, headers)
  disallowed = tuple()
  
  if resp:
    #Parse robots.txt
    r_entries = regex_robots.findall(resp.text)
    for e in r_entries:
      url = e.strip()
      if url.endswith('?') or url.endswith('$') or url.endswith('*'):
        url = url[:-1]
    
      if url not in disallowed:
        disallowed += (url, )
  
  resp = None
  links_visited = set()
  domain_emails = set()
  
  links = get_page_links(base_url, domain, main_resp, disallowed, regex_href)
  print(f'[++] {base_url} {len(links)} initial links')
  
  try:
    f = open(f'{domain}_emails.txt', 'w')
    f_links = open(f'{domain}_links.txt', 'w')
  except Exception as e:
    print(f'[-] {str(e)}')
    return False
  
  if links:
    if initial_only:
      # Process only initial links without crawling deeper
      for link in links:
        f_links.write(link + '\n')
        f_links.flush()
        links_visited.add(link)
        
        resp = do_get(session, link, None, headers)
        if resp:
          content_type = resp.headers.get('Content-Type')
          if content_type and content_type.startswith('text/html'):
            domain_emails.update(extract_emails(f, regex_emails, resp.text, domain_emails, tlds))
    else:
      # Original crawling behavior
      for link in links:
    
        if link in links_visited:
          continue
      
        print(f'[+] {link}')
        f_links.write(link + '\n')
        f_links.flush()

        resp = do_get(session, link, None, headers)
      
        links_visited.add(link)
        
        if resp:
          new_list = get_page_links(base_url, domain, resp, disallowed, regex_href)
          print(f'[++] {base_url} {len(new_list)} more links')
        
          if new_list:
            links.extend(new_list)
            for new_link in new_list:
              if new_link not in all_links:
                f_links.write(new_link + '\n')
                f_links.flush()
            domain_emails.update(extract_emails(f, regex_emails, resp.text, domain_emails, tlds))
          else:
            #If page has no href links and it's an html page then search in it too.
            content_type = resp.headers.get('Content-Type')
            if content_type and content_type.startswith('text/html'):
              domain_emails.update(extract_emails(f, regex_emails, resp.text, domain_emails, tlds))
      
  else:
    #If main page has no href links and it's an html page then search in it too.
    content_type = main_resp.headers.get('Content-Type')
    if content_type and content_type.startswith('text/html'):
      domain_emails.update(extract_emails(f, regex_emails, main_resp.text, domain_emails, tlds))
    
  f.close()
  f_links.close()
  print(f'[+] Extracted {len(domain_emails)} emails and {len(links_visited)} links from {domain}')
  
  return True

def get_iana_tlds(regex_href):
  
  session = Session()
  
  iana_path = '/domains/root/db'
  resp = do_get(session, f'http://www.iana.org{iana_path}', None, get_headers())
  
  if not resp:
    return False
  
  regex_links = regex_href.findall(resp.text)
  iana_len = len(iana_path) + 1
  
  if not regex_links:
    return False
  
  tlds = set()
  
  for href in regex_links:
    
    href = href[1]
    if href == "" or href is None or href == '#':
      continue
    
    if not href.startswith(iana_path + '/'):
      continue
    
    tld_html = href[iana_len:]
    
    # just to be sure
    if not tld_html.endswith('.html'):
      continue
    
    # 5 = len('.html')
    tld = tld_html[:-5]
    
    tlds.add(tld)
  
  if tlds:
    return tlds
  
  return False
  
def process_single_domain(args):
    """Wrapper function to handle single domain processing for multiprocessing"""
    domain, regex_pattern, regex_robots, regex_href, headers, tlds, initial_only = args
    try:
        result = parse_domain(domain, regex_pattern, regex_robots, regex_href, headers, tlds, initial_only)
        return domain, result
    except Exception as e:
        print(f"[-] Error processing domain {domain}: {str(e)}")
        return domain, False

def main():
    # Add argument parser
    parser = argparse.ArgumentParser(description='Email and link scraper')
    parser.add_argument('--initial-only', action='store_true', 
                      help='Process only initial links without crawling deeper')
    args = parser.parse_args()

    try:
        with open(DOMAINS_FILE, 'r') as f:
            domains = f.read().splitlines()
    except FileNotFoundError:
        print(f'[-] File {DOMAINS_FILE} not found!')
        return
    except PermissionError:
        print(f'[-] Insufficient permission to read {DOMAINS_FILE}!')
        return
    
    if len(domains) == 0:
        print(f'[-] File {DOMAINS_FILE} is empty!')
        return
    
    unique_domains = set()
    for domain in domains:
        if '.' in domain:
            unique_domains.add(domain)
    
    if len(unique_domains) == 0:
        print(f'[-] File {DOMAINS_FILE} contains no domains!')
        return
    
    packages.urllib3.disable_warnings()
    regex_pattern = regex_compile("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", regex_IGNORECASE)
    regex_robots = regex_compile("^Disallow[ ]*:(.*)", regex_MULTILINE)
    regex_href = regex_compile("<a\\s+(?:[^>]*?\\s+)?href=([\"'])(.*?)\\1")
    
    tlds = get_iana_tlds(regex_href)
    
    # Prepare arguments for parallel processing
    process_args = []
    headers = get_headers()  # Get headers once
    initial_only = args.initial_only
    
    for domain in unique_domains:
        args = (domain, regex_pattern, regex_robots, regex_href, headers, tlds, initial_only)
        process_args.append(args)
    
    print(f"[+] Starting parallel processing with {MAX_PROCESSES} processes")
    print(f"[+] Initial only mode: {initial_only}")
    
    # Create process pool and run domains in parallel
    with Pool(processes=MAX_PROCESSES) as pool:
        results = pool.map(process_single_domain, process_args)
    
    # Process results
    successful = 0
    failed = 0
    for domain, result in results:
        if result:
            successful += 1
        else:
            failed += 1
    
    print(f"\n[+] Processing complete:")
    print(f"[+] Successfully processed: {successful} domains")
    print(f"[-] Failed to process: {failed} domains")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        exit(1)