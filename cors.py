import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style
import json
import socket

init(autoreset=True)

from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("Key")

def whois(url):
    print(Fore.CYAN + "\n--- WHOIS Information ---\n")
    api_url = 'https://api.api-ninjas.com/v1/whois?domain={}'.format(url)
    resp = requests.get(api_url, headers={'X-Api-Key': API_KEY})
    if resp.status_code == 200:
        try:
            data = json.loads(resp.text)
            for k, v in data.items():
                print(f"{Fore.YELLOW}{k}:{Style.RESET_ALL} {v}")
        except json.JSONDecodeError:
            print(resp.text)
    else:
        print("Error:", resp.status_code, resp.text)

def makeRequest(url):
    print(Fore.CYAN + "\n--- HTTP Response Headers ---\n")
    try:
        req = requests.get(url)
        for k,v in req.headers.items():
            print(f"{Fore.GREEN}{k}:{Style.RESET_ALL} {v}")
    except requests.RequestException as e:
        print(Fore.RED + "Errore nella richiesta: ", e)

def corsHeaders(url):
    print(Fore.CYAN + "\n--- HTTP CORS's Headers ---\n")

    cors_headers = [
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'Access-Control-Expose-Headers',
        'Access-Control-Max-Age'
    ]

    headers_to_test = {
        "Origin": "https://evil.com/"
    }

    try:
        req = requests.get(url)
        head = req.headers # dict

        # 1. Allow-Origin wildcard + credentials = VULNERABLE
        allow_origin = head.get("Access-Control-Allow-Origin", "")
        allow_credentials = head.get("Access-Control-Allow-Credentials", "")

        if allow_origin == "*" and allow_credentials.lower() == "true":
            print(Fore.RED + "[!] VULNERABLE: Wildcard origin + Allow-Credentials=True (non conforme e pericoloso)")

        # 2. Allow-Origin reflects input 
        elif allow_origin == headers_to_test["Origin"]:
            print(Fore.YELLOW + "[!] POSSIBLE VULNERABILITY: Reflective origin — server riflette il valore di Origin")

        # 3. Wildcard origin 
        elif allow_origin == "*":
            print(Fore.YELLOW + "[i] Nota: Access-Control-Allow-Origin è *")

        # 4. Check missing Vary: Origin
        if "Access-Control-Allow-Origin" in head and "Vary" not in head:
            print(Fore.YELLOW + "[!] Manca l'header Vary: Origin → rischio cache poisoning")

        '''
        per ottenere l'header cors con il suo valore dobbiamo utilizzare il dizzionario head, quindi
        chiave-valore, dove la chiave è head e  il valore è h
        '''

        for h in cors_headers:
            if h in head:
                print(f"\nCORS Header trovato: {Fore.GREEN} {h}: {head[h]}{Style.RESET_ALL}\n")
    except requests.RequestException as e:
        print(Fore.RED + "Errore nella richiesta: ", e)

def main():
    
    url = input(Fore.CYAN + "\nInserisci un URL: " + Style.RESET_ALL).strip()

    parsing = urlparse(url)
    schema = parsing.scheme
    netloc = parsing.netloc
    IP = socket.gethostbyname(netloc)
    print(f"\nIP: {Fore.LIGHTMAGENTA_EX}{IP}{Style.RESET_ALL}")

    choice = input("\n1: whois + headers\n2: whois + CORS'S Headers\n")

    while(choice != "1" and choice != "2"):
        choice = input("\n1: whois + headers\n2: whois + CORS'S Headers\n")

    if url and choice == "1":
        print(Fore.MAGENTA + f"\nProtocollo: {schema} ---- Dominio: {netloc}\n")
        makeRequest(url)
        whois(netloc)
    elif url and choice == "2":
        print(Fore.MAGENTA + f"\nProtocollo: {schema} ---- Dominio: {netloc}\n")
        whois(netloc)
        corsHeaders(url)
    else:
        print(Fore.RED + "\nNessun URL immesso...\n")
        exit(-1)

if __name__ == "__main__":
    main()