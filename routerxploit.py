import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import os
import time
from datetime import datetime
import mimetypes
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib
from tqdm import tqdm
import shutil
import json
import logging
import sys

class RouterFind:
    def __init__(self):
        self.discovered_routes = set()
        self.discovered_files = set()
        self.visited_urls = set()
        self.base_url = None
        self.output_dir = None
        self.scan_session = None
        self.pbar = None
        self.download_progress = {}
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        self.common_extensions = {
            'web': ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do'],
            'data': ['.xml', '.json', '.csv', '.sql', '.db', '.sqlite'],
            'docs': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.rtf', '.odt'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.bmp', '.webp'],
            'config': ['.env', '.conf', '.config', '.ini', '.yml', '.yaml', '.htaccess'],
            'scripts': ['.js', '.py', '.sh', '.bat', '.css', '.jsx', '.ts', '.tsx'],
            'archives': ['.zip', '.rar', '.tar', '.gz', '.7z'],
            'media': ['.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.wav'],
            'fonts': ['.ttf', '.otf', '.woff', '.woff2', '.eot']
        }

    def setup_scan_session(self, url):
        """Configura a sessão de scan e cria diretórios necessários"""
        domain = urlparse(url).netloc
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_session = f"{domain}_{timestamp}"
        self.output_dir = os.path.join("scans", self.scan_session)
        

        for category in self.common_extensions.keys():
            os.makedirs(os.path.join(self.output_dir, category), exist_ok=True)
        

        os.makedirs(os.path.join(self.output_dir, "reports"), exist_ok=True)
        

        log_file = os.path.join(self.output_dir, "reports", "scan.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    def calculate_file_hash(self, file_path):
        """Calcula o hash SHA-256 de um arquivo"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def download_file(self, url, category):
        """Download de arquivo com progresso"""
        try:
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                file_name = os.path.basename(urlparse(url).path)
                if not file_name:
                    file_name = f"unnamed_{hashlib.md5(url.encode()).hexdigest()[:8]}"
                
                save_path = os.path.join(self.output_dir, category, file_name)
                
                total_size = int(response.headers.get('content-length', 0))
                block_size = 1024
                
                with open(save_path, 'wb') as file, tqdm(
                    desc=f"Downloading {file_name}",
                    total=total_size,
                    unit='iB',
                    unit_scale=True,
                    unit_divisor=1024,
                ) as pbar:
                    for data in response.iter_content(block_size):
                        size = file.write(data)
                        pbar.update(size)
                

                file_hash = self.calculate_file_hash(save_path)
                return save_path, file_hash
                
        except Exception as e:
            logging.error(f"Erro ao baixar {url}: {str(e)}")
        return None, None

    def is_valid_url(self, url):
        """Verificando se a URL é valida e pertence ao mesmo domínio"""
        if not url:
            return False
        
        if '#' in url:
            return False
        
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return True
        
        return parsed_url.netloc == urlparse(self.base_url).netloc

    def classify_file(self, url):
        """Classifica o arquivo baseado na extensão"""
        ext = os.path.splitext(url)[1].lower()
        for category, extensions in self.common_extensions.items():
            if ext in extensions:
                return category
        return 'outros'

    def find_routes(self, url, max_pages=100, max_threads=5):
        self.base_url = url
        self.setup_scan_session(url)
        urls_to_visit = [url]
        discovered_files_info = []

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            while urls_to_visit and len(self.visited_urls) < max_pages:
                current_url = urls_to_visit.pop(0)

                if current_url in self.visited_urls:
                    continue

                try:
                    logging.info(f"Visitando: {current_url}")
                    response = requests.get(current_url, headers=headers, timeout=10)
                    self.visited_urls.add(current_url)

                    if response.status_code != 200:
                        continue

      
                    route = urlparse(current_url).path
                    if route:
                        self.discovered_routes.add(route)

           
                    content_type = response.headers.get('content-type', '')
                    if not content_type.startswith('text/html'):
                        category = self.classify_file(current_url)
                        future = executor.submit(self.download_file, current_url, category)
                        file_path, file_hash = future.result()
                        if file_path:
                            discovered_files_info.append({
                                'url': current_url,
                                'category': category,
                                'content_type': content_type,
                                'file_path': file_path,
                                'hash': file_hash,
                                'size': os.path.getsize(file_path)
                            })

               
                    soup = BeautifulSoup(response.text, 'html.parser')

   
                    for tag in ['a', 'link', 'script', 'img', 'source', 'video', 'audio']:
                        for element in soup.find_all(tag):
                            href = element.get('href') or element.get('src')
                            if href:
                                full_url = urljoin(current_url, href)
                                if self.is_valid_url(full_url):
                                    if any(full_url.lower().endswith(ext) for ext_list in self.common_extensions.values() for ext in ext_list):
                                        self.discovered_files.add(full_url)
                                    elif full_url not in self.visited_urls:
                                        urls_to_visit.append(full_url)

                    for script in soup.find_all('script'):
                        if script.string:
                            urls = re.findall(r'["\']/((?:[a-zA-Z0-9\-\_\/]*/)*[a-zA-Z0-9\-\_]*\.[a-zA-Z0-9]+)["\']', script.string)
                            for found_url in urls:
                                full_url = urljoin(current_url, found_url)
                                if self.is_valid_url(full_url):
                                    self.discovered_files.add(full_url)

                except Exception as e:
                    logging.error(f"Erro ao processar {current_url}: {str(e)}")
                    continue

        return self.discovered_routes, discovered_files_info

def display_banner():
    banner = """
\033[31m
    ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗ ██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
    ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
    ██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
    ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
    ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
                                                                                    by Levi Maycon
\033[0m"""
    print(banner)

def generate_report(output_dir, routes, files_info, scan_duration, url):
    """Gera relatório detalhado do scan"""
    report = {
        "scan_info": {
            "target_url": url,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": f"{scan_duration:.2f} seconds",
            "total_routes": len(routes),
            "total_files": len(files_info)
        },
        "routes": sorted(list(routes)),
        "files": files_info
    }


    report_path = os.path.join(output_dir, "reports", "report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)


    html_report = f"""
    <html>
    <head>
        <title>Scan Report - {url}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .section {{ margin: 20px 0; }}
            .file-item {{ margin: 10px 0; padding: 10px; background: #f5f5f5; }}
        </style>
    </head>
    <body>
        <h1>Scan Report - {url}</h1>
        <div class="section">
            <h2>Scan Information</h2>
            <p>Date: {report['scan_info']['scan_date']}</p>
            <p>Duration: {report['scan_info']['duration']}</p>
            <p>Total Routes: {report['scan_info']['total_routes']}</p>
            <p>Total Files: {report['scan_info']['total_files']}</p>
        </div>
        <div class="section">
            <h2>Discovered Routes</h2>
            <ul>
                {''.join(f'<li>{route}</li>' for route in routes)}
            </ul>
        </div>
        <div class="section">
            <h2>Discovered Files</h2>
            {''.join(f'''
            <div class="file-item">
                <p>URL: {file['url']}</p>
                <p>Category: {file['category']}</p>
                <p>Type: {file['content_type']}</p>
                <p>Size: {file['size']} bytes</p>
                <p>Hash: {file['hash']}</p>
            </div>
            ''' for file in files_info)}
        </div>
    </body>
    </html>
    """

    html_path = os.path.join(output_dir, "reports", "report.html")
    with open(html_path, "w") as f:
        f.write(html_report)

def menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        display_banner()
        print("\n\033[93m[*] Menu Principal:\033[0m")
        print("\033[96m[1]\033[0m Iniciar novo scan")
        print("\033[96m[2]\033[0m Sobre")
        print("\033[96m[3]\033[0m GitHub")
        print("\033[96m[4]\033[0m Sair")
        
        choice = input("\n\033[93m[>]\033[0m Escolha uma opção: ")
        
        if choice == "1":
            url = input("\n\033[93m[>]\033[0m Digite a URL do site: ")
            max_pages = int(input("\033[93m[>]\033[0m Digite o número máximo de páginas para verificar (padrão: 200): ") or "200")
            max_threads = int(input("\033[93m[>]\033[0m Digite o número de threads para download (padrão: 5): ") or "5")
            
            print("\n\033[92m[+] Iniciando scan...\033[0m")
            start_time = time.time()
            
            finder = RouterFind()
            routes, files_info = finder.find_routes(url, max_pages, max_threads)
            

            scan_duration = time.time() - start_time

            generate_report(finder.output_dir, routes, files_info, scan_duration, url)
            

            print(f"\n\033[92m[+] Scan concluído com sucesso!\033[0m")
            print(f"\033[93m[+] Relatórios gerados em: {finder.output_dir}/reports/\033[0m")

        elif choice == "2":
            print("\n\033[94mSobre:\033[0m")
            print("Este programa realiza uma varredura profunda de websites, descobrindo rotas e arquivos, realizando o download de arquivos encontrados e gerando relatórios detalhados.")
            print("\n\033[94mDesenvolvedor:\033[0m Levi Maycon")
            print("\nPressione qualquer tecla para voltar ao menu principal...")
            input()

        elif choice == "3":
            print("\n\033[94mGitHub:\033[0m")
            print("Visite o repositório do projeto no GitHub: https://github.com/LeviMaycon/routerxploit")
            print("\nPressione qualquer tecla para voltar ao menu principal...")
            input()

        elif choice == "4":
            print("\n\033[92mSaindo...\033[0m")
            break

        else:
            print("\n\033[91mOpção inválida, tente novamente.\033[0m")
            input()


if __name__ == "__main__":
    menu()