import yara
import os
import argparse
import hashlib
import json
import shutil
import concurrent.futures
import time
from colorama import init, Fore, Style
from tqdm import tqdm
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Inicializa as cores no terminal
init(autoreset=True)

def calcular_sha256(caminho_ficheiro):
    sha256_hash = hashlib.sha256()
    try:
        with open(caminho_ficheiro, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "Erro_ao_calcular_hash"

def compilar_regras(caminho_regra):
    if not os.path.exists(caminho_regra):
        print(f"{Fore.RED}[-] Erro: Caminho de regras '{caminho_regra}' não encontrado.{Style.RESET_ALL}")
        return None, []

    caminhos_carregados = []
    try:
        if os.path.isfile(caminho_regra):
            regras = yara.compile(filepath=caminho_regra)
            caminhos_carregados.append(os.path.abspath(caminho_regra))
            return regras, caminhos_carregados
            
        elif os.path.isdir(caminho_regra):
            arquivos_yara = {}
            for root, _, files in os.walk(caminho_regra):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        namespace = file.split('.')[0]
                        caminho_completo = os.path.join(root, file)
                        arquivos_yara[namespace] = caminho_completo
                        caminhos_carregados.append(os.path.abspath(caminho_completo))

            if not arquivos_yara:
                print(f"{Fore.YELLOW}[!] Nenhum ficheiro .yar encontrado em '{caminho_regra}'.{Style.RESET_ALL}")
                return None, []

            print(f"{Fore.CYAN}[*] Compilando {len(arquivos_yara)} ficheiro(s) de regras...{Style.RESET_ALL}")
            regras = yara.compile(filepaths=arquivos_yara)
            return regras, caminhos_carregados

    except yara.SyntaxError as e:
        print(f"{Fore.RED}[-] Erro de sintaxe na regra YARA: {e}{Style.RESET_ALL}")
        return None, []

def escanear_ficheiro_worker(caminho, regras, quarentena, silenciar_erros=True):
    """Função isolada que escaneia o ficheiro e devolve o resultado formatado."""
    resultado_alerta = None
    try:
        resultados = regras.match(caminho)
        if resultados:
            hash_arquivo = calcular_sha256(caminho)
            nomes_regras = [match.rule for match in resultados]
            
            alerta_msg = (
                f"\n{Fore.RED}{Style.BRIGHT}[!!!] AMEAÇA INTERCETADA [!!!]{Style.RESET_ALL}\n"
                f"{Fore.YELLOW} 📄 Alvo:   {caminho}\n"
                f"{Fore.YELLOW} 🧬 SHA256: {hash_arquivo}\n"
            )
            for regra in nomes_regras:
                alerta_msg += f"{Fore.RED} 🚨 Regra:  {regra}{Style.RESET_ALL}\n"

            if quarentena:
                pasta_quarentena = "Quarentena"
                if not os.path.exists(pasta_quarentena):
                    os.makedirs(pasta_quarentena, exist_ok=True)
                destino = os.path.join(pasta_quarentena, os.path.basename(caminho))
                
                # Pequena pausa para garantir que o SO libertou o ficheiro
                time.sleep(0.5) 
                try:
                    shutil.move(caminho, destino)
                    alerta_msg += f"{Fore.MAGENTA} 🔒 Ação: Ficheiro neutralizado e movido para a Quarentena!{Style.RESET_ALL}\n"
                except Exception as e:
                    alerta_msg += f"{Fore.RED} ❌ Erro ao mover para Quarentena: {e}{Style.RESET_ALL}\n"

            resultado_alerta = {
                "ficheiro": caminho,
                "hash_sha256": hash_arquivo,
                "regras_acionadas": nomes_regras,
                "mensagem_formatada": alerta_msg
            }
    except Exception as e:
        if not silenciar_erros:
            print(f"Erro ao ler {caminho}: {e}")
        
    return resultado_alerta

# =====================================================================
# CLASSE DO ESCUDO ATIVO (Monitorização em Tempo Real)
# =====================================================================
class SentinelShield(FileSystemEventHandler):
    def __init__(self, regras, quarentena, arquivos_regras):
        self.regras = regras
        self.quarentena = quarentena
        self.arquivos_regras = arquivos_regras

    def on_created(self, event):
        if not event.is_directory:
            self.verificar_ameaca(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.verificar_ameaca(event.src_path)

    def verificar_ameaca(self, caminho):
        # Ignora os ficheiros de regras para não criar um loop infinito
        if os.path.abspath(caminho) in self.arquivos_regras:
            return
            
        # 🛡️ NOVA REGRA: Ignora qualquer evento que aconteça dentro da Quarentena!
        if "Quarentena" in os.path.abspath(caminho):
            return

        # Aguarda um momento para o ficheiro acabar de ser descarregado/escrito
        time.sleep(1)
        resultado = escanear_ficheiro_worker(caminho, self.regras, self.quarentena)
        if resultado:
            print(resultado["mensagem_formatada"])

# =====================================================================
# FUNÇÃO PRINCIPAL
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="SentinelYara 🛡️ - Motor Avançado de Caça a Malwares")
    parser.add_argument("-r", "--rules", required=True, help="Ficheiro (.yar) ou Pasta com regras")
    parser.add_argument("-t", "--target", required=True, help="Ficheiro ou pasta alvo para varredura/monitorização")
    parser.add_argument("-q", "--quarantine", action="store_true", help="Move os ficheiros infetados para a Quarentena")
    parser.add_argument("--report", action="store_true", help="Gera um relatório JSON no final (Apenas varredura normal)")
    parser.add_argument("-w", "--watch", action="store_true", help="Ativa o Escudo Ativo (Monitorização em Tempo Real)")
    
    args = parser.parse_args()

    regras, arquivos_de_regras = compilar_regras(args.rules)
    if not regras:
        return

    alvo = args.target

    # ================= MODO ESCUDO ATIVO =================
    if args.watch:
        if not os.path.isdir(alvo):
            print(f"{Fore.RED}[-] Erro: O Escudo Ativo precisa de uma pasta como alvo, não um ficheiro.{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.GREEN}{Style.BRIGHT}🛡️ ESCUDO ATIVO LIGADO 🛡️{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] A vigiar a pasta: {os.path.abspath(alvo)}")
        print(f"{Fore.CYAN}[*] Pressiona CTRL+C para desativar o escudo.{Style.RESET_ALL}\n")

        event_handler = SentinelShield(regras, args.quarantine, arquivos_de_regras)
        observer = Observer()
        observer.schedule(event_handler, alvo, recursive=True)
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print(f"\n{Fore.YELLOW}[!] Escudo Ativo desativado.{Style.RESET_ALL}")
        observer.join()

    # ================= MODO VARREDURA TURBO =================
    else:
        print(f"{Fore.CYAN}[*] A iniciar varredura turbo...{Style.RESET_ALL}")
        lista_alvos = []

        if os.path.isfile(alvo):
            lista_alvos.append(alvo)
        elif os.path.isdir(alvo):
            for root, _, files in os.walk(alvo):
                for file in files:
                    caminho_completo = os.path.join(root, file)
                    # Ignora o arquivo de regras e a pasta Quarentena na varredura normal
                    if os.path.abspath(caminho_completo) not in arquivos_de_regras and "Quarentena" not in os.path.abspath(caminho_completo):
                        lista_alvos.append(caminho_completo)
        else:
            print(f"{Fore.RED}[-] Erro: O alvo '{alvo}' não é válido.{Style.RESET_ALL}")
            return

        relatorio_dados = []
        threads_maximas = os.cpu_count() or 4
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads_maximas) as executor:
            futuros = {executor.submit(escanear_ficheiro_worker, caminho, regras, args.quarantine): caminho for caminho in lista_alvos}
            
            for futuro in tqdm(concurrent.futures.as_completed(futuros), total=len(lista_alvos), desc="A Escanear", unit="fich", bar_format="{l_bar}{bar:30}{r_bar}"):
                resultado = futuro.result()
                if resultado:
                    tqdm.write(resultado["mensagem_formatada"])
                    relatorio_dados.append({
                        "ficheiro": resultado["ficheiro"],
                        "hash_sha256": resultado["hash_sha256"],
                        "regras_acionadas": resultado["regras_acionadas"]
                    })

        if args.report and relatorio_dados:
            ficheiro_relatorio = "relatorio_sentinel.json"
            with open(ficheiro_relatorio, "w") as f:
                json.dump(relatorio_dados, f, indent=4)
            print(f"\n{Fore.GREEN}[+] Relatório gerado com sucesso: {ficheiro_relatorio}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[+] Varredura finalizada. Ficheiros analisados: {len(lista_alvos)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()