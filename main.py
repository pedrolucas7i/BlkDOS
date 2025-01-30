import psutil
import platform
import socket
import curses
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
from collections import defaultdict
import subprocess
import os
import requests

LOG_FILE = "ips.log"
CONFIG_FILE = "limites_config.txt"

def obter_geolocalizacao(ip):
    """ Obtém a geolocalização do IP usando a API ip-api.com """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data["status"] == "success":
            return f"{data['city']}, {data['regionName']}, {data['country']}"
        else:
            return "Localização desconhecida"
    except Exception as e:
        print(f"Erro ao obter localização de {ip}: {e}")
        return "Erro na API"

# Função para ler o arquivo de configuração de limites
def ler_configuracoes(arquivo):
    limites = {
        "ICMP": 100,   # Valor padrão
        "TCP": 200,    # Valor padrão
        "UDP": 150     # Valor padrão
    }

    try:
        with open(arquivo, "r") as file:
            for linha in file:
                if "LIMITE_PACOTES_ICMP" in linha:
                    limites["ICMP"] = int(linha.split("=")[-1].strip())
                elif "LIMITE_PACOTES_TCP" in linha:
                    limites["TCP"] = int(linha.split("=")[-1].strip())
                elif "LIMITE_PACOTES_UDP" in linha:
                    limites["UDP"] = int(linha.split("=")[-1].strip())
    except FileNotFoundError:
        print(f"Arquivo de configuração '{arquivo}' não encontrado. Usando valores padrão.")

    return limites

# Carregar limites do arquivo de configuração
limites_diarios = ler_configuracoes(CONFIG_FILE)

# Dicionário para armazenar o número de pacotes recebidos por IP e estado das conexões
pacotes_por_ip = defaultdict(lambda: {"ICMP": 0, "TCP": 0, "UDP": 0})
conexoes_tcp = defaultdict(lambda: {"estado": "CLOSED", "pacotes": 0, "primeira_conexao": None, "ultima_conexao": None, "portas": set()})


"""
# Função para carregar dados do arquivo LOG_FILE
def carregar_dados_do_arquivo():
    # Carrega os dados do arquivo LOG_FILE e retorna como dicionário.
    dados = {}
    try:
        with open(LOG_FILE, "r") as f:
            for linha in f:
                partes = linha.strip().split(",")
                if len(partes) == 6:  # IP, Protocolo, Conexões, Última Conexão, Local, Remoto
                    ip = partes[0].strip()
                    protocolo = partes[1].strip()
                    conexoes = int(partes[2].strip())
                    ultima_conexao = partes[3].strip()
                    local = partes[4].strip()
                    remoto = partes[5].strip()
                    dados[ip] = {
                        "protocolo": protocolo,
                        "conexoes": conexoes,
                        "ultima_conexao": ultima_conexao,
                        "local": local,
                        "remoto": remoto,
                    }
    except FileNotFoundError:
        pass
    return dados
"""

# Função para salvar dados no arquivo
def salvar_dados_no_arquivo(dados):
    """Salva o dicionário de dados no arquivo LOG_FILE."""
    with open(LOG_FILE, "w") as f:
        for ip, info in dados.items():
            linha = f"{ip},{info['protocolo']},{info['conexoes']},{info['ultima_conexao']},{info['local']},{info['remoto']}\n"
            f.write(linha)

# Função para atualizar os dados
def atualizar_dados(dados, ip, protocolo, local, remoto):
    """Atualiza os dados para o IP fornecido, incluindo geolocalização."""
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ip not in dados:
        dados[ip] = {
            "protocolo": protocolo,
            "conexoes": 1,
            "ultima_conexao": agora,
            "local": local,
            "remoto": remoto,
            "geolocalizacao": obter_geolocalizacao(ip)  # Obtém a geolocalização
        }
    else:
        dados[ip]["conexoes"] += 1
        dados[ip]["ultima_conexao"] = agora

# Função que captura pacotes de rede
def capturar_pacotes(window, dados):
    """Captura todos os pacotes de rede e atualiza os dados."""
    def processar_pacote(pacote):
        if IP in pacote:
            ip_origem = pacote[IP].src
            local = f"{pacote[IP].dst}"  # Destino
            remoto = f"{ip_origem}"      # Origem
            if TCP in pacote:
                protocolo = "TCP"
                porta_origem = pacote[TCP].sport
                porta_destino = pacote[TCP].dport
                atualizar_tcp_conexao(ip_origem, pacote[TCP], porta_origem, porta_destino)
            elif UDP in pacote:
                protocolo = "UDP"
                porta_origem = pacote[UDP].sport
                porta_destino = pacote[UDP].dport
            elif ICMP in pacote:
                protocolo = "ICMP"
            else:
                protocolo = "Outro"
            
            # Atualiza os dados do IP com base no protocolo
            atualizar_dados(dados, ip_origem, protocolo, local, remoto)
            
            # Atualiza a contagem de pacotes por protocolo
            pacotes_por_ip[ip_origem][protocolo] += 1

            # Verifica se o número de pacotes excede o limite para aquele protocolo
            limite = limites_diarios.get(protocolo, None)
            if limite is not None and pacotes_por_ip[ip_origem][protocolo] > limite:
                print(f"Blocking {ip_origem}")
                #bloquear_ip_firewall(ip_origem)

    # Captura todos os pacotes IP (filtrando ICMP, TCP, UDP)
    sniff(filter="ip", prn=processar_pacote, store=False)

# Função para atualizar o estado da conexão TCP
def atualizar_tcp_conexao(ip, pacote_tcp, porta_origem, porta_destino):
    """Atualiza o estado das conexões TCP."""
    chave_conexao = (ip, porta_origem, porta_destino)
    
    if chave_conexao not in conexoes_tcp:
        conexoes_tcp[chave_conexao]["primeira_conexao"] = datetime.now()
    
    if pacote_tcp.flags == "S":  # Handshake SYN
        conexoes_tcp[chave_conexao]["estado"] = "SYN_SENT"
    elif pacote_tcp.flags == "A":  # ACK (resposta do handshake)
        conexoes_tcp[chave_conexao]["estado"] = "ESTABLISHED"
    elif pacote_tcp.flags == "F":  # FIN (fechamento)
        conexoes_tcp[chave_conexao]["estado"] = "FINISHED"
    
    # Incrementa o número de pacotes
    conexoes_tcp[chave_conexao]["pacotes"] += 1
    conexoes_tcp[chave_conexao]["portas"].add((porta_origem, porta_destino))
    conexoes_tcp[chave_conexao]["ultima_conexao"] = datetime.now()

# Função para exibir as conexões e pacotes no terminal
def listar_conexoes(window, dados):
    """Exibe as conexões e pacotes capturados no terminal."""
    window.clear()
    header = f"{'IP':48} {'Protocolo':<10} {'Conexões':<10} {'Última Conexão':<22} {'Localização':<45} {'Local':<48} {'Remoto':<48}"
    window.addstr(0, 0, header)
    window.addstr(1, 0, "=" * len(header))

    row = 2
    for ip, info in sorted(dados.items()):
        geolocalizacao = info.get("geolocalizacao", "N/A")  # Obtém a localização armazenada
        line = f"{ip:<48} {info['protocolo']:<10} {info['conexoes']:<10} {info['ultima_conexao']:<22} {geolocalizacao:<45} {info['local']:<48} {info['remoto']:<48}"
        window.addstr(row, 0, line)
        row += 1


# Função para bloquear um IP usando iptables no Linux
def bloquear_ip_firewall(ip):
    try:
        sistema = platform.system().lower()
        if sistema == "linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"IP {ip} bloqueado no firewall.")
        elif sistema == "windows":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=\"Bloqueio Temp\"",
                            "dir=in", "action=block", f"remoteip={ip}"], check=True)
            print(f"IP {ip} bloqueado no firewall.")
        else:
            raise ValueError("Sistema operacional não suportado.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar comando de bloqueio: {e}")
    except ValueError as ve:
        print(ve)

# Função para desbloquear um IP no firewall
def desbloquear_ip_firewall(ip):
    try:
        sistema = platform.system().lower()
        if (sistema == "linux"):
                # Comando para desbloquear um IP usando iptables
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"IP {ip} desbloqueado no firewall.")
        elif (sistema == "windows"):
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=\"Bloqueio Temp\""])
                print(f"IP {ip} desbloqueado no firewall")
        else:
                print("Sistema operativo não reconhecido! (Tentando comando GNU Linux)")
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"IP {ip} desbloqueado no firewall.")

    except subprocess.CalledProcessError as e:
        print(f"Erro ao desbloquear o IP {ip}: {e}")


# Função para configurar o sudoers
def configurar_sudoers():
    """Configura o sudoers para permitir que o iptables seja executado sem senha."""
    
    usuario = os.getenv("USER")  # Pega o nome do usuário atual no sistema
    sudoers_file = "/etc/sudoers"

    # Definindo o caminho do arquivo sudoers
    sudoers_entry = f"{usuario} ALL=(ALL) NOPASSWD: /usr/sbin/iptables"

    # Verificar se a entrada já está presente
    try:
        with open(sudoers_file, "r") as file:
            conteudo = file.read()
            if sudoers_entry in conteudo:
                print("A configuração de sudoers já está presente.")
                return
    except FileNotFoundError:
        print("Erro: arquivo sudoers não encontrado.")
        return
    
    # Adicionar a entrada de permissão no sudoers
    try:
        with open(sudoers_file, "a") as file:
            file.write(f"\n{sudoers_entry}\n")
        print("Configuração do sudoers aplicada com sucesso!")
    except PermissionError:
        print("Erro: você precisa de permissões de administrador para modificar o sudoers.")


# Função principal
def main(stdscr):
    
    max_lines, max_cols = curses.LINES, curses.COLS  # Tamanho do terminal
    header = f"{'IP':48} {'Protocolo':<10} {'Conexões':<10} {'Última Conexão':<22} {'Local':<48} {'Remoto':<48}"
    if (max_cols < len(str(header))):
        print("Largura do terminal insuficiente!")
        return
    
    sistema = platform.system().lower()
    if (sistema == "linux"):
            configurar_sudoers()
    curses.curs_set(0)  # Esconde o cursor
    stdscr.nodelay(True)  # Configura o terminal para não bloquear entradas
    stdscr.timeout(1000)  # Atualiza a tela a cada 1 segundo
    dados = {}

    # Inicia a captura de pacotes em uma thread separada
    thread_pacotes = threading.Thread(target=capturar_pacotes, args=(stdscr, dados,), daemon=True)
    thread_pacotes.start()

    while True:
        stdscr.refresh()
        salvar_dados_no_arquivo(dados)  # Salva os dados no arquivo
        listar_conexoes(stdscr, dados)  # Exibe as conexões no terminal

        try:
            # Sai do programa se 'q' for pressionado
            key = stdscr.getch()
            if key == ord('q'):
                break
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    curses.wrapper(main)
