import psutil
import socket
import curses
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

LOG_FILE = "ips.log"

def carregar_dados_do_arquivo():
    """Carrega os dados do arquivo LOG_FILE e retorna como dicionário."""
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

def salvar_dados_no_arquivo(dados):
    """Salva o dicionário de dados no arquivo LOG_FILE."""
    with open(LOG_FILE, "w") as f:
        for ip, info in dados.items():
            linha = f"{ip},{info['protocolo']},{info['conexoes']},{info['ultima_conexao']},{info['local']},{info['remoto']}\n"
            f.write(linha)

def atualizar_dados(dados, ip, protocolo, local, remoto):
    """Atualiza os dados para o IP fornecido."""
    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if ip in dados:
        dados[ip]["conexoes"] += 1
        dados[ip]["ultima_conexao"] = agora
        dados[ip]["local"] = local
        dados[ip]["remoto"] = remoto
    else:
        dados[ip] = {
            "protocolo": protocolo,
            "conexoes": 1,
            "ultima_conexao": agora,
            "local": local,
            "remoto": remoto,
        }

def monitorar_conexoes(dados):
    """Monitora as conexões ativas e atualiza os dados."""
    conexoes = psutil.net_connections(kind='inet')
    for conexao in conexoes:
        protocolo = "TCP" if conexao.type == socket.SOCK_STREAM else "UDP"
        ip = conexao.raddr.ip if conexao.raddr else "N/A"
        local = f"{conexao.laddr.ip}:{conexao.laddr.port}" if conexao.laddr else "N/A"
        remoto = f"{conexao.raddr.ip}:{conexao.raddr.port}" if conexao.raddr else "N/A"
        atualizar_dados(dados, ip, protocolo, local, remoto)

def capturar_todos_pacotes(dados):
    """Captura todos os pacotes de rede e atualiza os dados."""
    def processar_pacote(pacote):
        if IP in pacote:
            ip_origem = pacote[IP].src
            local = f"{pacote[IP].dst}"  # Destino
            remoto = f"{ip_origem}"      # Origem
            if TCP in pacote:
                protocolo = "TCP"
            elif UDP in pacote:
                protocolo = "UDP"
            elif ICMP in pacote:
                protocolo = "ICMP"
            else:
                protocolo = "Outro"
            atualizar_dados(dados, ip_origem, protocolo, local, remoto)

    # Captura todos os pacotes IP
    sniff(filter="ip", prn=processar_pacote, store=False)

def listar_conexoes(window, dados):
    """Exibe as conexões e pacotes capturados no terminal."""
    window.clear()
    header = f"{'IP':<50} {'Protocolo':<10} {'Conexões':<10} {'Última Conexão':<22} {'Local':<50} {'Remoto':<50}"
    window.addstr(0, 0, header)
    window.addstr(1, 0, "=" * len(header))

    row = 2
    for ip, info in sorted(dados.items()):
        protocolo = info["protocolo"]
        conexoes = info["conexoes"]
        ultima_conexao = info["ultima_conexao"]
        local = info["local"]
        remoto = info["remoto"]
        line = f"{ip:<50} {protocolo:<10} {conexoes:<10} {ultima_conexao:<22} {local:<50} {remoto:<50}"
        window.addstr(row, 0, line)
        row += 1

        # Evita exceder o tamanho da janela
        if row >= curses.LINES - 1:
            break

    window.refresh()

def main(stdscr):
    curses.curs_set(0)  # Esconde o cursor
    stdscr.nodelay(True)  # Configura o terminal para não bloquear entradas
    stdscr.timeout(1000)  # Atualiza a tela a cada 1 segundo

    dados = carregar_dados_do_arquivo()  # Carrega dados do arquivo ao iniciar

    # Inicia a captura de pacotes em uma thread separada
    thread_pacotes = threading.Thread(target=capturar_todos_pacotes, args=(dados,), daemon=True)
    thread_pacotes.start()

    while True:
        monitorar_conexoes(dados)  # Atualiza os dados no arquivo
        salvar_dados_no_arquivo(dados)  # Salva os dados no arquivo
        listar_conexoes(stdscr, dados)  # Exibe as conexões ativas no terminal

        try:
            # Sai do programa se 'q' for pressionado
            key = stdscr.getch()
            if key == ord('q'):
                break
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    curses.wrapper(main)
