import psutil
import socket
import curses
import time

def listar_conexoes(window):
    # Configurações iniciais da janela
    window.clear()
    window.addstr(0, 0, f"{'Proto':<6} {'Endereço Local':<25} {'Endereço Remoto':<25} {'Estado':<13} {'PID':<6}")
    window.addstr(1, 0, "=" * 80)

    conexoes = psutil.net_connections(kind='inet')  # 'inet' para IPv4 e IPv6
    row = 2
    for conexao in conexoes:
        # Determina o protocolo
        proto = "TCP" if conexao.type == socket.SOCK_STREAM else "UDP"
        # Formata o endereço local
        laddr = f"{conexao.laddr.ip}:{conexao.laddr.port}" if conexao.laddr else "N/A"
        # Formata o endereço remoto
        raddr = f"{conexao.raddr.ip}:{conexao.raddr.port}" if conexao.raddr else "N/A"
        # Estado da conexão
        estado = conexao.status if conexao.status else "N/A"
        # Processo associado
        pid = str(conexao.pid) if conexao.pid else "N/A"

        # Adiciona informações à janela
        window.addstr(row, 0, f"{proto:<6} {laddr:<25} {raddr:<25} {estado:<13} {pid:<6}")
        row += 1

        # Evita exceder o tamanho da janela
        if row >= curses.LINES - 1:
            break

    window.refresh()

def main(stdscr):
    curses.curs_set(0)  # Esconde o cursor
    stdscr.nodelay(True)  # Configura o terminal para não bloquear entradas
    stdscr.timeout(1000)  # Atualiza a tela a cada 1 segundo

    while True:
        listar_conexoes(stdscr)
        try:
            # Sai do programa se 'q' for pressionado
            key = stdscr.getch()
            if key == ord('q'):
                break
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    curses.wrapper(main)
