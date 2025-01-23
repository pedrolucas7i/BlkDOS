import psutil
import socket

def listar_conexoes():
    print(f"{'Proto':<6} {'Endereço Local':<25} {'Endereço Remoto':<25} {'Estado':<13} {'PID':<6}")
    print("=" * 80)

    conexoes = psutil.net_connections(kind='inet')  # 'inet' para IPv4 e IPv6
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
        pid = conexao.pid if conexao.pid else "N/A"

        print(f"{proto:<6} {laddr:<25} {raddr:<25} {estado:<13} {pid:<6}")

if __name__ == "__main__":
    listar_conexoes()
