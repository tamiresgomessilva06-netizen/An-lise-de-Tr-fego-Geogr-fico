try:
    from scapy.all import sniff, IP
except ImportError as erro:
    raise SystemExit(
        "Scapy não está instalado. Instale com: python -m pip install scapy"
    ) from erro
from datetime import datetime
import urllib.request
import json

# Cache para não fazer requisições repetidas para o mesmo IP
cache_ip = {}

def obter_cidade(ip):
    # IPs internos/privados não possuem cidade na internet
    if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
        return "Rede Interna"
    
    if ip in cache_ip:
        return cache_ip[ip]
    
    try:
        # Consulta rápida e gratuita para descobrir a cidade do IP
        url = f"http://ip-api.com/json/{ip}?fields=city,country"
        req = urllib.request.urlopen(url, timeout=1)
        dados = json.loads(req.read().decode())
        
        cidade = dados.get("city", "Desconhecida")
        pais = dados.get("country", "")
        
        resultado = f"{cidade}, {pais}" if cidade != "Desconhecida" else "Desconhecida"
        cache_ip[ip] = resultado
        return resultado
    except:
        return "Desconhecida"

def processar_pacote(pacote):
    if pacote.haslayer(IP):
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst
        protocolo = pacote[IP].proto
        
        # Pega a hora atual do seu computador
        horario = datetime.now().strftime("%H:%M:%S")
        
        # Descobre a cidade do IP de destino
        cidade = obter_cidade(ip_dst)
        
        print(f"[{horario}] [IP] {ip_src} ---> {ip_dst} | Local: {cidade} (Prot: {protocolo})")

print("[*] Iniciando captura de tráfego com horário e cidade...")
sniff(prn=processar_pacote, store=False)
