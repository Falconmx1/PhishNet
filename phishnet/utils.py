import logging
import sys
import socket
import ssl
from urllib.parse import urlparse
import requests
from typing import Dict, Tuple

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('phishnet.log')
    ]
)

logger = logging.getLogger('PhishNet')

def check_blacklist(url: str) -> bool:
    """
    Verifica si la URL está en listas negras (simulado)
    En producción integrar con APIs como:
    - Google Safe Browsing
    - VirusTotal
    - PhishTank
    """
    # Simulación - en producción hacer llamadas reales
    blacklist_domains = [
        'paypal-verify.xyz',
        'secure-login.tk',
        'appleid-verify.ml'
    ]
    
    parsed = urlparse(url)
    return parsed.netloc in blacklist_domains

def check_ssl_cert(url: str) -> Dict[str, bool]:
    """
    Verifica validez del certificado SSL
    """
    result = {
        'valid': False,
        'self_signed': False,
        'expired': False
    }
    
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            result['valid'] = True
            
            # Verificar self-signed (simplificado)
            issuer = dict(x[0] for x in cert['issuer'])
            if 'CN' in issuer and issuer['CN'] == hostname:
                result['self_signed'] = True
                
    except (ssl.SSLError, socket.error, Exception) as e:
        logger.debug(f"SSL check failed for {hostname}: {e}")
        result['valid'] = False
        
    return result

def normalize_url(url: str) -> str:
    """Normaliza URL para análisis"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url
