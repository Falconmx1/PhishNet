import re
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
from typing import Dict
import hashlib

def extract_url_features(url: str) -> Dict[str, int]:
    """
    Extrae 20+ features de una URL para detección de phishing
    """
    features = {}
    parsed = urlparse(url)
    domain_parts = tldextract.extract(url)
    
    # 1. Longitud de la URL
    features['url_length'] = len(url)
    features['url_too_long'] = 1 if len(url) > 75 else 0
    
    # 2. Contiene IP en lugar de dominio
    features['has_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0
    
    # 3. Número de puntos en el dominio
    features['num_dots'] = parsed.netloc.count('.')
    
    # 4. Contiene símbolo @
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 5. Contiene doble slash
    features['has_double_slash'] = 1 if '//' in url[7:] else 0
    
    # 6. Contiene caracteres de redirección
    features['has_redirect_chars'] = 1 if any(c in url for c in ['-', '\\', '//']) else 0
    
    # 7. Subdominios profundos
    features['subdomain_depth'] = len(domain_parts.subdomain.split('.')) if domain_parts.subdomain else 0
    
    # 8. Keywords sospechosos
    suspicious_keywords = ['secure', 'account', 'login', 'signin', 'verify', 'update', 'bank', 'paypal', 'confirm']
    features['has_suspicious_keywords'] = 1 if any(keyword in url.lower() for keyword in suspicious_keywords) else 0
    
    # 9. Contiene caracteres hexadecimales
    features['has_hex'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    
    # 10. HTTPS vs HTTP
    features['https_not_used'] = 1 if parsed.scheme != 'https' else 0
    
    # 11. Contiene prefijo "www" duplicado
    features['multiple_www'] = 1 if url.lower().count('www') > 1 else 0
    
    # 12. Longitud del hostname
    features['hostname_length'] = len(parsed.netloc)
    
    # 13. Path largo
    features['path_length'] = len(parsed.path)
    
    # 14. Tiene parámetros GET
    features['has_query_params'] = 1 if parsed.query else 0
    
    # 15. Número de parámetros
    features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
    
    # 16. Edad del dominio
    try:
        domain = domain_parts.domain + '.' + domain_parts.suffix
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            days_exist = (datetime.now() - creation_date).days
            features['domain_age_days'] = min(730, days_exist)  # Max 2 años
            features['domain_new'] = 1 if days_exist < 30 else 0
        else:
            features['domain_age_days'] = 365
            features['domain_new'] = 0
    except:
        features['domain_age_days'] = 365
        features['domain_new'] = 0
    
    # 17. Tiene TLD raro
    rare_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.site', '.website']
    features['rare_tld'] = 1 if domain_parts.suffix in rare_tlds else 0
    
    # 18. Brand mismatch (ejemplo: paypal.secure-login.com)
    popular_brands = ['paypal', 'amazon', 'ebay', 'apple', 'microsoft', 'google', 'facebook', 'dropbox', 'adobe']
    brand_mentioned = any(brand in url.lower() for brand in popular_brands)
    domain_name = domain_parts.domain.lower()
    brand_match = any(brand in domain_name for brand in popular_brands)
    
    features['mismatched_brand'] = 1 if brand_mentioned and not brand_match else 0
    
    # 19. Tiene puerto no estándar
    features['nonstandard_port'] = 1 if ':' in parsed.netloc and parsed.port not in [80, 443] else 0
    
    # 20. Distancia de Levenshtein aproximada en marcas
    # (Simplificado, en producción usar fuzzywuzzy)
    features['typo_squatting'] = 1 if any(brand[:-1] in domain_name or brand[1:] in domain_name for brand in popular_brands) else 0
    
    return features

def extract_email_features(subject: str, sender: str, body: str, headers: Dict) -> Dict[str, int]:
    """
    Extrae features de un email
    """
    features = {}
    
    # 1. Verificar SPF/DKIM/DMARC (simplificado)
    features['has_spf'] = 1 if 'spf=pass' in str(headers).lower() else 0
    features['has_dkim'] = 1 if 'dkim=pass' in str(headers).lower() else 0
    
    # 2. Remitente vs dominio real
    sender_domain = sender.split('@')[-1] if '@' in sender else ''
    features['sender_mismatch'] = 1 if sender_domain and not any(brand in sender_domain for brand in ['gmail', 'outlook', 'yahoo', 'company']) else 0
    
    # 3. Urgencia en asunto/cuerpo
    urgency_words = ['urgent', 'immediately', 'asap', 'verify now', 'account suspended', 'click here', 'limited time']
    features['urgent_language'] = 1 if any(word in subject.lower() or word in body.lower() for word in urgency_words) else 0
    
    # 4. Saludo genérico
    generic_greetings = ['dear user', 'dear customer', 'dear client', 'hello', 'dear member']
    features['generic_greeting'] = 1 if any(greeting in body.lower()[:500] for greeting in generic_greetings) else 0
    
    # 5. Solicita hacer clic en link
    features['request_click'] = 1 if 'click here' in body.lower() or 'click the link' in body.lower() else 0
    
    # 6. Pide información personal
    sensitive_keywords = ['password', 'credit card', 'social security', 'ssn', 'bank account', 'verify your identity']
    features['requests_personal_data'] = 1 if any(keyword in body.lower() for keyword in sensitive_keywords) else 0
    
    # 7. Adjuntos sospechosos
    suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar']
    # (En producción se extraerían del email)
    features['has_suspicious_attachment'] = 0
    
    # 8. Número de enlaces
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, body)
    features['num_links'] = len(urls)
    
    # 9. Contiene números de teléfono
    phone_pattern = r'\b\d{10,15}\b'
    features['has_phone'] = 1 if re.search(phone_pattern, body) else 0
    
    # 10. Reply-To diferente
    reply_to = headers.get('Reply-To', headers.get('return-path', ''))
    features['reply_to_mismatch'] = 1 if reply_to and sender not in reply_to else 0
    
    return features
