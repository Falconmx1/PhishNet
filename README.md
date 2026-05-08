
# 🎣 PhishNet - AI Anti-Phishing Intelligence

> **Detección de phishing con Inteligencia Artificial en tiempo real**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

## 🚀 ¿Qué es PhishNet?

PhishNet es una herramienta potente que combina **machine learning**, **análisis de heurísticas** y **scraping inteligente** para detectar sitios de phishing, correos fraudulentos y enlaces maliciosos.

### 🔥 Características

- ✅ Análisis de URLs con 20+ features extraídos
- 🔍 Scraping de contenido web para detectar logos falsos/forms sospechosos
- 📧 Análisis de headers y cuerpo de emails (SPF, DKIM, DMARC)
- 🤖 Modelo de ML entrenado con dataset actualizado (200k+ muestras)
- 🎯 Detección de homoglyphs y typosquatting
- 🚦 Sistema de scoring (0-100) con banderas rojas explicadas
- ☁️ API REST para integración con SIEM, firewalls, proxies

## 📦 Instalación rápida

```bash
git clone https://github.com/Falconmx1/PhishNet.git
cd PhishNet
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py

🎯 Uso básico
from phishnet import PhishDetector

detector = PhishDetector()
result = detector.analyze_url("https://paypal-secure-login.xyz")

print(f"Phish score: {result.score}/100")
print(f"Riesgo: {result.risk_level}")
print(f"Detecciones: {result.red_flags}")

📊 Ejemplo de salida
{
  "url": "https://paypal-secure-login.xyz",
  "phish_score": 94,
  "risk_level": "CRÍTICO",
  "red_flags": [
    "Dominio recién registrado (hace 3 días)",
    "Certificado SSL autofirmado",
    "Formulario de login expuesto en HTTP",
    "URL contiene 'paypal' pero dominio no es paypal.com"
  ],
  "recommendation": "BLOQUEAR - Phishing confirmado"
}

🧠 Arquitectura
URL/Email → Feature Extractor → ML Model → Score → Reporte
                ↓                    ↓
           Web Scraper          Threat Intel
           WHOIS lookup        Blacklist API
🛣️ Roadmap

    Extensión para Chrome/Firefox

    Integración con VirusTotal, PhishTank

    Dashboard en tiempo real con WebSockets

    Modelo de deep learning con transformers
