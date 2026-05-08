
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

🚀 Cómo ejecutar
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Ejecutar la API
python app.py

# 3. Probar con curl
curl -X POST "http://localhost:8000/analyze/url" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-secure-login.xyz", "deep_scan": true}'

# 4. Ver documentación interactiva
# Abrir en navegador: http://localhost:8000/docs
