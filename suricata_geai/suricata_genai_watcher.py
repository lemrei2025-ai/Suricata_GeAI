#!/usr/bin/env python3
"""
suricata_genai_watcher.py
--------------------------------
Vigila el archivo eve.json de Suricata en tiempo real, envía cada
alerta nueva a un modelo GenAI (Llama 3.3 70B, vía la API GRATUITA
de Groq, sin tarjeta de crédito) para que la analice, y envía un
correo con:
  - Resumen del evento
  - Clasificación de severidad / tipo de ataque probable
  - Análisis técnico
  - Recomendaciones de mitigación
  - Checklist de acciones para el analista de seguridad

Diseñado para un taller / laboratorio. Antes de usarlo en producción
revisa la sección de "Consideraciones de seguridad" del README.
"""

import json
import os
import time
import smtplib
import logging
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta

import requests  # pip install requests

# ----------------------------------------------------------------------
# CONFIGURACIÓN (idealmente vía variables de entorno, no hardcodeadas)
# ----------------------------------------------------------------------

EVE_JSON_PATH = os.environ.get("EVE_JSON_PATH", "/var/log/suricata/eve.json")

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.environ.get("EMAIL_TO", "")  # puede ser "a@x.com,b@x.com"

# Evita inundar de correos por el mismo tipo de alerta repetida
DEDUP_WINDOW_MINUTES = int(os.environ.get("DEDUP_WINDOW_MINUTES", "10"))

# Severidades mínimas de Suricata que dispararán el análisis (1=alta,2=media,3=baja)
MIN_SEVERITY = int(os.environ.get("MIN_SEVERITY", "3"))

LOG_FILE = os.environ.get("WATCHER_LOG", "watcher.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# Caché simple en memoria para deduplicar: {signature_id: last_sent_datetime}
_dedup_cache = {}


# ----------------------------------------------------------------------
# 1. LECTURA EN TIEMPO REAL DE eve.json (equivalente a "tail -f")
# ----------------------------------------------------------------------
def follow_file(path):
    """Generador que produce nuevas líneas añadidas al archivo, sin bloquear."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)  # nos posicionamos al final (solo eventos nuevos)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line


# ----------------------------------------------------------------------
# 2. FILTRADO: solo nos interesan eventos de tipo "alert"
# ----------------------------------------------------------------------
def parse_alert(raw_line):
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    severity = alert.get("severity", 3)
    if severity > MIN_SEVERITY:
        return None

    return event


def should_dedup(event):
    sig_id = event.get("alert", {}).get("signature_id")
    now = datetime.utcnow()
    last = _dedup_cache.get(sig_id)
    if last and now - last < timedelta(minutes=DEDUP_WINDOW_MINUTES):
        return True
    _dedup_cache[sig_id] = now
    return False


# ----------------------------------------------------------------------
# 3. ANÁLISIS CON GenAI (Llama 3.3 70B vía API gratuita de Groq)
# ----------------------------------------------------------------------
ANALYSIS_SYSTEM_PROMPT = """Eres un analista SOC (Security Operations Center) senior.
Recibirás un evento JSON generado por Suricata (IDS/IPS). Debes responder
ÚNICAMENTE con un objeto JSON válido (sin texto adicional, sin markdown),
con esta estructura exacta:

{
  "resumen_ejecutivo": "string breve, 2-3 frases",
  "severidad_estimada": "Critica | Alta | Media | Baja",
  "tipo_ataque_probable": "string",
  "indicadores_relevantes": ["ip origen, puertos, protocolo, firma, etc."],
  "falso_positivo_probable": true/false,
  "analisis_tecnico": "explicación técnica detallada de por qué se disparó la alerta y qué implica",
  "mitigaciones_inmediatas": ["acción 1", "acción 2"],
  "mitigaciones_mediano_plazo": ["acción 1", "acción 2"],
  "checklist_analista": [
    "Paso 1 de verificación...",
    "Paso 2...",
    "Paso 3..."
  ]
}

No inventes IOCs que no estén en el evento. Si falta información, dilo explícitamente
en analisis_tecnico. Sé preciso y accionable."""


def analyze_with_genai(event):
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "max_tokens": 1500,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},  # fuerza salida JSON válida
        "messages": [
            {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Evento Suricata a analizar:\n{json.dumps(event, indent=2, ensure_ascii=False)}",
            },
        ],
    }

    try:
        resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        text = text.strip().strip("```json").strip("```").strip()
        return json.loads(text)
    except Exception as e:
        logging.error(f"Error consultando GenAI (Groq): {e}")
        return {
            "resumen_ejecutivo": "No se pudo obtener análisis automático (fallo de API).",
            "severidad_estimada": "Desconocida",
            "tipo_ataque_probable": "N/A",
            "indicadores_relevantes": [],
            "falso_positivo_probable": None,
            "analisis_tecnico": f"Error: {e}",
            "mitigaciones_inmediatas": ["Revisar manualmente el evento crudo adjunto."],
            "mitigaciones_mediano_plazo": [],
            "checklist_analista": [
                "Verificar disponibilidad del servicio de análisis GenAI.",
                "Analizar el evento manualmente mientras se restablece el servicio.",
            ],
        }


# ----------------------------------------------------------------------
# 4. CONSTRUCCIÓN Y ENVÍO DEL CORREO
# ----------------------------------------------------------------------
def build_email_body(event, analysis):
    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "N/A")
    dest_ip = event.get("dest_ip", "N/A")
    proto = event.get("proto", "N/A")
    ts = event.get("timestamp", "N/A")

    checklist_html = "".join(f"<li>☐ {item}</li>" for item in analysis.get("checklist_analista", []))
    mitig_inmed_html = "".join(f"<li>{m}</li>" for m in analysis.get("mitigaciones_inmediatas", []))
    mitig_medio_html = "".join(f"<li>{m}</li>" for m in analysis.get("mitigaciones_mediano_plazo", []))
    iocs_html = "".join(f"<li>{i}</li>" for i in analysis.get("indicadores_relevantes", []))

    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; font-size: 14px;">
      <h2 style="color:#b30000;">🚨 Alerta Suricata + Análisis GenAI</h2>
      <p><b>Fecha del evento:</b> {ts}</p>
      <p><b>Firma:</b> {alert.get('signature','N/A')} (SID {alert.get('signature_id','N/A')})</p>
      <p><b>Severidad Suricata:</b> {alert.get('severity','N/A')} &nbsp;|&nbsp;
         <b>Severidad estimada IA:</b> {analysis.get('severidad_estimada','N/A')}</p>
      <p><b>Origen → Destino:</b> {src_ip} → {dest_ip} ({proto})</p>

      <h3>Resumen ejecutivo</h3>
      <p>{analysis.get('resumen_ejecutivo','')}</p>

      <h3>Tipo de ataque probable</h3>
      <p>{analysis.get('tipo_ataque_probable','')}</p>
      <p><b>¿Posible falso positivo?</b> {analysis.get('falso_positivo_probable','N/A')}</p>

      <h3>Indicadores relevantes</h3>
      <ul>{iocs_html}</ul>

      <h3>Análisis técnico</h3>
      <p>{analysis.get('analisis_tecnico','')}</p>

      <h3>Mitigaciones inmediatas</h3>
      <ul>{mitig_inmed_html}</ul>

      <h3>Mitigaciones a mediano plazo</h3>
      <ul>{mitig_medio_html}</ul>

      <h3>✅ Checklist para el analista de seguridad</h3>
      <ul>{checklist_html}</ul>

      <hr>
      <p style="font-size:12px;color:#555;">Evento crudo (JSON):</p>
      <pre style="background:#f4f4f4;padding:10px;font-size:11px;overflow-x:auto;">{json.dumps(event, indent=2, ensure_ascii=False)}</pre>
    </body>
    </html>
    """
    return html


def send_email(subject, html_body):
    if not (SMTP_USER and SMTP_PASS and EMAIL_TO):
        logging.warning("Config SMTP incompleta: se omite el envío de correo.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(EMAIL_FROM, EMAIL_TO.split(","), msg.as_string())
        logging.info(f"Correo enviado a {EMAIL_TO}: {subject}")
    except Exception as e:
        logging.error(f"Error enviando correo: {e}")


# ----------------------------------------------------------------------
# 5. LOOP PRINCIPAL
# ----------------------------------------------------------------------
def main():
    logging.info(f"Iniciando watcher sobre {EVE_JSON_PATH} ...")
    if not os.path.exists(EVE_JSON_PATH):
        logging.error(f"No existe el archivo {EVE_JSON_PATH}. Verifica la ruta de Suricata.")
        return

    for raw_line in follow_file(EVE_JSON_PATH):
        event = parse_alert(raw_line)
        if not event:
            continue

        if should_dedup(event):
            logging.info(f"Alerta {event['alert'].get('signature')} deduplicada (ventana activa).")
            continue

        logging.info(f"Nueva alerta detectada: {event['alert'].get('signature')}")
        analysis = analyze_with_genai(event)
        subject = f"[SOC] {analysis.get('severidad_estimada','?')} - {event['alert'].get('signature','Alerta Suricata')}"
        html_body = build_email_body(event, analysis)
        send_email(subject, html_body)


if __name__ == "__main__":
    main()
