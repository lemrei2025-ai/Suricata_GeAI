# Taller: Suricata + GenAI — Análisis automático de alertas con envío de correo

Este taller integra **Suricata (IDS/IPS)** con un modelo **GenAI** para que cada
evento detectado sea analizado automáticamente, se generen recomendaciones de
mitigación, y se notifique por correo con un checklist para el analista SOC.

## Arquitectura del laboratorio

```
Tráfico de red
     │
     ▼
 Suricata (IDS) ──► eve.json (log de eventos/alertas)
     │
     ▼
 suricata_genai_watcher.py  (vigila el log en tiempo real)
     │
     ▼
 API GenAI (Claude)  ──► analiza el evento y genera:
     │                     - severidad, tipo de ataque
     │                     - análisis técnico
     │                     - mitigaciones
     │                     - checklist para el analista
     ▼
 Correo electrónico (SMTP) al equipo de seguridad
```

---

## Paso 1 — Instalar Suricata

En Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y suricata jq
```

Verifica la instalación:

```bash
suricata --build-info
```

Identifica tu interfaz de red (para el modo IDS pasivo):

```bash
ip a
```

## Paso 2 — Configurar Suricata para generar `eve.json`

Edita `/etc/suricata/suricata.yaml` y confirma que la salida `eve-log` está
activa (viene habilitada por defecto en la mayoría de instalaciones):

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            metadata: yes
            http-body: yes
```

Define la interfaz a monitorear en la misma configuración (`af-packet` o
`pcap`, según tu entorno) y luego inicia Suricata:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i <tu_interfaz> -D
```

Confirma que se está generando el log:

```bash
tail -f /var/log/suricata/eve.json
```

## Paso 3 — Crear una regla de prueba para el taller

Para no depender de tráfico malicioso real, crea una regla simple en
`/etc/suricata/rules/local.rules`:

```
alert icmp any any -> any any (msg:"TALLER - Ping detectado (prueba ICMP)"; sid:1000001; rev:1; classtype:not-suspicious;)
```

Agrega el archivo a `suricata.yaml` (sección `rule-files`) y recarga Suricata:

```bash
sudo kill -USR2 $(pidof suricata)   # recarga reglas en caliente
```

Genera tráfico de prueba en otra terminal:

```bash
ping -c 4 8.8.8.8
```

Deberías ver una nueva línea `event_type: alert` en `eve.json`.

## Paso 4 — Preparar el entorno Python del watcher

```bash
mkdir -p /opt/suricata-genai
cp suricata_genai_watcher.py /opt/suricata-genai/
cp .env.example /opt/suricata-genai/.env
cd /opt/suricata-genai
python3 -m venv venv
source venv/bin/activate
pip install requests
```

Edita `.env` con tus datos reales:

- `ANTHROPIC_API_KEY`: tu clave de la API de Anthropic (nunca la subas a git).
- `SMTP_USER` / `SMTP_PASS`: si usas Gmail, genera una "contraseña de aplicación"
  (no tu contraseña normal de la cuenta).
- `EMAIL_TO`: correos del equipo SOC, separados por comas.

## Paso 5 — Probar el watcher manualmente

```bash
export $(cat /opt/suricata-genai/.env | xargs)
python3 /opt/suricata-genai/suricata_genai_watcher.py
```

En otra terminal, genera de nuevo tráfico de prueba (`ping -c 4 8.8.8.8`).
Deberías ver en la consola:

```
Nueva alerta detectada: TALLER - Ping detectado (prueba ICMP)
Correo enviado a analista1@empresa.com: [SOC] ...
```

Revisa tu bandeja de entrada: llegará un correo HTML con resumen ejecutivo,
severidad, análisis técnico, mitigaciones y el checklist para el analista.

## Paso 6 — Dejarlo corriendo permanentemente (systemd)

```bash
sudo useradd -r -s /usr/sbin/nologin socanalyst   # usuario de servicio
sudo chown -R socanalyst:socanalyst /opt/suricata-genai
sudo cp suricata-genai-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-genai-watcher.service
sudo systemctl status suricata-genai-watcher.service
```

Ver logs en vivo:

```bash
journalctl -u suricata-genai-watcher.service -f
```

## Paso 7 — Checklist que recibe el analista en cada correo

El modelo genera un checklist adaptado a cada alerta, pero como base general
el analista SOC debería siempre verificar:

- [ ] Confirmar si la IP origen es interna, externa o conocida/lista blanca.
- [ ] Revisar si el patrón se repite (¿es un escaneo, fuerza bruta, C2 beacon?).
- [ ] Correlacionar con otros logs (firewall, EDR, autenticación) en la misma ventana de tiempo.
- [ ] Determinar si el activo/destino es crítico (servidor, base de datos, etc.).
- [ ] Evaluar si la firma tiene historial de falsos positivos en el entorno.
- [ ] Aplicar la mitigación inmediata sugerida si la severidad es Alta/Crítica.
- [ ] Documentar el caso en el sistema de tickets / SOAR.
- [ ] Escalar a Nivel 2 si no se puede descartar como falso positivo en 30 min.
- [ ] Cerrar el caso con causa raíz y lecciones aprendidas.

## Paso 8 — Ajustes recomendados antes de producción

1. **Deduplicación / throttling**: ya incluido (`DEDUP_WINDOW_MINUTES`), para
   no inundar el correo si una firma se dispara cientos de veces por minuto.
2. **Filtrado por severidad**: `MIN_SEVERITY` controla qué tan sensibles son
   los correos (1 = solo alta severidad, 3 = todo).
3. **Persistencia**: considera guardar cada análisis en una base de datos
   (Postgres/SQLite) además del correo, para tener trazabilidad histórica.
4. **Enriquecimiento**: podrías añadir geolocalización de IP, reputación
   (VirusTotal/AbuseIPDB) antes de enviar el evento al modelo, para un
   análisis más rico.
5. **No envíes datos sensibles innecesarios** al proveedor GenAI (por ejemplo,
   payloads con credenciales o PII); considera enmascararlos antes de enviar.
6. **Manejo de errores**: si la API de GenAI falla, el script ya envía un
   correo con la info cruda para que el analista no pierda la alerta.
7. **Alta disponibilidad**: `Restart=always` en el systemd unit asegura que
   el watcher se reinicie si falla.

## Paso 9 — Extensiones posibles para continuar el taller

- Integrarlo con Slack/Teams además de (o en vez de) correo.
- Conectarlo a un SOAR (TheHive, Shuffle) para automatizar la respuesta.
- Agregar un dashboard (Kibana/Grafana) alimentado desde `eve.json` para
  visualización en paralelo al análisis por IA.
- Usar clasificación por lotes (batch) si el volumen de alertas es muy alto,
  para no exceder límites de tasa de la API.

---

Con esto tienes el taller completo, ejecutable de punta a punta: detección
(Suricata) → análisis automático (GenAI) → notificación accionable (correo)
→ checklist operativo (analista SOC).
