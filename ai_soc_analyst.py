#!/usr/bin/env python3
"""
AI SOC Analyst Assistant
=========================
Consome alertas do Wazuh Indexer (porta 9200), aplica triagem rápida com
Claude Haiku e, quando necessário, investigação profunda com Claude Sonnet.

Arquitetura de roteamento:
    rule.level <= 6   -> ignorado (ruído estatístico, não chama LLM)
    rule.level 7-8    -> Haiku decide se escala para investigação
    rule.level >= 9   -> vai direto para Sonnet (alta confiança de relevância)

Deduplicação:
    Alertas com o mesmo (rule.id + agent.name) vistos dentro da janela de
    DEDUP_WINDOW_MINUTES reaproveitam o veredito anterior em vez de chamar
    o LLM novamente -- evita gasto redundante de tokens em padrões que
    disparam repetidamente em curto intervalo (ex: DLL search order hijack
    disparando dezenas de vezes seguidas para arquivos diferentes do mesmo
    processo).

Uso:
    python3 ai_soc_analyst.py             # loop contínuo (polling)
    python3 ai_soc_analyst.py --once      # roda uma única vez e encerra
    python3 ai_soc_analyst.py --interval 30   # muda o intervalo de polling (segundos)
"""

import argparse
import json
import os
import time
import urllib3
from datetime import datetime, timezone
from pathlib import Path

import requests
from anthropic import Anthropic

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS", "")  # defina via env var

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"

STATE_FILE = Path(__file__).parent / "state.json"
OUTPUT_FILE = Path(__file__).parent / "investigations.json"

LEVEL_IGNORE_MAX = 6      # <= 6: ignorado
LEVEL_TRIAGE_MAX = 8      # 7-8: triagem via Haiku
# >= 9: escalado direto para Sonnet

DEDUP_WINDOW_MINUTES = 30  # mesmo rule_id + agent dentro dessa janela reaproveita o veredito

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
NOTIFY_VEREDITOS = {"malicioso"}       # quais vereditos disparam notificação
NOTIFY_MIN_CONFIANCA = "alta"          # confiança mínima para disparar

client = Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None


# ---------------------------------------------------------------------------
# Estado (evita reprocessar o mesmo alerta)
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        state.setdefault("recent", {})
        return state
    return {"last_timestamp": None, "recent": {}}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def dedup_key(summary: dict) -> str:
    return f"{summary.get('rule_id')}:{summary.get('agent')}"


def check_duplicate(state: dict, key: str, current_ts: str) -> dict | None:
    """Retorna o registro em cache se o mesmo rule_id+agent foi visto dentro
    da janela de deduplicação; caso contrário, retorna None."""
    entry = state["recent"].get(key)
    if not entry:
        return None
    try:
        last_seen = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        now = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    elapsed_minutes = (now - last_seen).total_seconds() / 60
    if elapsed_minutes <= DEDUP_WINDOW_MINUTES:
        return entry
    return None


def update_dedup_cache(state: dict, key: str, ts: str, result: dict) -> None:
    state["recent"][key] = {"timestamp": ts, "result": result}


# ---------------------------------------------------------------------------
# Wazuh Indexer — busca de alertas
# ---------------------------------------------------------------------------

def fetch_new_alerts(since: str | None, size: int = 50) -> list[dict]:
    """Busca alertas novos no índice wazuh-alerts-*, ordenados por timestamp asc."""
    query: dict = {
        "size": size,
        "sort": [{"@timestamp": "asc"}],
        "query": {"match_all": {}},
    }
    if since:
        query["query"] = {"range": {"@timestamp": {"gt": since}}}

    resp = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def summarize_alert(alert: dict) -> dict:
    """Extrai os campos relevantes de um alerta para uso nos prompts.

    Os campos de eventdata variam conforme o Event ID do Sysmon (ex: EID 1 =
    criação de processo traz commandLine/parentImage; EID 11 = criação de
    arquivo traz targetFilename; EID 3 = conexão de rede traz destinationIp).
    Por isso capturamos um conjunto amplo de campos e deixamos ausentes como
    None -- o prompt é instruído a lidar com campos ausentes sem assumir
    que "campo vazio = falso positivo".
    """
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})
    system = alert.get("data", {}).get("win", {}).get("system", {})

    return {
        "timestamp": alert.get("@timestamp"),
        "agent": alert.get("agent", {}).get("name"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_firedtimes": rule.get("firedtimes"),
        "mitre_id": mitre.get("id", []),
        "mitre_technique": mitre.get("technique", []),
        "mitre_tactic": mitre.get("tactic", []),
        "sysmon_event_id": system.get("eventID"),
        "process_image": eventdata.get("image"),
        "parent_image": eventdata.get("parentImage"),
        "command_line": eventdata.get("commandLine"),
        "parent_command_line": eventdata.get("parentCommandLine"),
        "target_filename": eventdata.get("targetFilename"),
        "integrity_level": eventdata.get("integrityLevel"),
        "hashes": eventdata.get("hashes"),
        "destination_ip": eventdata.get("destinationIp"),
        "destination_port": eventdata.get("destinationPort"),
        "user": eventdata.get("user"),
    }


# ---------------------------------------------------------------------------
# Camada 1 — Triagem rápida (Haiku)
# ---------------------------------------------------------------------------

def triage_with_haiku(summary: dict) -> dict:
    """Pergunta ao Haiku se o alerta parece um falso positivo ou merece
    investigação aprofundada. Retorna {"escalate": bool, "reason": str}."""

    prompt = f"""Você é um analista SOC N1 fazendo triagem rápida de um alerta de segurança.

Alerta:
{json.dumps(summary, indent=2, ensure_ascii=False)}

Responda SOMENTE em JSON, sem markdown, no formato:
{{"escalate": true/false, "reason": "justificativa curta em 1 frase"}}

escalate=true se houver indício real de atividade maliciosa que mereça
investigação de um analista N2. escalate=false se parecer falso positivo,
atividade administrativa legítima, ou ruído."""

    response = client.messages.create(
        model=HAIKU_MODEL,
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    text = text.replace("```json", "").replace("```", "").strip()
    usage = {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens}
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        result = {"escalate": True, "reason": "Falha ao parsear resposta do Haiku; escalando por segurança."}
    result["_usage"] = usage
    return result


# ---------------------------------------------------------------------------
# Camada 2 — Investigação profunda (Sonnet)
# ---------------------------------------------------------------------------

def investigate_with_sonnet(summary: dict, triage_reason: str) -> dict:
    """Pede ao Sonnet uma investigação completa, com veredito e recomendação."""

    prompt = f"""Você é um analista SOC N2/N3 investigando um alerta de segurança escalado.

Alerta:
{json.dumps(summary, indent=2, ensure_ascii=False)}

Motivo da escalação: {triage_reason}

Diretrizes para a investigação:
- rule_level é a severidade atribuída pelo próprio Wazuh (0-15). Um level
  alto (>=12) já é um forte indício de comportamento anômalo -- não rebaixe
  o veredito para falso_positivo apenas por reconhecer um nome de arquivo,
  processo ou padrão que "parece" familiar. Padrões conhecidos também são
  abusados por atacantes (ex: nomes de arquivo mimetizando artefatos
  legítimos do Windows/PowerShell é uma técnica real de evasão).
  Só classifique como falso_positivo se houver evidência concreta nos
  campos técnicos (ex: processo pai esperado, integrity_level condizente,
  ausência de indicadores de MITRE relevantes) -- não por familiaridade
  superficial do nome.
- Campos ausentes (None) significam que aquele Event ID do Sysmon não
  captura esse dado -- NÃO interprete campo ausente como "sem evidência
  suficiente". Baseie-se no que os campos presentes de fato mostram.
- Dê peso maior para a combinação rule_level + mitre_tactic do que para
  a plausibilidade aparente do nome do arquivo/processo isoladamente.
- O uso de flags de ofuscação/evasão (ex: "-EncodedCommand", "-enc",
  "-ExecutionPolicy Bypass", "-WindowStyle Hidden", comandos em Base64)
  já é, por si só, um forte indicador de técnica de evasão (MITRE T1027 /
  T1140), MESMO que o conteúdo decodificado pareça benigno ou que a ação
  final tenha sido bloqueada por antivírus/EDR. O uso dessas flags nunca
  deve reduzir sozinho a confiança do veredito para falso_positivo -- na
  melhor das hipóteses (payload decodificado inofensivo, ação bloqueada)
  o veredito deve ser "suspeito", nunca "falso_positivo", pois o
  comportamento de ofuscação em si já caracteriza tentativa de evasão.
- Considere a cadeia de processo (process_image / parent_image /
  command_line / parent_command_line) quando disponível para avaliar se a
  execução é consistente com uso administrativo ou com uma técnica de
  ataque.

Responda SOMENTE em JSON, sem markdown, no formato:
{{
  "veredito": "malicioso" | "suspeito" | "falso_positivo",
  "confianca": "alta" | "media" | "baixa",
  "resumo": "resumo da investigação em até 3 frases",
  "recomendacao": "ação recomendada para o analista humano"
}}"""

    response = client.messages.create(
        model=SONNET_MODEL,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    text = text.replace("```json", "").replace("```", "").strip()
    usage = {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens}
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        result = {
            "veredito": "suspeito",
            "confianca": "baixa",
            "resumo": "Falha ao parsear resposta do Sonnet.",
            "recomendacao": "Revisar manualmente.",
        }
    result["_usage"] = usage
    return result


# ---------------------------------------------------------------------------
# Persistência dos resultados
# ---------------------------------------------------------------------------

def append_result(record: dict) -> None:
    results = []
    if OUTPUT_FILE.exists():
        results = json.loads(OUTPUT_FILE.read_text())
    results.append(record)
    OUTPUT_FILE.write_text(json.dumps(results, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Notificações (Slack / Discord)
# ---------------------------------------------------------------------------

def should_notify(investigation: dict) -> bool:
    veredito = investigation.get("veredito")
    confianca = investigation.get("confianca")
    return veredito in NOTIFY_VEREDITOS and confianca == NOTIFY_MIN_CONFIANCA


def build_notification_text(summary: dict, investigation: dict) -> str:
    return (
        f"🔴 ALERTA CRÍTICO — AI SOC Analyst\n\n"
        f"Host: {summary.get('agent')}\n"
        f"Regra: {summary.get('rule_description')} (level {summary.get('rule_level')})\n"
        f"MITRE: {', '.join(summary.get('mitre_technique') or []) or '-'}\n"
        f"Veredito: {investigation.get('veredito')} (confiança: {investigation.get('confianca')})\n\n"
        f"Resumo: {investigation.get('resumo', '-')}\n\n"
        f"Recomendação: {investigation.get('recomendacao', '-')}"
    )


def notify_slack(text: str) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
    except requests.RequestException as exc:
        print(f"    -> falha ao notificar Slack: {exc}")


def notify_discord(text: str) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": text}, timeout=10)
    except requests.RequestException as exc:
        print(f"    -> falha ao notificar Discord: {exc}")


def notify(summary: dict, investigation: dict) -> None:
    if not should_notify(investigation):
        return
    if not SLACK_WEBHOOK_URL and not DISCORD_WEBHOOK_URL:
        return
    text = build_notification_text(summary, investigation)
    notify_slack(text)
    notify_discord(text)
    print("    -> 🔔 notificação enviada")


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

def process_alert(alert: dict, state: dict) -> None:
    summary = summarize_alert(alert)
    level = summary["rule_level"] or 0

    ts = summary["timestamp"]
    desc = summary["rule_description"]

    if level <= LEVEL_IGNORE_MAX:
        print(f"[{ts}] level={level} IGNORADO — {desc}")
        return

    key = dedup_key(summary)
    duplicate = check_duplicate(state, key, ts)
    if duplicate:
        cached = duplicate["result"]
        print(f"[{ts}] level={level} DUPLICADO (dentro de {DEDUP_WINDOW_MINUTES}min) — {desc}")
        print(f"    -> reaproveitando veredito de {duplicate['timestamp']}: "
              f"{cached.get('veredito', cached.get('reason'))}")
        append_result({
            "timestamp": ts, "alert": summary, "stage": "deduplicated",
            "cached_from": duplicate["timestamp"], "cached_result": cached,
        })
        return

    if level <= LEVEL_TRIAGE_MAX:
        print(f"[{ts}] level={level} TRIAGEM (Haiku) — {desc}")
        triage = triage_with_haiku(summary)
        if not triage.get("escalate"):
            print(f"    -> benigno: {triage.get('reason')}")
            append_result({
                "timestamp": ts, "alert": summary, "stage": "haiku_only",
                "triage": triage,
            })
            update_dedup_cache(state, key, ts, triage)
            return
        print(f"    -> escalado: {triage.get('reason')}")
        reason = triage.get("reason", "")
        triage_usage = triage.get("_usage", {})
    else:
        print(f"[{ts}] level={level} ESCALADO DIRETO (Sonnet) — {desc}")
        reason = "Nível de severidade >= 9 (escalação automática)."
        triage_usage = {}

    investigation = investigate_with_sonnet(summary, reason)
    print(f"    -> veredito: {investigation.get('veredito')} "
          f"(confiança: {investigation.get('confianca')})")
    print(f"    -> recomendação: {investigation.get('recomendacao')}")

    append_result({
        "timestamp": ts, "alert": summary, "stage": "sonnet_investigation",
        "triage_reason": reason, "investigation": investigation,
        "_triage_usage": triage_usage,
    })
    update_dedup_cache(state, key, ts, investigation)
    notify(summary, investigation)


def run_once(state: dict) -> dict:
    alerts = fetch_new_alerts(state.get("last_timestamp"))
    if not alerts:
        print(f"[{datetime.now(timezone.utc).isoformat()}] Nenhum alerta novo.")
        return state

    print(f"[{datetime.now(timezone.utc).isoformat()}] {len(alerts)} alerta(s) novo(s) encontrado(s).")
    for alert in alerts:
        process_alert(alert, state)
        state["last_timestamp"] = alert.get("@timestamp")
        save_state(state)

    return state


def main() -> None:
    parser = argparse.ArgumentParser(description="AI SOC Analyst Assistant")
    parser.add_argument("--once", action="store_true", help="Roda uma única vez e encerra")
    parser.add_argument("--interval", type=int, default=60, help="Intervalo de polling em segundos")
    args = parser.parse_args()

    if not ANTHROPIC_API_KEY:
        raise SystemExit("ERRO: defina a variável de ambiente ANTHROPIC_API_KEY antes de rodar.")
    if not WAZUH_INDEXER_PASS:
        raise SystemExit("ERRO: defina a variável de ambiente WAZUH_INDEXER_PASS antes de rodar.")
    if not SLACK_WEBHOOK_URL and not DISCORD_WEBHOOK_URL:
        print("AVISO: nenhum webhook de notificação configurado "
              "(SLACK_WEBHOOK_URL / DISCORD_WEBHOOK_URL). Seguindo sem notificações.")

    state = load_state()

    if args.once:
        run_once(state)
        return

    print(f"Iniciando polling contínuo (intervalo: {args.interval}s). Ctrl+C para parar.")
    try:
        while True:
            state = run_once(state)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nEncerrado pelo usuário.")


if __name__ == "__main__":
    main()
