#!/usr/bin/env python3
"""
Dashboard do AI SOC Analyst Assistant
=======================================
Visualiza o histórico de triagens e investigações gravado em
investigations.json: métricas gerais (volume, custo estimado,
distribuição de veredictos) e uma tabela filtrável com o detalhe de
cada alerta processado.

Uso:
    streamlit run dashboard.py
"""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

DATA_FILE = Path(__file__).parent / "investigations.json"

# Preços aproximados por milhão de tokens (USD) -- ajustar conforme tabela
# oficial vigente em platform.claude.com caso mude.
PRICING = {
    "haiku": {"input": 1.00, "output": 5.00},
    "sonnet": {"input": 3.00, "output": 15.00},
}

st.set_page_config(page_title="AI SOC Analyst — Dashboard", layout="wide")


@st.cache_data(ttl=30)
def load_data() -> list[dict]:
    if not DATA_FILE.exists():
        return []
    return json.loads(DATA_FILE.read_text())


def estimate_cost(records: list[dict]) -> dict:
    """Soma o custo real em USD com base no uso de tokens registrado em
    cada chamada de API (campo _usage nos resultados de triagem/investigação)."""
    haiku_in = haiku_out = sonnet_in = sonnet_out = 0

    for r in records:
        stage = r.get("stage")
        if stage == "haiku_only":
            usage = r.get("triage", {}).get("_usage", {})
            haiku_in += usage.get("input_tokens", 0)
            haiku_out += usage.get("output_tokens", 0)
        elif stage == "sonnet_investigation":
            # triagem do Haiku pode ou não ter ocorrido antes da escalação
            triage_usage = r.get("_triage_usage", {})
            haiku_in += triage_usage.get("input_tokens", 0)
            haiku_out += triage_usage.get("output_tokens", 0)
            usage = r.get("investigation", {}).get("_usage", {})
            sonnet_in += usage.get("input_tokens", 0)
            sonnet_out += usage.get("output_tokens", 0)

    cost_haiku = (haiku_in / 1_000_000) * PRICING["haiku"]["input"] + \
                 (haiku_out / 1_000_000) * PRICING["haiku"]["output"]
    cost_sonnet = (sonnet_in / 1_000_000) * PRICING["sonnet"]["input"] + \
                  (sonnet_out / 1_000_000) * PRICING["sonnet"]["output"]

    return {
        "haiku_tokens": haiku_in + haiku_out,
        "sonnet_tokens": sonnet_in + sonnet_out,
        "cost_haiku": cost_haiku,
        "cost_sonnet": cost_sonnet,
        "cost_total": cost_haiku + cost_sonnet,
    }


def flatten_record(r: dict) -> dict:
    alert = r.get("alert", {})
    stage = r.get("stage")

    if stage == "sonnet_investigation":
        inv = r.get("investigation", {})
        veredito = inv.get("veredito", "-")
        confianca = inv.get("confianca", "-")
        resumo = inv.get("resumo", "-")
        recomendacao = inv.get("recomendacao", "-")
    elif stage == "deduplicated":
        cached = r.get("cached_result", {})
        veredito = cached.get("veredito", cached.get("reason", "-"))
        confianca = cached.get("confianca", "-")
        resumo = f"(reaproveitado de {r.get('cached_from', '-')})"
        recomendacao = "-"
    else:  # haiku_only
        triage = r.get("triage", {})
        veredito = "benigno" if not triage.get("escalate") else "-"
        confianca = "-"
        resumo = triage.get("reason", "-")
        recomendacao = "-"

    return {
        "timestamp": r.get("timestamp"),
        "agent": alert.get("agent"),
        "rule_level": alert.get("rule_level"),
        "rule_description": alert.get("rule_description"),
        "mitre_technique": ", ".join(alert.get("mitre_technique") or []),
        "stage": stage,
        "veredito": veredito,
        "confianca": confianca,
        "resumo": resumo,
        "recomendacao": recomendacao,
    }


def main() -> None:
    st.title("🛡️ AI SOC Analyst Assistant — Dashboard")
    st.caption("Triagem (Haiku) + Investigação (Sonnet) sobre alertas do Wazuh")

    records = load_data()

    if not records:
        st.warning(
            "Nenhum dado encontrado em investigations.json ainda. "
            "Rode `python3 ai_soc_analyst.py --once` primeiro."
        )
        return

    df = pd.DataFrame([flatten_record(r) for r in records])
    costs = estimate_cost(records)

    # -----------------------------------------------------------------
    # Métricas gerais
    # -----------------------------------------------------------------
    st.subheader("Visão geral")
    col1, col2, col3, col4, col5 = st.columns(5)

    total = len(df)
    n_malicioso = (df["veredito"] == "malicioso").sum()
    n_suspeito = (df["veredito"] == "suspeito").sum()
    n_falso_pos = (df["veredito"] == "falso_positivo").sum()
    n_dedup = (df["stage"] == "deduplicated").sum()

    col1.metric("Total processado", total)
    col2.metric("🔴 Malicioso", int(n_malicioso))
    col3.metric("🟡 Suspeito", int(n_suspeito))
    col4.metric("🟢 Falso positivo", int(n_falso_pos))
    col5.metric("♻️ Deduplicado", int(n_dedup))

    col1, col2, col3 = st.columns(3)
    col1.metric("Tokens Haiku", f"{costs['haiku_tokens']:,}")
    col2.metric("Tokens Sonnet", f"{costs['sonnet_tokens']:,}")
    col3.metric("Custo total estimado", f"US$ {costs['cost_total']:.4f}")

    st.divider()

    # -----------------------------------------------------------------
    # Distribuição por veredito e por agente
    # -----------------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Distribuição por veredito")
        veredito_counts = df[df["veredito"].isin(
            ["malicioso", "suspeito", "falso_positivo", "benigno"]
        )]["veredito"].value_counts()
        st.bar_chart(veredito_counts)

    with col2:
        st.subheader("Alertas por agente")
        agent_counts = df["agent"].value_counts()
        st.bar_chart(agent_counts)

    st.divider()

    # -----------------------------------------------------------------
    # Tabela filtrável
    # -----------------------------------------------------------------
    st.subheader("Detalhamento")

    col1, col2, col3 = st.columns(3)
    with col1:
        veredito_filter = st.multiselect(
            "Veredito", options=sorted(df["veredito"].dropna().unique()),
        )
    with col2:
        stage_filter = st.multiselect(
            "Estágio", options=sorted(df["stage"].dropna().unique()),
        )
    with col3:
        agent_filter = st.multiselect(
            "Agente", options=sorted(df["agent"].dropna().unique()),
        )

    filtered = df.copy()
    if veredito_filter:
        filtered = filtered[filtered["veredito"].isin(veredito_filter)]
    if stage_filter:
        filtered = filtered[filtered["stage"].isin(stage_filter)]
    if agent_filter:
        filtered = filtered[filtered["agent"].isin(agent_filter)]

    st.dataframe(
        filtered.sort_values("timestamp", ascending=False),
        use_container_width=True,
        column_config={
            "resumo": st.column_config.TextColumn(width="large"),
            "recomendacao": st.column_config.TextColumn(width="large"),
        },
    )


if __name__ == "__main__":
    main()
