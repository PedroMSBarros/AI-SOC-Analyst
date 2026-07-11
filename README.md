# AI SOC Analyst Assistant

Assistente de triagem e investigação de alertas de segurança que consome
alertas em tempo real do Wazuh (SIEM open-source) e usa um roteamento em
duas camadas de modelos Claude — **Haiku 4.5** para triagem rápida e
**Sonnet 5** para investigação profunda — para automatizar boa parte do
trabalho de um analista SOC N1/N2.

Construído como parte do meu portfólio de cibersegurança, sobre a
infraestrutura do [Mini SOC Lab](https://github.com/PedroMSBarros/Mini-Soc-Lab)
(Project 1).

## Destaques

- **Roteamento por severidade**: ~68% dos alertas (ruído estatístico,
  level ≤6) nunca chegam a chamar um LLM — economia de custo desde a
  origem
- **Deduplicação**: alertas repetidos do mesmo tipo/host dentro de uma
  janela de 30 min reaproveitam o veredito anterior — reduziu o custo de
  operação **pela metade** em uso real
- **Custo real em escala**: um SOC processando 10.000 alertas brutos/dia
  custaria **menos de US$ 10/mês** em tokens de IA (ver
  [análise completa](PROJECT2_PHASE1.md#avaliação-de-custo-de-tokens-em-escala))
- **Validado contra ataques reais**: prompt calibrado e testado contra os
  3 cenários de ataque documentados no Project 1, mais um teste de
  Reverse Shell ao vivo via Metasploit que revelou um gap real de
  visibilidade no ruleset padrão do Wazuh (documentado em detalhe)
- **Dashboard com custo real**: métricas, veredictos e uso de tokens
  calculados a partir do `response.usage` de cada chamada de API — não é
  estimativa

## Arquitetura

```
Wazuh Indexer (9200)
        │
        ▼
   rule.level <= 6  ───────────────────────► Ignorado (ruído estatístico)
        │
   rule.level 7-8 ──► Claude Haiku 4.5 (triagem rápida)
        │                     │
        │              escalate=false ─────► Registrado como benigno
        │                     │
        │              escalate=true
        │                     ▼
   rule.level >= 9 ──► Claude Sonnet 5 (investigação profunda)
                               │
                               ▼
                Veredito + confiança + recomendação
                               │
                               ▼
                  malicioso + confiança alta?
                               │
                               ▼
                   🔔 Notificação (Slack/Discord)
```

Alertas com o mesmo `rule_id` + `agent.name` dentro de 30 minutos
reaproveitam o veredito em cache em vez de reinvestigar (deduplicação).

## Stack técnica

- **Python 3** + SDK oficial `anthropic`
- **Wazuh Indexer** (API REST estilo OpenSearch) como fonte de alertas
- **Streamlit** para o dashboard
- **Modelos:** `claude-haiku-4-5` (triagem) e `claude-sonnet-4-6` (investigação)

## Setup

```bash
pip install -r requirements.txt --break-system-packages

export ANTHROPIC_API_KEY="sua-api-key-aqui"
export WAZUH_INDEXER_URL="https://localhost:9200"   # padrão, pode omitir
export WAZUH_INDEXER_USER="admin"                    # padrão, pode omitir
export WAZUH_INDEXER_PASS="sua-senha-do-indexer"

# Opcional: notificações para veredictos "malicioso" com confiança "alta"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

> ⚠️ Por simplicidade, as credenciais ficam em variáveis de ambiente
> locais. Em um ambiente de produção, o recomendado seria um cofre de
> segredos (AWS Secrets Manager, HashiCorp Vault) com rotação automática.

## Uso

```bash
# Loop contínuo (polling a cada 60s por padrão)
python3 ai_soc_analyst.py

# Execução única (útil para testes/demo)
python3 ai_soc_analyst.py --once

# Intervalo customizado
python3 ai_soc_analyst.py --interval 30
```

## Dashboard

```bash
streamlit run dashboard.py --server.port 8501
```

Métricas gerais (volume, custo real, distribuição de veredictos) e
tabela filtrável por veredito/estágio/agente.

## Arquivos gerados

- `state.json` — checkpoint do último alerta processado + cache de
  deduplicação
- `investigations.json` — histórico completo de triagens e
  investigações, incluindo uso real de tokens por chamada

## Documentação técnica completa

Para o processo detalhado de desenvolvimento — incluindo a calibração
do prompt do Sonnet (de falsos-positivos incorretos até veredictos
corretos e validados), a resolução de incidentes de infraestrutura
(RAM, rede), o teste de ataque real via Kali/Metasploit e a descoberta
do gap de visibilidade no ruleset do Wazuh — veja
[PROJECT2_PHASE1.md](PROJECT2_PHASE1.md).
