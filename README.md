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

![Tabela de detalhamento filtrável](screenshots/dashboard-tabela-detalhamento.png)

Notificação automática no Discord para veredictos `malicioso`/`alta` confiança:

![Notificação no Discord](screenshots/discord-notificacao.png)

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
