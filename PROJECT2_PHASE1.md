# Project 2 — AI SOC Analyst Assistant

## Fase 1: Triagem e Investigação Automatizada com Roteamento de Modelos — CONCLUÍDA

### Objetivo

Construir um pipeline que consome alertas de segurança do Wazuh Indexer e
aplica um roteamento em duas camadas de modelos Claude para automatizar a
triagem inicial (N1) e a investigação aprofundada (N2/N3) de um SOC.

### Arquitetura

```
Wazuh Indexer (porta 9200)
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
```

Justificativa do threshold: em uma amostra de 1290 alertas reais do
ambiente de lab, ~85% tinham `rule.level <= 8` (majoritariamente ruído
administrativo — login, sudo, criação de serviço legítima). Rotear esse
volume para um LLM seria desperdício de custo; o roteamento por
severidade concentra o gasto de tokens onde há maior probabilidade de
sinal real.

### Stack técnica

- **Fonte de dados:** Wazuh Indexer (OpenSearch-compatible REST API)
- **Modelos:** `claude-haiku-4-5` (triagem) e `claude-sonnet-4-6` (investigação)
- **Linguagem:** Python 3.14, biblioteca `anthropic` oficial
- **Persistência:** checkpoint local (`state.json`) para evitar
  reprocessamento; log estruturado de auditoria (`investigations.json`)

### Schema de alerta mapeado

Cada alerta do Wazuh expõe, entre outros campos:

```
rule.level                          → severidade (0-15)
rule.description                    → descrição da regra disparada
rule.mitre.id / technique / tactic  → mapeamento MITRE ATT&CK nativo
agent.name                          → host afetado
data.win.eventdata.image            → processo que executou a ação
data.win.eventdata.parentImage      → processo pai
data.win.eventdata.commandLine      → linha de comando completa
data.win.eventdata.targetFilename   → arquivo criado/modificado
data.win.eventdata.integrityLevel   → nível de integridade do processo
data.win.eventdata.hashes           → hashes do binário (MD5/SHA256/IMPHASH)
```

O fato de o Wazuh já entregar o mapeamento MITRE pronto eliminou boa
parte do trabalho de prompt engineering — o desafio real não foi
"ensinar" o modelo sobre táticas de ataque, e sim calibrar o *julgamento*
de severidade.

### Iteração de prompt: de falso positivo a veredito correto

A primeira versão do prompt de investigação (Sonnet) cometia um erro de
calibração relevante: alertas críticos reais eram classificados como
`falso_positivo` com base na familiaridade superficial de nomes de
arquivo/padrões (ex: reconhecer `__PSScriptPolicyTest_*.ps1` como um
artefato comum do PowerShell e presumir benignidade, mesmo em um alerta
de `rule.level = 15`).

**Ajustes aplicados ao prompt do Sonnet:**

1. Instrução explícita para não rebaixar o veredito com base em
   familiaridade de nome/padrão sem evidência concreta na cadeia de
   processo.
2. Instrução para tratar campos ausentes (`None`) como "esse Event ID
   não captura esse dado", em vez de "evidência insuficiente".
3. Instrução para dar peso maior à combinação `rule.level` + MITRE
   tactic do que à plausibilidade aparente isolada.
4. Instrução explícita: flags de ofuscação (`-EncodedCommand`, `-enc`,
   `-ExecutionPolicy Bypass`, Base64) são, por si só, indicador de evasão
   (MITRE T1027/T1140) — o piso do veredito nesses casos passa a ser
   `suspeito`, nunca `falso_positivo`, independentemente do conteúdo
   decodificado ou do resultado final do ataque.

### Resultado — antes e depois

| Alerta (rule.level) | Descrição | Veredito ANTES | Veredito DEPOIS |
|---|---|---|---|
| 15 | Executable dropped em pasta usada por malware | `falso_positivo` (confiança média) | `suspeito` (confiança média) — recomenda hash + VirusTotal/sandbox |
| 12 | FodHelper.EXE usado para bypass de UAC | `falso_positivo` (confiança média) | **`malicioso` (confiança alta)** — recomenda isolamento imediato do endpoint, análise de registro `HKCU\Software\Classes\ms-settings`, runbook de Privilege Escalation |
| 12 | PowerShell spawnou processo que executou comando Base64 (`-EncodedCommand`) | `falso_positivo` (confiança média) | **`suspeito` (confiança alta)** — recomenda isolamento preventivo, coleta de logs PowerShell ScriptBlock/Module Logging (Event ID 4103/4104), investigação de vetor de origem (phishing, lateral movement) |
| 9 | PowerShell criou script na pasta Temp | `falso_positivo` (confiança alta) | `suspeito` (confiança média) — recomenda correlação com Sysmon Event ID 1/4688 |

O alerta de `rule.level = 12` — que corresponde ao ataque de Privilege
Escalation via bypass de UAC documentado no Project 1 (MITRE T1548.002)
— passou a ser corretamente identificado como `malicioso` com confiança
alta, incluindo uma recomendação de resposta a incidente tecnicamente
consistente com o procedimento real esperado de um analista N2/N3.

O segundo alerta de `rule.level = 12` (PowerShell abuse via
`-EncodedCommand`, MITRE T1027/T1140) validou especificamente a
instrução de "flag de ofuscação é red flag por si só": o veredito
`suspeito (confiança alta)` explicitou que o uso de `-EncodedCommand`
"pode ser um teste de capacidade de evasão ou o estágio inicial de um
ataque em múltiplas fases", sem relativizar a severidade com base no
conteúdo do payload decodificado -- exatamente o comportamento
desejado.

### Exemplo de saída (veredito malicioso)

```json
{
  "alert": {
    "rule_level": 12,
    "rule_description": "Known auto-elevated utility FodHelper.EXE may have been used to bypass UAC",
    "mitre_id": ["T1548.002"],
    "mitre_tactic": ["Privilege Escalation", "Defense Evasion"]
  },
  "investigation": {
    "veredito": "malicioso",
    "confianca": "alta",
    "recomendacao": "Isolar imediatamente o endpoint da rede para contenção. Coletar e preservar a memória RAM e logs do sistema (Sysmon, Security, PowerShell) antes de qualquer remediação. Investigar chaves de registro HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command. Rastrear processos filhos do fodhelper.exe. Acionar o runbook de resposta a incidente de Privilege Escalation e abrir investigação forense completa."
  }
}
```

### Aprendizado registrado

Modelos de linguagem, mesmo com contexto técnico completo, podem
subestimar severidade quando reconhecem padrões superficialmente
familiares. Prompt engineering para SOC não é apenas "dar mais dados" —
é também **restringir explicitamente os atalhos de raciocínio** que
levam a subestimar risco. Esse ajuste foi validado empiricamente contra
os 3 cenários de ataque reais documentados no Project 1 (Mini SOC Lab).

### Incidente de infraestrutura: instabilidade por RAM insuficiente

Durante os testes desta fase, a VM Wazuh-Manager travou (hard freeze,
sem OOM killer, sem log de kernel panic gravado) em duas ocasiões
distintas. Diagnóstico via `free -h` revelou apenas 97MB de RAM
disponível em uma VM com 2.6GB total, rodando simultaneamente
Wazuh Manager + Indexer (JVM, ~1GB) + Dashboard (Node.js) + overhead do
sistema. A ausência de rastro no `journalctl` (boot anterior) confirma
que o travamento foi anterior à capacidade do kernel de sequer registrar
o evento -- sintoma consistente com thrashing severo de memória.

**Correção aplicada:** RAM da VM elevada de 2.6GB para 4.6GB via
VirtualBox (host: Dell OptiPlex 7070, 12GB RAM total), preservando
margem para o sistema host. Memória disponível pós-ajuste subiu para
~2.3GB, eliminando a condição de pressão crítica.

### Teste de validação end-to-end ao vivo

Após reconectar o agente Windows10-Vitima (offline desde 2026-07-06) e
resolver um problema recorrente de rede (interface host-only `enp0s8`
não sobe automaticamente após reboot da VM -- mitigado com o script
`~/subir_wazuh.sh`), foi executado um teste de geração de evento real:

```powershell
$cmd = 'Write-Host "Teste de deteccao ao vivo - AI SOC Analyst"; Get-Date'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

O evento percorreu o pipeline completo em produção -- Sysmon (host
Windows) → Wazuh Agent → Wazuh Manager → Wazuh Indexer →
`ai_soc_analyst.py` (rodando em modo `--interval 2`) → Claude Sonnet --
sem qualquer intervenção manual, confirmando que a arquitetura funciona
de ponta a ponta em tempo real, não apenas em reprocessamento de dados
históricos.

![Terminal com detecção em tempo real e execução do comando codificado no host Windows](screenshots/terminal-deteccao-tempo-real.png)

**Resultado:**

```
rule_id: 92057 | level: 12 | MITRE: T1059.001 (PowerShell)
Veredito: suspeito (confiança: alta)
```

O Sonnet manteve o veredito em `suspeito` mesmo após decodificar o
payload Base64 e constatar que o conteúdo era inofensivo (`Write-Host
"Teste..."`), justificando explicitamente que o uso da flag
`-EncodedCommand` já caracteriza uma técnica de evasão (T1059.001/T1027)
independentemente do conteúdo -- validando em produção o ajuste de
prompt aplicado anteriormente. O modelo também levantou, sem ser
solicitado, a hipótese de que o evento poderia ser um teste de
red/purple team documentado -- hipótese correta.

![Saída JSON da investigação do Sonnet: resumo e recomendação](screenshots/investigacao-json-sonnet.png)

O mesmo teste, executado uma segunda vez ~12 minutos depois (mesmo
`rule_id` + mesmo `agent.name`, dentro da janela de deduplicação de 30
min), foi corretamente identificado como duplicata e reaproveitou o
veredito em cache, sem nova chamada de API -- validando a lógica de
deduplicação em cenário real, além do teste unitário isolado.

### Notificações validadas

Webhook do Discord configurado e testado com sucesso (mensagem de teste
recebida no canal em <1s). A partir deste ponto, qualquer veredito
`malicioso` com confiança `alta` dispara notificação automática.

## Fase 3 (parcial): Ataque real via Kali e descoberta de gap de visibilidade

### Cenário de ataque

Reverse shell via Metasploit contra o host Windows10-Vitima, simulando
um cenário de Command & Control real:

1. Payload gerado com `msfvenom` (`windows/x64/meterpreter/reverse_tcp`)
2. Handler configurado no Metasploit (`exploit/multi/handler`)
3. Payload servido via HTTP simples (`python3 -m http.server`) e
   baixado no host Windows via `Invoke-WebRequest`

**Pré-requisito de infraestrutura identificado:** a VM Kali nunca teve
um adaptador de rede host-only configurado (só possuía NAT), portanto
não enxergava a rede `192.168.56.0/24` onde os demais hosts do lab
residem. Adaptador 2 (Host-only) foi adicionado nas configurações de
rede da VM.

### Resultado: bloqueio pelo Windows Defender

O Microsoft Defender Antivírus interceptou e colocou em quarentena o
payload antes mesmo da execução, via Proteção em Tempo Real:

```
Ameaça: Trojan:Win32/Zusy.NCD!MTB
Severidade: Grave
Ação: Colocar em Quarentena
Processo: powershell.exe (via Invoke-WebRequest)
```

![Windows Defender bloqueando o payload gerado pelo msfvenom](screenshots/windows-defender-ameaca-detectada.png)

### Gap de visibilidade descoberto no Wazuh

A detecção do Defender inicialmente **não gerou nenhum alerta visível**
no Wazuh, apesar do agente estar ativo e íntegro. Investigação revelou
duas causas em camadas distintas:

**Causa 1 -- canal de log ausente:** o `ossec.conf` do agente Windows
não coletava o canal `Microsoft-Windows-Windows Defender/Operational`
(só monitorava Sysmon, Security, System e Application). Corrigido
adicionando o `<localfile>` correspondente.

**Causa 2 (mais relevante) -- ruleset padrão insuficiente:** mesmo após
o canal passar a ser coletado, o ruleset padrão do Wazuh
(`0600-win-wdefender_rules.xml`) classifica eventos do Defender **apenas
pela severidade genérica do log** (`INFORMATION`/`WARNING`/`ERROR`), não
pelo tipo específico de evento. Detecções reais de malware (Event ID
1116/1117) chegam com `severityValue = INFORMATION`, o que as classifica
na regra `62100` como **level 0** -- e alertas de level 0 não são
persistidos como alertas visíveis pelo Wazuh por padrão. **Na prática,
isso significa que o ruleset padrão do Wazuh suprime silenciosamente
detecções reais de malware do Windows Defender**, a menos que o ambiente
tenha uma regra customizada para tratá-las com a severidade adequada.
Isso foi confirmado observando que até mesmo a regra específica de
Event ID 1117 do próprio Wazuh (`62124`) é gerada em nível baixo
(level 3) e sua descrição embutida (`$(win.eventdata.processName)`)
vem vazia -- evidência de que o próprio ruleset oficial tem uma
referência de campo incorreta (o campo decodificado real é
`processName` com um espaço antes do "Name", não casando com a
referência sem espaço usada na descrição).

### Tentativa de correção: regra customizada

Foi escrita uma regra local (`local_rules.xml`, ID `100100`, level 12)
encadeada via `<if_sid>62124</if_sid>`, testando a presença do campo
`win.eventdata.threat Name` para elevar a severidade de detecções reais
de malware. A regra foi confirmada como **corretamente carregada e
habilitada** pela API do Wazuh (`GET /rules?rule_ids=100100`), com a
condição de campo e MITRE ATT&CK (T1204.002, T1027) configurados
corretamente -- porém **não disparou em produção**, mesmo com o campo
comprovadamente presente no JSON decodificado (`win.eventdata.threat
Name` confirmado via `archives.json`). Tentativas de ajuste do nome do
campo (com espaço, com underscore) não resolveram. A causa raiz exata
não foi identificada dentro do tempo desta sessão -- suspeita-se de uma
particularidade de como o `analysisd` indexa internamente chaves JSON
com caracteres especiais para fins de correspondência de regras, algo
não documentado claramente na documentação pública do Wazuh.

### Valor do achado, independente da resolução

Mesmo sem a regra customizada funcionando, o processo de investigação
em si é o resultado central: **identificar que um SIEM confiável, com
configuração majoritariamente padrão, pode estar suprimindo alertas
reais de antivírus por classificação incorreta de severidade** é
exatamente o tipo de gap que um analista de detection engineering deve
saber caçar -- e documentá-lo com evidências concretas (JSON bruto,
regras do ruleset, testes de API) tem valor equivalente ou maior do que
uma correção "silenciosa" sem essa investigação.

### Próximos passos para retomar

- Investigar se o problema está na indexação de chaves JSON com espaço
  pelo `analysisd` (possivelmente abrir uma consulta na comunidade/
  documentação oficial do Wazuh)
- Alternativa mais simples a testar: reescrever a regra usando
  `<field name="win.eventdata.threat_ID">` (campo numérico, sem espaço
  no nome original) como gatilho em vez de `threat Name`
- Alternativa via Integrator/script de resposta ativa, processando o
  full_log diretamente em Python fora do mecanismo de regras do Wazuh

## Avaliação de custo de tokens em escala

Com base em 1015 alertas processados ao longo do desenvolvimento
(mistura de replay histórico + eventos ao vivo), foram calculados os
custos médios reais por chamada de API:

| Modelo | Custo médio por chamada |
|---|---|
| Haiku 4.5 (triagem) | US$ 0,000017 |
| Sonnet 5 (investigação) | US$ 0,001444 |

**Distribuição de severidade** (baseada na amostra real de 1290 alertas
do Project 1): 68,1% ignorados (level ≤6, sem custo), 28,8% triados pelo
Haiku (level 7-8), 3,2% escalados direto ao Sonnet (level ≥9).

**Taxa de deduplicação observada nesta sessão:** 51,3% dos alertas
relevantes (level ≥7) eram repetições do mesmo `rule_id`+`agent` dentro
da janela de 30 min -- ou seja, a deduplicação **cortou o custo de
operação pela metade** no cenário real observado.

### Projeção de custo por volume de alertas

| Alertas/dia (brutos) | Custo/dia sem dedup | Custo/dia com dedup | Custo/mês com dedup |
|---|---|---|---|
| 100 | US$ 0,01 | US$ 0,00 | US$ 0,07 |
| 1.000 | US$ 0,05 | US$ 0,02 | US$ 0,74 |
| 10.000 | US$ 0,51 | US$ 0,25 | US$ 7,41 |
| 50.000 | US$ 2,54 | US$ 1,24 | US$ 37,06 |

**Conclusão:** mesmo um SOC de porte médio-grande processando 10 mil
alertas brutos por dia (volume tipicamente associado a ambientes
corporativos com centenas de endpoints) teria um custo mensal de IA
inferior a US$ 10 -- uma fração irrisória comparada ao custo de um
analista humano em tempo integral. Isso demonstra viabilidade econômica
real para IA aplicada a triagem de SOC: o roteamento por severidade
(evitar chamar LLM para os ~68% de eventos de baixa severidade) e a
deduplicação (evitar reinvestigar o mesmo padrão repetido) são,
juntos, responsáveis pela maior parte dessa eficiência de custo --
mais do que a escolha específica de modelo.
