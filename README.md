# 🕵️ Assistente de Threat Intelligence (OSINT) com IA

Sistema de **IA + Automação** que resolve um problema comum em resposta a incidentes: **consolidar rapidamente a reputação de um IOC (IP, domínio ou hash) espalhada por múltiplas fontes OSINT**, sem precisar checar manualmente VirusTotal, AbuseIPDB e Shodan um por um.

O pipeline consulta cada fonte, consolida os sinais brutos e usa IA para emitir um **veredito de risco único, com justificativa e recomendação de ação** — reduzindo o tempo de triagem de um IOC de minutos para segundos.

## 🧩 Problema que resolve

- Durante um incidente, cada IOC precisa ser checado em várias plataformas diferentes.
- Cada fonte fala uma "língua" diferente (score de abuso, nº de detecções, portas abertas) — falta uma camada que **traduza isso em uma decisão**.
- Analistas juniores muitas vezes não sabem ponderar corretamente esses sinais (ex: 1 report de abuso ≠ IP malicioso confirmado).

## ⚙️ Como funciona (Pipeline)

```
IOC (IP/domínio/hash) → Consulta VirusTotal + AbuseIPDB + Shodan → Consolidação → IA (Claude API) → Veredito + Relatório
```

1. **Coleta**: o script consulta as APIs públicas de VirusTotal, AbuseIPDB e Shodan (cada uma isolada em sua própria função, fácil de estender).
2. **Consolidação**: os dados brutos das três fontes são unificados em um único JSON.
3. **IA (Prompt Engineering)**: o `system_prompt.md` instrui a IA a atuar como Analista Sênior de Threat Intelligence, ponderando convergência de evidências entre fontes para emitir um veredito com nível de confiança.
4. **Relatório**: saída em Markdown com veredito, evidências por fonte, contexto da ameaça (se houver) e ação recomendada.

## 🎮 Modo Demonstração (sem precisar de 3 API keys)

Como VirusTotal, AbuseIPDB e Shodan exigem cadastro e chave própria, o projeto inclui um **modo demo** (`--demo`) com 4 cenários pré-carregados em `sample_data/osint_demo_data.json`, cobrindo diferentes níveis de risco:

| IOC | Cenário | Veredito esperado |
|---|---|---|
| `185.220.101.45` | Nó Tor com alto volume de abuso reportado | Malicioso |
| `45.148.10.203` | Poucas detecções, baixo score de abuso | Provavelmente Benigno / Suspeito leve |
| `freehost-cdn-update.net` | Domínio recém-registrado (6 dias) com detecções | Suspeito/Malicioso |
| `8.8.8.8` | DNS público do Google, zero detecções | Benigno |

Isso demonstra que o sistema **não gera apenas alarmes** — ele também sabe reconhecer infraestrutura legítima.

## 📂 Estrutura do projeto

```
threat-intel-osint-ai/
├── system_prompt.md              # Prompt de IA especializado (Prompt Engineering)
├── osint_analyzer.py             # Script de automação (pipeline completo + modo demo)
├── requirements.txt               # Dependências Python
├── sample_data/
│   └── osint_demo_data.json      # 4 cenários de exemplo (malicioso, suspeito, benigno)
└── README.md
```

## 🚀 Como executar

### Modo Demonstração (recomendado para avaliar o projeto)
```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sua-chave-aqui"

python osint_analyzer.py --ioc "185.220.101.45" --type ip --demo
python osint_analyzer.py --ioc "freehost-cdn-update.net" --type domain --demo
python osint_analyzer.py --ioc "8.8.8.8" --type ip --demo
```

### Modo Produção (com APIs reais)
```bash
export ANTHROPIC_API_KEY="sua-chave-aqui"
export VIRUSTOTAL_API_KEY="sua-chave-vt"
export ABUSEIPDB_API_KEY="sua-chave-abuseipdb"
export SHODAN_API_KEY="sua-chave-shodan"

python osint_analyzer.py --ioc "1.2.3.4" --type ip
```

O relatório final será salvo em `relatorio_threat_intel.md`.

## 🧠 Destaque técnico: o Prompt

O núcleo do sistema é o `system_prompt.md`, desenhado com boas práticas de **prompt engineering**:
- Persona clara (Analista Sênior de Threat Intelligence)
- Lógica explícita de ponderação de evidências (convergência entre múltiplas fontes aumenta confiança)
- Distinção clara entre "infraestrutura suspeita" e "malícia confirmada" (evita falsos positivos por excesso de zelo)
- Regras estritas contra atribuição infundada a grupos de ameaça (APTs) sem evidência
- Few-shot example calibrando o formato e o tom da análise

## 🔮 Possíveis evoluções

- Adicionar mais fontes: URLhaus, AlienVault OTX, GreyNoise, MISP.
- Cache local de consultas para evitar rate-limit das APIs gratuitas.
- Modo batch para analisar uma lista de IOCs extraída de um relatório de incidente.
- Exportação para formato STIX/TAXII para integração com plataformas de CTI.

## 🛠️ Stack

- **Python 3.11+**
- **Claude API (Anthropic)** — modelo `claude-sonnet-4-6`
- **APIs OSINT**: VirusTotal, AbuseIPDB, Shodan
- Prompt Engineering (Role Prompting, Few-shot, Weighted Evidence Reasoning, Structured Output)

---

> Projeto desenvolvido como parte de um portfólio de sistemas de IA aplicados a Cybersecurity, unindo automação, Threat Intelligence e engenharia de prompts.
