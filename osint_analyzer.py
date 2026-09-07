"""
Sistema: Assistente de Threat Intelligence (OSINT) com IA
Autor: [Seu Nome]
Descrição: Pipeline que consulta múltiplas APIs públicas de reputação (VirusTotal,
           AbuseIPDB, Shodan) para um IOC (IP, domínio ou hash), consolida os
           dados brutos e usa a API da Anthropic (Claude) para gerar um
           relatório de inteligência de ameaças com veredito e recomendações.

Fluxo: IOC -> Consulta às APIs OSINT -> Consolidação -> IA -> Relatório

NOTA: Este script inclui um MODO DEMO (--demo) que usa dados de exemplo
pré-carregados, para que o projeto possa ser demonstrado no portfólio sem
exigir chaves de API de todos os serviços (VirusTotal, AbuseIPDB e Shodan
exigem cadastro/API key própria).
"""

import json
import os
import argparse
import requests

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Coletores OSINT (cada função isola uma fonte — fácil de adicionar novas)
# ---------------------------------------------------------------------------

def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    """Consulta a API pública do VirusTotal para IPs, domínios ou hashes."""
    endpoint_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = endpoint_map.get(ioc_type)
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    stats = data["data"]["attributes"].get("last_analysis_stats", {})
    tags = data["data"]["attributes"].get("tags", [])
    return {
        "malicious_detections": stats.get("malicious", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "tags": tags,
    }


def query_abuseipdb(ip: str, api_key: str) -> dict:
    """Consulta a API do AbuseIPDB (apenas para IPs)."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()["data"]
    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "categories": data.get("reports", []),  # simplificado
    }


def query_shodan(ip: str, api_key: str) -> dict:
    """Consulta a API do Shodan (apenas para IPs)."""
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "open_ports": data.get("ports", []),
        "org": data.get("org", "Desconhecido"),
        "country": data.get("country_name", "Desconhecido"),
    }


def load_demo_data(ioc: str, demo_path: str) -> dict:
    """Carrega dados de exemplo pré-coletados (modo demonstração de portfólio)."""
    with open(demo_path, encoding="utf-8") as f:
        demo_db = json.load(f)
    if ioc not in demo_db:
        raise SystemExit(
            f"IOC '{ioc}' não encontrado nos dados de demonstração. "
            f"IOCs disponíveis: {list(demo_db.keys())}"
        )
    return demo_db[ioc]


# ---------------------------------------------------------------------------
# Camada de IA
# ---------------------------------------------------------------------------

def call_ai_threat_analysis(consolidated_data: dict, system_prompt: str, api_key: str) -> str:
    """Envia os dados consolidados de OSINT para a IA e retorna o relatório em Markdown."""
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 2500,
        "system": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Analise o seguinte IOC com base nos dados consolidados de múltiplas "
                    "fontes OSINT:\n\n" + json.dumps(consolidated_data, ensure_ascii=False, indent=2)
                ),
            }
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    response = requests.post(ANTHROPIC_API_URL, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    data = response.json()
    return "".join(block.get("text", "") for block in data.get("content", []))


def save_report(text: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Pipeline de Threat Intelligence (OSINT) com consolidação via IA."
    )
    parser.add_argument("--ioc", required=True, help="O IOC a ser analisado (IP, domínio ou hash)")
    parser.add_argument("--type", choices=["ip", "domain", "hash"], required=True, help="Tipo do IOC")
    parser.add_argument(
        "--demo", action="store_true",
        help="Usa dados de exemplo pré-carregados em vez de consultar APIs reais (não exige API keys de OSINT)"
    )
    parser.add_argument(
        "--demo-data", default="sample_data/osint_demo_data.json",
        help="Caminho do arquivo de dados de demonstração"
    )
    parser.add_argument(
        "--prompt", default="system_prompt.md", help="Caminho do arquivo com o system prompt"
    )
    parser.add_argument(
        "--output", default="relatorio_threat_intel.md", help="Caminho do relatório de saída"
    )
    args = parser.parse_args()

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if not anthropic_key:
        raise SystemExit(
            "Defina a variável de ambiente ANTHROPIC_API_KEY antes de executar.\n"
            "Ex.: export ANTHROPIC_API_KEY='sua-chave-aqui'"
        )

    # 1. Coleta os dados OSINT (modo demo ou APIs reais)
    if args.demo:
        print(f"[MODO DEMO] Carregando dados de exemplo para o IOC '{args.ioc}'...")
        consolidated = load_demo_data(args.ioc, args.demo_data)
    else:
        print(f"Consultando fontes OSINT reais para o IOC '{args.ioc}'...")
        consolidated = {"ioc": args.ioc, "type": args.type}

        vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if vt_key:
            consolidated["virustotal"] = query_virustotal(args.ioc, args.type, vt_key)

        if args.type == "ip":
            abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
            if abuse_key:
                consolidated["abuseipdb"] = query_abuseipdb(args.ioc, abuse_key)

            shodan_key = os.environ.get("SHODAN_API_KEY")
            if shodan_key:
                consolidated["shodan"] = query_shodan(args.ioc, shodan_key)

    # 2. Carrega o system prompt
    with open(args.prompt, encoding="utf-8") as f:
        system_prompt = f.read()

    # 3. Chama a IA para consolidar a análise
    print("Consolidando inteligência com a IA...")
    report = call_ai_threat_analysis(consolidated, system_prompt, anthropic_key)

    # 4. Salva o relatório
    save_report(report, args.output)
    print(f"Relatório gerado com sucesso: {args.output}")


if __name__ == "__main__":
    main()
