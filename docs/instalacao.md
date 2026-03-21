# Instalação e Uso — Verificador de Hosts

## Pré-requisitos

- **Python 3.11+** (recomendado; mínimo 3.8)
- **pip** (gerenciador de pacotes do Python)
- **Sistema Linux** (recomendado — comandos `ping`, `arp`, `ip neigh` são usados internamente)
- Ferramentas de sistema: `ping`, `arp` ou `ip` (geralmente já instaladas)

### Verificar versão do Python

```bash
python --version
# ou
python3 --version
```

### Instalar Python (caso não tenha)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip -y
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip
```

---

## Instalação do projeto

### 1. Clone o repositório

```bash
git clone https://github.com/anxiousCamel/verificador_hosts
cd verificador_hosts
```

### 2. Crie um ambiente virtual (recomendado)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> Para desativar o ambiente virtual depois: `deactivate`

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

---

## Dependências Python

| Pacote | Versão mínima | Finalidade |
|---|---|---|
| `rich` | 13.7.0 | Interface colorida no terminal (tabelas, progresso, cores) |
| `tqdm` | 4.66.4 | Barra de progresso em loops longos |
| `requests` | 2.31.0 | Download dos arquivos NVD para atualização da base CVE |
| `orjson` | 3.9.15 | Leitura rápida de arquivos JSON grandes (base NVD) |
| `packaging` | 24.0 | Comparação de versões de software para análise de CVEs |

> Todas as dependências são instaladas automaticamente via `pip install -r requirements.txt`.

---

## Como usar

### Modo padrão (scanner de hosts)

```bash
python3 -m src
```

O programa irá:
1. Perguntar o modo de operação (`auto` / `leve` / `completo`)
2. Verificar e atualizar a base NVD local (CVEs) se necessário
3. Solicitar o range de IPs a varrer (ex: `192.168.1`, início `1`, fim `50`)
4. Executar o scan e exibir o relatório colorido no terminal
5. Oferecer exportação dos resultados em CSV

### Modo pentest (pipeline de 6 fases)

```bash
python3 -m src.cli.pentest_cli
```

Executa o pipeline completo de reconhecimento, enumeração e análise de vulnerabilidades.
Ao final, oferece exportação do relatório em JSON.

---

## Modos de operação

| Modo | Velocidade | Recursos |
|---|---|---|
| `leve` | Rápido | Sem resolução DNS, sem CVEs, apenas TCP |
| `completo` | Completo | DNS reverso, CVEs, TCP + ICMP |
| `auto` (padrão) | Adaptativo | Linux → completo, Windows → leve |

Para forçar um modo via variável de ambiente:

```bash
VH_MODE=completo python3 -m src
VH_MODE=leve python3 -m src
```

Para desativar a pergunta interativa de modo:

```bash
VH_ASK_MODE=0 python3 -m src
```

---

## Variáveis de ambiente opcionais

| Variável | Padrão | Descrição |
|---|---|---|
| `VH_MODE` | `auto` | Modo: `auto`, `leve`, `completo` |
| `VH_ASK_MODE` | `1` | `0` para não perguntar o modo |
| `VH_MAX_HOSTS_WORKERS` | 6–8 | Threads para scan de hosts (4–12) |
| `VH_MAX_PORTS_WORKERS` | 3–4 | Threads para scan de portas (2–6) |
| `VH_TIMEOUT_SOCKET` | 2.0–3.0 | Timeout de conexão em segundos (1.5–5.0) |
| `VH_BATCH_SIZE` | 8–10 | Tamanho do lote de IPs (6–16) |
| `VH_SKIP_CVE` | `0` | `1` para pular verificação de CVEs |
| `VH_SKIP_NVD_UPDATE` | `0` | `1` para pular atualização da base NVD |

---

## Estrutura do projeto

```
verificador_hosts/
├── src/
│   ├── __main__.py          # Entry point: python -m src
│   ├── cli/
│   │   ├── scanner_cli.py   # CLI do scanner simples
│   │   ├── pentest_cli.py   # CLI do pipeline de pentest
│   │   └── input_handler.py # Coleta de input do usuário
│   ├── core/
│   │   ├── batch_scanner.py # Varredura em lotes com cache e governança
│   │   ├── governor.py      # Governança adaptativa de recursos
│   │   └── pentest_pipeline.py # Pipeline de pentest (6 fases)
│   ├── services/
│   │   ├── scan_service.py  # Lógica de scan de hosts e portas
│   │   ├── cve_analyzer.py  # Análise de CVEs por banner
│   │   ├── nvd_updater.py   # Atualização da base NVD local
│   │   ├── reporter.py      # Geração de tabela e exportação CSV
│   │   ├── recon.py         # Reconhecimento (fase 1 pentest)
│   │   ├── enumeration.py   # Enumeração de serviços
│   │   ├── auth_tester.py   # Teste de autenticação
│   │   └── deep_enum.py     # Enumeração profunda
│   ├── infra/
│   │   ├── cache.py         # Cache de resultados
│   │   └── oui_loader.py    # Carregamento da tabela OUI (fabricantes)
│   ├── config/
│   │   └── settings.py      # Auto-configuração e presets
│   └── models/
│       └── pentest_models.py # Modelos de dados do pentest
├── nvd_data/                # Base NVD local (gerada automaticamente)
├── manuf                    # Tabela OUI de fabricantes (offline)
├── requirements.txt         # Dependências Python
└── docs/                    # Documentação
```

---

## Saída e relatórios

- **Terminal:** tabela colorida com IP, status, hostname, MAC, fabricante, SO, portas abertas, banners e CVEs encontrados
- **CSV:** exportado com delimitador `;`, campos: IP, Status, Hostname, MAC, Fabricante, SO, Portas, Banners, Vulnerabilidades, Latência (ms)
- **JSON (modo pentest):** relatório completo com todos os achados classificados por severidade (alto/médio/baixo)

---

## Observações

- Execute com permissões adequadas — algumas operações de rede (`ping`, `arp`) podem exigir sudo dependendo da configuração do sistema.
- Use apenas em redes onde você possui autorização. O modo pentest é especialmente intrusivo.
- A base NVD é baixada automaticamente na primeira execução (~500 MB). Pode demorar alguns minutos.
- Firewall ou filtros de rede podem impedir o banner grabbing ou ping, gerando falsos negativos.
