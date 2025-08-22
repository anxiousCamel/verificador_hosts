

# 🚀 Verificador de Hosts com Auditoria de Segurança

Projeto de auditoria de rede local via terminal, com recursos completos de varredura e análise de vulnerabilidades.

---
## 🧰 Tecnologias & Linguagens

<!-- Badges do stack -->

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/CLI-rich-5D2B7D" alt="rich" />
  <img src="https://img.shields.io/badge/CLI-tqdm-4A4A4A" alt="tqdm" />
  <img src="https://img.shields.io/badge/Rede-socket%20ssl-0A66C2" alt="socket/ssl" />
  <img src="https://img.shields.io/badge/SO-ping%20arp%20ip%20neigh-555555" alt="ping/arp/ip neigh" />
  <img src="https://img.shields.io/badge/HTTP-requests-BA2F2F?logo=httpie&logoColor=white" alt="requests" />
  <img src="https://img.shields.io/badge/Versionamento-packaging.version-2E7D32" alt="packaging" />
  <img src="https://img.shields.io/badge/Dados-NVD%20(CVE%20JSON)-E65100" alt="NVD" />
  <img src="https://img.shields.io/badge/Concorr%C3%AAncia-ThreadPoolExecutor%20Semaphore-6D4C41" alt="threads" />
  <img src="https://img.shields.io/badge/Relat%C3%B3rio-CSV%20(%3B%20delimiter)-2962FF" alt="CSV" />
</p>

<!-- Gráfico Mermaid (compatível com GitHub) -->

```mermaid
flowchart LR
  A[Verificador de Hosts] --> B[Python 3.8+]
  A --> C[CLI e UX]
  C --> C1[rich]
  C --> C2[tqdm]
  A --> D[Rede]
  D --> D1[socket]
  D --> D2[ssl]
  D --> D3[ping / arp / ip neigh]
  A --> E[Vulnerabilidades]
  E --> E1[NVD JSON]
  E --> E2[packaging.version]
  A --> F[Concorrencia]
  F --> F1[ThreadPoolExecutor]
  F --> F2[Semaphore]
  A --> G[Relatorios]
  G --> G1[rich Table]
  G --> G2[CSV]
```

<!-- Versão alternativa "safe" (se seu renderer não suportar alguns caracteres) -->

```mermaid
flowchart TD
  A[Verificador] --> B[Python]
  A --> C[CLI]
  C --> C1[rich]
  C --> C2[tqdm]
  A --> D[Rede]
  D --> D1[socket]
  D --> D2[ssl]
  D --> D3[ping/arp/ip]
  A --> E[CVEs]
  E --> E1[NVD]
  E --> E2[packaging]
  A --> F[Threads]
  F --> F1[ThreadPoolExecutor]
  F --> F2[Semaphore]
  A --> G[Relatorio]
  G --> G1[tabela]
  G --> G2[csv]
```


##  Funcionalidades

- **Ping + TTL** → Identificação de sistema operacional (Linux/Windows/Cisco)
- **Hostname reverso (DNS)**
- **MAC e fabricante** via OUI (offline, usando `manuf`)
- **Scan de portas comuns** com banner grabbing
- **Detecção de vulnerabilidades (CVEs)** baseado em banners e base local da NVD
- **Relatório visual colorido** no terminal com `rich`, destacando portas críticas e latência
- **Exportação para CSV** com delimitador `;`

---

##  Estrutura do Projeto

```
verificador_hosts/
├── __main__.py              # Script principal de execução
├── scan.py                  # Lógica de varredura de hosts e portas
├── utils.py                 # Auxiliares para entrada e tabela OUI
├── cve.py                   # Processamento e verificação de CVEs via NVD
├── atualizar_nvd.py         # Atualização da base NVD local (.json.gz + cache)
├── relatorio.py             # Exibição e exportação dos dados
├── config.py                # Auto-configuração de threads e timeout
├── requirements.txt         # Dependências do projeto
├── .gitignore               # Itens ignorados pelo Git
├── manuf                    # Arquivo OUI (Wireshark/Nmap) com fabricantes
└── nvd_data/                # Arquivos NVD baixados (ignorado no Git)
```

---

##  Instalação e Execução

1. Clone o repositório:

   ```bash
   git clone https://github.com/anxiousCamel/verificador_hosts
   cd verificador_hosts
   ```

2. (Opcional) Configure ambiente virtual:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

3. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

4. Execute o programa principal:

   ```bash
   python __main__.py
   ```

---

##  Atualizando a base CVE (NVD)

Para baixar ou atualizar a base local de vulnerabilidades (JSON .gz da NVD):

```bash
python atualizar_nvd.py
# Ou usar o comando principal, que verifica automaticamente e atualiza se necessário
python __main__.py
```

A base será salva em `nvd_data/` e usada para consulta local de CVEs.

---

##  Exportação de Relatórios

Ao final da varredura, você pode exportar os resultados em CSV com delimitador `;`.

Campos incluídos:

- IP, Status, Hostname, MAC, Fabricante, Sistema Operacional, Portas, Banners, Vulnerabilidades, Latência (ms)

---

##  Observações Importantes

- A detecção de CVEs depende da correspondência textual entre banners e descrições — pode haver inconsistência ou falsos negativos.
- Firewall ou filtros de rede podem impedir o banner grabbing ou ping.
- Repositório configurado para evitar versionamento de grandes dados locais (`nvd_data/`) e caches (`__pycache__`, `.pyc`).

---

##  Autor

Luiz Vinicius Belmont — Desenvolvedor e Infraestruturista

---

##  Licença

Uso interno e educacional. Consulte o autor para distribuição ou adaptação.
