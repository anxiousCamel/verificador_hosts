# Verificador de Hosts com Auditoria de Segurança

Este é um scanner de rede completo, com verificação de IPs online/offline, identificação de SO, MAC, fabricante, portas abertas e banners — tudo formatado com `rich`, e com exportação para CSV.

## 🛠 Funcionalidades

- Ping + TTL → identifica SO (Linux/Windows/Cisco)
- Hostname reverso (DNS)
- MAC e fabricante por OUI (consulta offline via `manuf`)
- Scan de portas conhecidas com banner grabbing
- Exportação em CSV com delimitador `;`
- Tabela colorida com destaque para portas críticas

## 📦 Instalação

```bash
git clone 
cd verificador_hosts
pip install -r requirements.txt
python __main__.py
