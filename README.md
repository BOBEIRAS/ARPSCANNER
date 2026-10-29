# Netmap

Scanner e monitor de dispositivos IPv4 numa rede local Linux. Envia pedidos
ARP, apresenta os dispositivos que respondem e, em modo de monitorização,
regista alterações observadas na rede.

Usa o programa apenas em redes próprias ou para as quais tenhas autorização.

## Requisitos

- Linux (incluindo Raspberry Pi OS; no WSL2, uma interface de rede compatível
  com `AF_PACKET`).
- GCC e `make`.
- Opcional: o ficheiro `/usr/share/ieee-data/oui.txt`, para identificar o
  fabricante pelo prefixo MAC.
- Para a API/dashboard: Python 3 e `python3-venv`.
- Para testes ARP autorizados: uma segunda máquina Linux na mesma rede de
  teste. O `ARPSPOOFER` usa APIs Linux e não corre diretamente no Windows.

O projeto usa apenas a libc e cabeçalhos do Linux; não precisa de dependências
adicionais para compilar.

## Compilar e instalar

Na pasta do projeto:

```sh
make
```

Para instalar em `/usr/local/bin` e atribuir ao executável a capacidade de abrir
raw sockets:

```sh
sudo make install
```

A instalação pede privilégios uma vez; depois o programa pode ser executado sem
`sudo`. Para remover os ficheiros gerados pela compilação:

```sh
make clean
```

## Utilização

```sh
./netmap
./netmap -i ens33 -w
./netmap 192.168.1.0/24
./netmap -t 3 192.168.1.0/24
./netmap 192.168.1.0/24 -p
```

As opções presentes nesta versão são:

- `-i iface`: escolhe a interface; sem esta opção, é usada a interface da rota
  predefinida.
- `-w`: continua a monitorizar, detetando entradas, saídas e regressos.
- `-t seg`: tempo de espera pelas respostas ARP em cada scan (por omissão, 2
  segundos).
- `-p`: testa portas TCP comuns nos dispositivos encontrados e apresenta uma
  classificação aproximada pelo conjunto de serviços que responde.
- `-j`: emite JSON Lines (um objeto por linha), adequado para um agente enviar
  os dados para uma API ou dashboard. Os objetos `snapshot` contêm os
  dispositivos encontrados e os objetos `event`/`alert` representam alterações
  detetadas. Combine com `-w` para produzir atualizações contínuas.
- `-h`: apresenta a ajuda.
- `alvo`: endereço IPv4 ou rede CIDR; se omitido, usa os endereços de host da
  rede da interface selecionada.

O scan de portas é opcional, usa ligações TCP não bloqueantes e testa uma lista
fixa de portas de serviços comuns. A classificação é apenas indicativa: uma
porta aberta não identifica com certeza o sistema operativo nem o tipo de
equipamento.

## Estrutura

- `src/`: código-fonte C dos módulos.
- `include/`: headers públicos partilhados entre módulos.
- `build/`: ficheiros objeto `.o` gerados pelo `make`; não é necessário
  versioná-los.
- `src/main.c`: argumentos, scan e ciclo de monitorização.
- `src/net.c` / `include/net.h`: interface, gateway, raw socket e envio/receção ARP.
- `src/oui.c` / `include/oui.h`: carregamento da tabela IEEE e pesquisa do fabricante.
- `src/names.c` / `include/names.h`: nomes personalizados, mDNS e DNS inverso.
- `src/ports.c` / `include/ports.h`: sondagem não bloqueante de portas TCP comuns e
  classificação indicativa dos serviços.
- `src/known.c` / `include/known.h`: dispositivos conhecidos e deteção de alterações
  IP/MAC.
- `src/output.c` / `include/output.h`: formatação da tabela e mensagens de estado.
- `src/util.c` / `include/util.h`: tempo monotónico e ordenação dos dispositivos.
- `include/common.h`: definições partilhadas de `struct device` e `struct arp_packet`.
- `Makefile`: compilação de todos os ficheiros `.c`, instalação e limpeza.

Os ficheiros `names.txt` e `known_devices.txt` são lidos na pasta de onde o
programa é executado. `names.txt` associa um MAC a um nome personalizado;
`known_devices.txt` é atualizado com os dispositivos encontrados.

### Integração com um dashboard

Para obter uma atualização inicial em JSON:

```sh
sudo ./netmap -j -p 192.168.1.0/24
```

Para monitorização contínua:

```sh
sudo ./netmap -j -w -p 192.168.1.0/24
```

Cada linha é um JSON independente. Um processo Flask, por exemplo, pode ler
`stdout` linha a linha e inserir os objetos na API/Supabase. O scanner só deve
ser usado em redes próprias ou autorizadas; a sondagem de portas é limitada a
serviços comuns e não pretende substituir uma auditoria completa do Nmap.

### Alertas automáticos para a API

O agente [alert_agent.py](tools/alert_agent.py) executa o scanner continuamente,
lê os alertas do Suricata (`eve.json`) e envia apenas alertas para uma API
HTTPS. Se a API falhar, guarda os eventos numa fila SQLite local e tenta
novamente.

Instala o agente:

```sh
sudo make install-agent
sudo install -d -m 700 /var/lib/netmap-alerts
sudo sh -c 'cat > /etc/netmap-alert-agent.conf' <<'EOF'
ALERT_API_URL=https://dashboard.exemplo.pt/api/alerts
ALERT_API_TOKEN=coloca_aqui_um_token_longo
NETMAP_TARGET=192.168.1.0/24
NETMAP_INTERFACE=ens33
SURICATA_EVE=/var/log/suricata/eve.json
EOF
sudo chmod 600 /etc/netmap-alert-agent.conf
sudo systemctl enable --now netmap-alert-agent
```

Se já tinhas instalado uma versão anterior, volta a executar `sudo
make install-agent` depois de recompilar: este comando atualiza também
`/usr/local/bin/netmap`, que é o executável usado pelo serviço.

O endpoint deve aceitar `POST` com `Content-Type: application/json` e
`Authorization: Bearer <token>`. Os alertas gerados automaticamente incluem
possível ARP spoofing, portas sensíveis abertas (23, 445, 3306 e 3389) e
alertas do Suricata. Não coloques o token no código nem no repositório.

### API e dashboard local

Para uma instalação autónoma , o projeto inclui uma API Flask e
um dashboard local. A API fica no porto `5000` e deve ser limitada à rede local
com uma regra de firewall. O agente comunica por `localhost`; esse tráfego não
sai do computador.

```sh
sudo apt install -y python3-venv
cd /home/andre/projetos/ARPSCANNER
sudo make install-dashboard
```

Adiciona ao `/etc/netmap-alert-agent.conf`:

```ini
ALERT_API_URL=http://127.0.0.1:5000/api/alerts
ALERT_API_TOKEN=um_token_longo_e_secreto
```

Depois inicia:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now netmap-dashboard netmap-alert-agent
```

Abre no navegador `http://IP_DO_PC:5000`. Para limitar o porto à rede
local, configura UFW, por exemplo: `sudo ufw allow from 192.168.1.0/24 to any port 5000 proto tcp`.

### Verificação da instalação

Confirma o nome da interface antes de configurar o serviço:

```sh
ip -br addr
ip route
```

Testa o scanner diretamente:

```sh
sudo /usr/local/bin/netmap -i ens33 -j -p 192.168.1.0/24
```

Confirma os serviços:

```sh
sudo systemctl --no-pager status netmap-dashboard
sudo systemctl --no-pager status netmap-alert-agent
sudo journalctl -u netmap-alert-agent -n 50 --no-pager
```

O dashboard deve abrir em `http://IP_DO_PC:5000`. Para testar a API
sem executar um ataque, envia um alerta de laboratório:

```sh
curl -X POST http://127.0.0.1:5000/api/alerts \
  -H "Authorization: Bearer um_token_longo_e_secreto" \
  -H "Content-Type: application/json" \
  -d '{"type":"alert","alert":"teste","severity":"medium","ip":"192.168.1.200"}'
```

Atualiza a página do dashboard; o alerta deve aparecer. O agente ignora
`snapshot` e `event` para não os enviar como alertas.

### Teste autorizado de ARP spoofing

Este teste altera temporariamente a tabela ARP de uma vítima e pode cortar a
ligação à Internet. Executa-o apenas em dispositivos teus ou numa rede de
laboratório. Não uses o router como vítima e não tentes capturar passwords,
cookies ou tráfego de outras pessoas.

Topologia recomendada:

```text
Raspberry/monitor: 192.168.1.113  (netmap + API + dashboard)
VM atacante:      192.168.1.114  (ARPSPOOFER)
Vítima de teste:  192.168.1.104  (teu telemóvel ou uma VM tua)
Gateway:          192.168.1.1
```

Os endereços são apenas um exemplo. Confirma sempre os valores no teu ambiente.
Na VMware, uma rede `Host-only` ou `Internal Network` é mais segura que
`Bridged`; se testares na rede doméstica, usa somente os teus dispositivos.
O monitor e o atacante têm de estar em máquinas diferentes. O próprio monitor
ignora anúncios ARP originados pelo seu MAC.

Na Raspberry, inicia o serviço e acompanha os alertas:

```sh
sudo systemctl restart netmap-alert-agent
sudo journalctl -u netmap-alert-agent --since "now" -f
```

Na VM atacante, confirma primeiro a interface e a conectividade:

```sh
ip -br addr
ip route
ping -c 3 192.168.1.1
ping -c 3 192.168.1.104
```

Se necessário, instala a ferramenta de diagnóstico:

```sh
sudo apt update
sudo apt install -y iputils-arping
sudo arping -I ens33 -c 3 192.168.1.1
sudo arping -I ens33 -c 3 192.168.1.104
```

Só depois de confirmares que a vítima é tua e está acessível inicia o
`ARPSPOOFER` na VM atacante:

```sh
sudo ./arpspoof ens33 192.168.1.104 192.168.1.1
```

Neste programa, a ordem é:

```text
arpspoof <interface> <IP_da_vítima> <IP_do_router>
```

O alerta esperado no dashboard é:

```json
{
  "type": "alert",
  "alert": "arp_mac_changed",
  "severity": "critical"
}
```

Também pode aparecer um alerta `high` para a alteração do IP da vítima. Para
confirmar o tráfego ARP durante um diagnóstico:

```sh
sudo tcpdump -ni ens33 'arp and (host 192.168.1.1 or host 192.168.1.104)'
```

Termina o teste imediatamente com `Ctrl+C` no atacante. Depois confirma que o
gateway voltou ao MAC legítimo e reconecta o Wi-Fi da vítima:

```sh
ip neigh show 192.168.1.1
```

Se a vítima ficar sem rede, desliga e liga o Wi-Fi. Se `ping` ao gateway
funcionar mas a vítima não responder, verifica se está numa rede guest ou se o
router tem isolamento entre clientes. O erro `MAC: No such device` significa
que o nome da interface está errado; usa o nome mostrado por `ip -br addr`.

### Resolução de problemas

- **`MAC: No such device`**: troca `eth0` pelo nome real, por exemplo `ens33`,
  em `/etc/netmap-alert-agent.conf`.
- **`HTTP 400`**: atualiza o agente com `sudo make install-agent`; payloads
  antigos incompatíveis podem ser removidos parando o serviço e apagando
  `/var/lib/netmap-alerts/queue.db`.
- **Dashboard sem alertas**: confirma o token, a porta `5000` e que o agente
  está ativo. Snapshots não são apresentados como alertas.
- **Vítima inacessível**: confirma que o IP ainda é o correto, que as máquinas
  estão na mesma rede e que não existe isolamento Wi-Fi.
- **Sem alerta ARP**: inicia o agente antes do teste e não o reinicies durante
  o teste; confirma também com `tcpdump` que a máquina monitorizadora recebe os
  anúncios ARP.

## Como funciona o ARP

Numa rede IPv4 local, um computador precisa de descobrir que endereço MAC
corresponde a um endereço IP. Envia então um pedido ARP em broadcast: todos os
equipamentos locais o recebem, mas normalmente só o equipamento que possui
aquele IP responde com o seu MAC. O netmap envia estes pedidos para os
endereços do intervalo escolhido e guarda as respostas. Como o ARP só funciona
no segmento local, o alvo tem de pertencer à rede local da interface.
