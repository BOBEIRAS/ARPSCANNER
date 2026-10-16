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
./netmap -i eth0 -w
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

## Como funciona o ARP

Numa rede IPv4 local, um computador precisa de descobrir que endereço MAC
corresponde a um endereço IP. Envia então um pedido ARP em broadcast: todos os
equipamentos locais o recebem, mas normalmente só o equipamento que possui
aquele IP responde com o seu MAC. O netmap envia estes pedidos para os
endereços do intervalo escolhido e guarda as respostas. Como o ARP só funciona
no segmento local, o alvo tem de pertencer à rede local da interface.
