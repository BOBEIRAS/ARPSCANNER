# arpscan

Scanner e monitor de dispositivos numa rede local IPv4, feito em C para Linux.
Usa pedidos ARP para encontrar dispositivos na rede da interface indicada e
assinala entradas e saídas enquanto está em execução.

> Utilize apenas em redes suas ou para as quais tenha autorização.

## Requisitos

- Linux com suporte para sockets `AF_PACKET` (o programa usa cabeçalhos Linux).
- GCC e ferramentas de compilação.
- Privilégios de `root` para abrir o raw socket.
- Opcional: `ieee-data`, para mostrar o fabricante associado ao endereço MAC.

Em Debian ou Ubuntu, instale as dependências com:

```sh
sudo apt update
sudo apt install build-essential ieee-data
```

Sem `ieee-data`, o scanner continua a funcionar, mas pode mostrar o fabricante
como desconhecido.

## Compilar

Na pasta do projeto:

```sh
gcc -Wall -Wextra -O2 arpscan.c -o arpscan
```

## Executar

Veja as interfaces de rede e os respetivos endereços:

```sh
ip -br addr
```

Escolha a interface ligada à rede que pretende monitorizar (por exemplo,
`eth0`, `enp3s0` ou `wlan0`) e execute:

```sh
sudo ./arpscan enp3s0
```

Substitua `enp3s0` pelo nome da interface do seu sistema. O programa obtém
automaticamente o endereço e a máscara IPv4 dessa interface. Prima `Ctrl+C`
para parar.

## O que esperar

- O primeiro scan apresenta a tabela dos dispositivos encontrados.
- Os scans seguintes são feitos aproximadamente a cada cinco segundos e
  mostram mudanças, como dispositivos que entram, saem ou voltam à rede.
- O fabricante é consultado em `/usr/share/ieee-data/oui.txt`, quando esse
  ficheiro está instalado.

## Dispositivos conhecidos e privacidade

O programa lê e atualiza `known_devices.txt` na pasta de onde é executado.
Usa os endereços MAC guardados nesse ficheiro para distinguir dispositivos já
vistos de dispositivos novos. Se o ficheiro ainda não existir, é criado quando
o programa regista dispositivos.

Este ficheiro é ignorado pelo Git porque pode conter endereços IP e MAC da sua
rede. Não o adicione ao repositório. Se já tiver sido adicionado ao Git,
remova-o do índice antes de publicar, sem apagar a cópia local:

```sh
git rm --cached known_devices.txt
```

O executável compilado `arpscan` também é ignorado; publique o código-fonte e
compile-o no sistema onde o vai utilizar.
