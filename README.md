# StrongSwanSysTray

Indicador de bandeja (systray) para Linux que conecta, desconecta, mostra o status e abre a configuração das VPNs IPsec do **strongSwan** definidas em `/etc/ipsec.conf`.

Ele foi feito para conexões que o NetworkManager não consegue gerenciar. Um exemplo é IKEv1 Aggressive + XAuth com PSK, comum em FortiGate, que o plugin `network-manager-strongswan` não suporta (ele só faz IKEv2).

## Funcionalidades

- O ícone na barra superior indica o estado da VPN: conectada, desconectada ou conectando.
- O menu lista todas as conexões `conn` do `ipsec.conf`, com o IP virtual recebido.
- **Conectar / Desconectar** cada conexão (`ipsec up` / `ipsec down`). Se o serviço estiver parado, ele é iniciado antes.
- **Status detalhado**: abre uma janela com a saída de `ipsec statusall`.
- **Editar configuração**: abre um terminal com `sudoedit /etc/ipsec.conf` e oferece recarregar ao salvar.
- **Recarregar configuração** (`ipsec reload`) e **Iniciar/Parar serviço strongSwan**.
- Notificações da área de trabalho ao conectar, ao desconectar, em caso de falha e quando o túnel cai.
- O status é lido **sem root**, então não pede senha a cada verificação. Só as ações pedem autenticação, via `pkexec`.

## Requisitos

- Linux com GNOME/Ubuntu (ou outro ambiente com suporte a AppIndicator/StatusNotifierItem).
- strongSwan com o *starter* (`strongswan-starter`, comando `ipsec`).
- Python 3.10+ com PyGObject (GTK 3). No Ubuntu já vem instalado.
- `gir1.2-ayatanaappindicator3-0.1`.
- No GNOME, a extensão *AppIndicator* precisa estar ativa. No Ubuntu ela já vem ativa (`ubuntu-appindicators@ubuntu.com`).

```bash
sudo apt install gir1.2-ayatanaappindicator3-0.1 gir1.2-notify-0.7 strongswan-starter
```

## Instalação

```bash
git clone https://github.com/marcosdenoni/StrongSwanSysTray.git
cd StrongSwanSysTray
./install.sh            # atalho no menu de aplicativos + início automático no login
./strongswan_systray.py &
```

Opções do `install.sh`:

| Opção | Efeito |
|---|---|
| *(nenhuma)* | Instala a dependência, se faltar, o atalho em `~/.local/share/applications` e o início automático em `~/.config/autostart` |
| `--polkit` | Também instala a regra polkit que dispensa a senha (veja abaixo) |
| `--remove` | Remove o atalho, o início automático e a regra polkit |

### Conectar sem digitar senha (opcional)

Por padrão, cada ação (conectar, desconectar, status) pede a senha de administrador pelo `pkexec`. A regra em [`polkit/49-strongswan-systray.rules`](polkit/49-strongswan-systray.rules) libera **somente** o `/usr/sbin/ipsec` para usuários do grupo `sudo` em sessão local ativa:

```bash
./install.sh --polkit
# ou manualmente:
sudo install -m 644 polkit/49-strongswan-systray.rules /etc/polkit-1/rules.d/
```

> Com essa regra, qualquer processo rodando como seu usuário pode subir e derrubar VPNs e ler o `ipsec statusall`, sem pedir senha. Avalie se isso é aceitável na sua máquina.

## Uso

```text
strongswan_systray.py [--config ARQUIVO] [--interval SEGUNDOS] [--list]

  --config     ipsec.conf a ser lido (padrão: /etc/ipsec.conf)
  --interval   intervalo de verificação do status (padrão: 3 s)
  --list       mostra as conexões e o estado atual no terminal e sai
```

Exemplo:

```text
$ ./strongswan_systray.py --list
charon: rodando
ecostorage           10.1.0.0/16                    conectado 10.152.100.2
```

## Configurando uma conexão

O app só lê o `ipsec.conf`. Ele não cria conexões. Entram no menu as conexões que:

- têm `auto=add`, `auto=route` ou `auto=start` (`auto=ignore` fica de fora, o que permite usá-las como base para `also=`);
- não são `type=passthrough`, `drop` ou `reject`.

São suportados `conn %default`, `also=` e `include`.

Exemplo para FortiGate (IKEv1 Aggressive + XAuth + Mode Config), equivalente à configuração do FortiClient:

```conf
conn minhavpn
    keyexchange=ikev1
    aggressive=yes
    authby=xauthpsk
    xauth=client
    xauth_identity=meu.usuario
    left=%defaultroute
    leftsourceip=%config
    right=meugateway.fortiddns.com
    rightsubnet=10.1.0.0/16          # redes remotas (evite 0.0.0.0/0, veja abaixo)
    ike=aes128-sha1-modp1536,aes256-sha256-modp1536!
    esp=aes128-sha1-modp1536,aes256-sha256-modp1536!
    ikelifetime=86400s
    lifetime=43200s
    modeconfig=pull
    dpdaction=restart
    dpddelay=30s
    auto=add

# mantém a LAN local fora do túnel
conn lan-passthrough
    leftsubnet=192.168.0.0/24
    rightsubnet=192.168.0.0/24
    type=passthrough
    authby=never
    auto=route
```

A PSK e a senha do XAuth ficam em `/etc/ipsec.secrets`:

```conf
: PSK "chave-compartilhada"
meu.usuario : XAUTH "senha"
```

## Como o status é detectado

O socket de controle do strongSwan (`/var/run/charon.ctl`) só é acessível pelo root. Por isso o app deduz o estado sem privilégios:

1. Ele verifica se o processo `charon` está rodando (`/proc/*/comm`).
2. Ele lê as rotas da tabela **220** (`ip route show table 220`), que o strongSwan cria para cada CHILD_SA instalada.
3. A conexão é considerada **conectada** quando existe uma rota para algum dos `rightsubnet` dela. O `src` dessa rota é o IP virtual mostrado no menu.

**Limitações:**
- Conexões sem `rightsubnet` (host-a-host) aparecem sempre como desconectadas.
- Se você configurar `installpolicy=no`, ou mudar `charon.install_routes` / `charon.routing_table` no `strongswan.conf`, a detecção não funciona.
- Para o estado exato, use **Status detalhado**.

## Solução de problemas

| Sintoma | Causa provável |
|---|---|
| Ícone não aparece | Falta a extensão AppIndicator no GNOME ou o pacote `gir1.2-ayatanaappindicator3-0.1` |
| "Falha ao conectar" com erro de XAuth | Senha ausente ou errada em `/etc/ipsec.secrets` |
| Conecta, mas nenhum host remoto responde | Use **Status detalhado** e `sudo ip -s xfrm state`. Se os bytes de entrada ficam em 0, o gateway não está devolvendo tráfego: faltam firewall policy ou rota de volta no lado remoto |
| Internet ou containers Docker param com a VPN ligada | `rightsubnet=0.0.0.0/0` manda todo o tráfego para o túnel. Restrinja às redes remotas |

## Estrutura

```text
strongswan_systray.py              aplicativo (arquivo único)
install.sh                         instalação para o usuário
data/strongswan-systray.desktop    atalho / início automático
polkit/49-strongswan-systray.rules regra opcional para dispensar a senha
```
