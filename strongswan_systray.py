#!/usr/bin/env python3
"""StrongSwanSysTray - indicador de bandeja para conexões strongSwan (ipsec.conf).

Conecta, desconecta, mostra o status e abre a configuração das conexões
definidas em /etc/ipsec.conf. O status é lido sem root (rotas da tabela 220
que o strongSwan instala); as ações privilegiadas usam pkexec.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field

import gi

gi.require_version("Gtk", "3.0")
try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
except (ValueError, ImportError):
    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator
    except (ValueError, ImportError):
        AppIndicator = None
from gi.repository import GLib, Gtk  # noqa: E402

try:
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify
except (ValueError, ImportError):
    Notify = None

APP_ID = "strongswan-systray"
APP_NAME = "StrongSwanSysTray"
ROUTE_TABLE = "220"

ICON_UP = "network-vpn-symbolic"
ICON_DOWN = "network-vpn-disconnected-symbolic"
ICON_BUSY = "network-vpn-acquiring-symbolic"

IGNORED_TYPES = {"passthrough", "drop", "reject", "pass"}


# --------------------------------------------------------------------------- #
# ipsec.conf
# --------------------------------------------------------------------------- #
@dataclass
class Connection:
    name: str
    options: dict[str, str] = field(default_factory=dict)

    @property
    def subnets(self) -> list[str]:
        raw = self.options.get("rightsubnet", "")
        return [s.strip() for s in raw.split(",") if s.strip()]

    @property
    def is_tunnel(self) -> bool:
        return self.options.get("type", "tunnel") not in IGNORED_TYPES

    @property
    def gateway(self) -> str:
        return self.options.get("right", "?")

    @property
    def uses_psk(self) -> bool:
        authby = self.options.get("authby", "")
        return authby in ("secret", "psk", "xauthpsk") or self.options.get("leftauth") == "psk"

    @property
    def user_auth(self) -> tuple[str, str] | None:
        """(tipo do segredo, chave da identidade) para XAuth/EAP, ou None."""
        o = self.options
        if (o.get("authby", "").startswith("xauth") or o.get("leftauth2") == "xauth"
                or o.get("xauth") == "client" or "xauth_identity" in o):
            return "XAUTH", "xauth_identity"
        if o.get("leftauth", "").startswith("eap") or "eap_identity" in o:
            return "EAP", "eap_identity"
        return None

    @property
    def remote_ids(self) -> list[str]:
        rid = self.options.get("rightid") or self.options.get("right", "")
        return [rid] if rid and not rid.startswith("%") else []


def parse_ipsec_conf(path: str) -> list[Connection]:
    """Lê as seções 'conn' de um ipsec.conf, resolvendo 'also=' e '%default'."""
    raw: dict[str, dict[str, str]] = {}
    order: list[str] = []
    current: dict[str, str] | None = None

    def read(p: str) -> None:
        nonlocal current
        try:
            with open(p, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return
        for line in lines:
            stripped = line.split("#", 1)[0].rstrip()
            if not stripped.strip():
                continue
            if not line[0].isspace():
                parts = stripped.split()
                if parts[0] == "conn" and len(parts) > 1:
                    name = parts[1]
                    current = raw.setdefault(name, {})
                    if name not in order:
                        order.append(name)
                elif parts[0] == "include" and len(parts) > 1:
                    pattern = parts[1]
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(os.path.dirname(p), pattern)
                    for inc in sorted(glob.glob(pattern)):
                        read(inc)
                    current = None
                else:
                    current = None  # config setup, ca, ...
            elif current is not None and "=" in stripped:
                key, value = stripped.strip().split("=", 1)
                current[key.strip()] = value.strip().strip('"')

    read(path)

    def resolve(name: str, seen: frozenset[str] = frozenset()) -> dict[str, str]:
        if name in seen or name not in raw:
            return {}
        opts: dict[str, str] = {}
        for parent in raw[name].get("also", "").split():
            opts.update(resolve(parent, seen | {name}))
        opts.update({k: v for k, v in raw[name].items() if k != "also"})
        return opts

    defaults = raw.get("%default", {})
    conns = []
    for name in order:
        if name == "%default":
            continue
        opts = dict(defaults)
        opts.update(resolve(name))
        conn = Connection(name, opts)
        if conn.is_tunnel and opts.get("auto", "ignore") != "ignore":
            conns.append(conn)
    return conns


# --------------------------------------------------------------------------- #
# Estado (sem root)
# --------------------------------------------------------------------------- #
def daemon_running() -> bool:
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                if fh.read().strip() == "charon":
                    return True
        except OSError:
            continue
    return False


def tunnel_routes() -> dict[str, str]:
    """Rotas da tabela do strongSwan: {destino: ip_virtual}."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "table", ROUTE_TABLE],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    routes = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("throw", "unreachable", "prohibit", "blackhole"):
            continue
        dest = "0.0.0.0/0" if parts[0] == "default" else parts[0]
        if "/" not in dest:
            dest += "/32"
        src = parts[parts.index("src") + 1] if "src" in parts else ""
        routes[dest] = src
    return routes


def connection_state(conn: Connection, routes: dict[str, str]) -> str | None:
    """Retorna o IP virtual se a conexão parece ativa, senão None."""
    for subnet in conn.subnets:
        if "/" not in subnet:
            subnet += "/32"
        if subnet in routes:
            return routes[subnet] or "conectado"
    return None


# --------------------------------------------------------------------------- #
# Comandos privilegiados
# --------------------------------------------------------------------------- #
def ipsec_bin() -> str:
    return shutil.which("ipsec") or "/usr/sbin/ipsec"


SECRETS_HELPER = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              "strongswan_systray_secrets.py")


def run_privileged(*args: str, command: list[str] | None = None,
                   stdin: str | None = None) -> tuple[int, str]:
    """Executa 'ipsec <args>' (ou outro comando) como root via pkexec."""
    cmd = ["pkexec", *(command or [ipsec_bin()]), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                              input=stdin)
    except subprocess.TimeoutExpired:
        return 1, "Tempo esgotado aguardando o strongSwan."
    except OSError as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def find_terminal() -> list[str] | None:
    candidates = [
        ("ptyxis", ["--"]),
        ("gnome-terminal", ["--"]),
        ("kgx", ["--"]),
        ("konsole", ["-e"]),
        ("xfce4-terminal", ["-x"]),
        ("x-terminal-emulator", ["-e"]),
    ]
    env_term = os.environ.get("TERMINAL")
    if env_term and shutil.which(env_term):
        return [env_term, "-e"]
    for name, flag in candidates:
        if shutil.which(name):
            return [name, *flag]
    return None


# --------------------------------------------------------------------------- #
# Indicador
# --------------------------------------------------------------------------- #
class Tray:
    def __init__(self, config_path: str, interval: int) -> None:
        self.config_path = config_path
        self.interval = interval
        self.busy: set[str] = set()
        self.conns: list[Connection] = []
        self.states: dict[str, str | None] = {}
        self.daemon = False
        self.signature: tuple | None = None

        self.indicator = AppIndicator.Indicator.new(
            APP_ID, ICON_DOWN, AppIndicator.IndicatorCategory.SYSTEM_SERVICES
        )
        self.indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.indicator.set_title(APP_NAME)

        if Notify is not None:
            Notify.init(APP_NAME)

        self.reload_config()
        GLib.timeout_add_seconds(self.interval, self.refresh)

    # -- estado ------------------------------------------------------------- #
    def reload_config(self) -> None:
        self.conns = parse_ipsec_conf(self.config_path)
        self.signature = None
        self.refresh()

    def refresh(self) -> bool:
        routes = tunnel_routes()
        self.daemon = daemon_running()
        new_states = {c.name: connection_state(c, routes) for c in self.conns}

        for name, ip in new_states.items():
            old = self.states.get(name, "unset")
            if old != "unset" and bool(old) != bool(ip) and name not in self.busy:
                self.notify(name, f"Conectado ({ip})" if ip else "Desconectado")
        self.states = new_states

        signature = (self.daemon, tuple(sorted(self.states.items())), tuple(sorted(self.busy)))
        if signature != self.signature:
            self.signature = signature
            self.update_icon()
            self.build_menu()
        return True

    def update_icon(self) -> None:
        if self.busy:
            icon, desc = ICON_BUSY, "Conectando"
        elif any(self.states.values()):
            icon, desc = ICON_UP, "VPN conectada"
        else:
            icon, desc = ICON_DOWN, "VPN desconectada"
        self.indicator.set_icon_full(icon, desc)

    # -- menu --------------------------------------------------------------- #
    def build_menu(self) -> None:
        menu = Gtk.Menu()

        if not self.daemon:
            menu.append(self.label_item("Serviço strongSwan parado"))
        if not self.conns:
            menu.append(self.label_item(f"Nenhuma conexão em {self.config_path}"))

        single = len(self.conns) == 1
        for conn in self.conns:
            ip = self.states.get(conn.name)
            if conn.name in self.busy:
                status = "aguarde…"
            elif ip:
                status = f"conectado · {ip}"
            else:
                status = "desconectado"
            mark = "●" if ip else "○"
            title = f"{mark} {conn.name} — {status}"

            items = [
                self.action_item("Conectar", lambda _w, c=conn: self.connect(c),
                                 sensitive=not ip and conn.name not in self.busy),
                self.action_item("Desconectar", lambda _w, c=conn: self.disconnect(c),
                                 sensitive=bool(ip) and conn.name not in self.busy),
                self.action_item("Credenciais…", lambda _w, c=conn: self.edit_credentials(c),
                                 sensitive=conn.name not in self.busy
                                 and (conn.uses_psk or conn.user_auth is not None)),
            ]
            if single:
                menu.append(self.label_item(title))
                for it in items:
                    menu.append(it)
            else:
                parent = Gtk.MenuItem(label=title)
                sub = Gtk.Menu()
                sub.append(self.label_item(f"Gateway: {conn.gateway}"))
                for it in items:
                    sub.append(it)
                parent.set_submenu(sub)
                menu.append(parent)

        menu.append(Gtk.SeparatorMenuItem())
        menu.append(self.action_item("Status detalhado…", lambda _w: self.show_status()))
        menu.append(self.action_item("Editar ipsec.conf (nano)…",
                                     lambda _w: self.edit_file(self.config_path, "update")))
        menu.append(self.action_item("Editar ipsec.secrets (nano)…",
                                     lambda _w: self.edit_file(self.secrets_path, "rereadsecrets")))
        menu.append(self.action_item("Recarregar configuração", lambda _w: self.reload_daemon()))
        if self.daemon:
            menu.append(self.action_item("Parar serviço strongSwan",
                                         lambda _w: self.service("stop")))
        else:
            menu.append(self.action_item("Iniciar serviço strongSwan",
                                         lambda _w: self.service("start")))
        menu.append(Gtk.SeparatorMenuItem())
        menu.append(self.action_item("Sair", lambda _w: Gtk.main_quit()))

        menu.show_all()
        self.indicator.set_menu(menu)

    @staticmethod
    def label_item(text: str) -> Gtk.MenuItem:
        item = Gtk.MenuItem(label=text)
        item.set_sensitive(False)
        return item

    @staticmethod
    def action_item(text: str, callback, sensitive: bool = True) -> Gtk.MenuItem:
        item = Gtk.MenuItem(label=text)
        item.connect("activate", callback)
        item.set_sensitive(sensitive)
        return item

    # -- ações -------------------------------------------------------------- #
    def run_async(self, key: str, args: list[str], on_done,
                  command: list[str] | None = None, stdin: str | None = None) -> None:
        self.busy.add(key)
        self.refresh()

        def worker() -> None:
            code, output = run_privileged(*args, command=command, stdin=stdin)
            GLib.idle_add(finish, code, output)

        def finish(code: int, output: str) -> bool:
            self.refresh()  # atualiza o estado sem notificar (ainda ocupado)
            self.busy.discard(key)
            on_done(code, output)
            self.refresh()
            return False

        threading.Thread(target=worker, daemon=True).start()

    def connect(self, conn: Connection) -> None:
        def done(code: int, output: str) -> None:
            if code == 0 and "established successfully" in output:
                ip = connection_state(conn, tunnel_routes())
                self.notify(conn.name, f"Conectado ({ip})" if ip else "Conectado")
            elif code in (126, 127):
                self.notify(conn.name, "Autenticação cancelada")
            else:
                self.notify(conn.name, "Falha ao conectar:\n" + last_lines(output))

        if not self.daemon:
            # sobe o serviço antes; 'ipsec start' retorna antes do charon estar pronto
            self.run_async(conn.name, ["start"],
                           lambda *_: GLib.timeout_add_seconds(2, self._connect_now, conn, done))
        else:
            self._connect_now(conn, done)

    def _connect_now(self, conn: Connection, done) -> bool:
        self.run_async(conn.name, ["up", conn.name], done)
        return False

    def disconnect(self, conn: Connection) -> None:
        def done(code: int, output: str) -> None:
            if code in (126, 127):
                self.notify(conn.name, "Autenticação cancelada")
            elif code != 0:
                self.notify(conn.name, "Falha ao desconectar:\n" + last_lines(output))
            else:
                self.notify(conn.name, "Desconectado")

        self.run_async(conn.name, ["down", conn.name], done)

    def reload_daemon(self) -> None:
        def done(code: int, output: str) -> None:
            self.reload_config()
            if code == 0:
                self.notify(APP_NAME, "Configuração recarregada")
            elif code not in (126, 127):
                self.notify(APP_NAME, "Falha ao recarregar:\n" + last_lines(output))

        if self.daemon:
            self.run_async("__reload__", ["reload"], done)
        else:
            self.reload_config()
            self.notify(APP_NAME, "Configuração relida (serviço parado)")

    def service(self, action: str) -> None:
        def done(code: int, output: str) -> None:
            if code not in (0, 126, 127):
                self.notify(APP_NAME, f"Falha ao executar '{action}':\n" + last_lines(output))
            GLib.timeout_add_seconds(2, lambda: self.refresh() and False)

        self.run_async("__service__", [action], done)

    def show_status(self) -> None:
        def done(code: int, output: str) -> None:
            if code in (126, 127):
                return
            StatusWindow(output or "(sem saída)")

        self.run_async("__status__", ["statusall"], done)

    def edit_credentials(self, conn: Connection) -> None:
        dialog = CredentialsDialog(conn)
        response = dialog.run()
        values = dialog.values()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return

        user_auth = conn.user_auth
        request = {
            "conn": conn.name,
            "remote_ids": conn.remote_ids,
            "user_type": user_auth[0] if user_auth else "",
            "user_key": user_auth[1] if user_auth else "",
            "identity": values["identity"],
            "old_identity": conn.options.get(user_auth[1], "") if user_auth else "",
            "password": values["password"],
            "psk": values["psk"],
            "config": self.config_path,
        }

        def done(code: int, output: str) -> None:
            if code in (126, 127):
                self.notify(conn.name, "Autenticação cancelada")
                return
            try:
                result = json.loads(output.splitlines()[-1])
                message = result["message"]
            except (ValueError, IndexError, KeyError):
                message = "Falha ao salvar credenciais:\n" + last_lines(output)
            self.notify(conn.name, message)
            self.reload_config()

        self.run_async(conn.name, [], done,
                       command=[sys.executable, "-I", SECRETS_HELPER],
                       stdin=json.dumps(request))

    @property
    def secrets_path(self) -> str:
        return os.path.join(os.path.dirname(self.config_path), "ipsec.secrets")

    def edit_file(self, path: str, apply_action: str) -> None:
        """Abre o arquivo no nano como root (sudo) num terminal e oferece aplicar."""
        term = find_terminal()
        if term is None:
            self.notify(APP_NAME, "Nenhum terminal encontrado para editar " + path)
            return
        target = shlex.quote(path)
        script = (
            f"sudo nano {target} || {{ read -r -p 'Enter para fechar' _; exit 1; }}; "
            "if pgrep -x charon >/dev/null; then "
            f"read -r -p 'Aplicar no strongSwan agora (ipsec {apply_action})? [S/n] ' r; "
            f'[ "${{r,,}}" = n ] || sudo ipsec {apply_action}; '
            "read -r -p 'Enter para fechar' _; fi"
        )
        subprocess.Popen([*term, "bash", "-c", script], start_new_session=True)
        if path == self.config_path:
            GLib.timeout_add_seconds(5, self._watch_config, os.path.getmtime(path), 0)

    def _watch_config(self, mtime: float, ticks: int) -> bool:
        try:
            if os.path.getmtime(self.config_path) != mtime:
                self.reload_config()
                return False
        except OSError:
            return False
        if ticks < 120:  # observa por até 10 minutos
            GLib.timeout_add_seconds(5, self._watch_config, mtime, ticks + 1)
        return False

    # -- util --------------------------------------------------------------- #
    @staticmethod
    def notify(title: str, body: str) -> None:
        if Notify is None:
            return
        try:
            Notify.Notification.new(f"VPN {title}", body, ICON_UP).show()
        except GLib.Error:
            pass


class CredentialsDialog(Gtk.Dialog):
    """Usuário/senha (XAuth ou EAP) e PSK de uma conexão.

    Os valores atuais não são exibidos (o ipsec.secrets só é legível pelo
    root): campos de senha vazios mantêm o que já está gravado.
    """

    def __init__(self, conn: Connection) -> None:
        super().__init__(title=f"Credenciais — {conn.name}")
        self.add_buttons("Cancelar", Gtk.ResponseType.CANCEL,
                         "Salvar", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_resizable(False)
        self.user_auth = conn.user_auth

        grid = Gtk.Grid(row_spacing=8, column_spacing=12, margin=16)
        self.get_content_area().add(grid)
        row = 0

        def add(label: str, widget: Gtk.Widget) -> None:
            nonlocal row
            lbl = Gtk.Label(label=label, xalign=1)
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(widget, 1, row, 1, 1)
            row += 1

        add("Gateway:", Gtk.Label(label=conn.gateway, xalign=0, selectable=True))

        self.identity = Gtk.Entry(width_chars=32, activates_default=True)
        self.password = self.secret_entry()
        self.psk = self.secret_entry()

        if self.user_auth:
            kind = "XAuth" if self.user_auth[0] == "XAUTH" else "EAP"
            self.identity.set_text(conn.options.get(self.user_auth[1], ""))
            add(f"Usuário ({kind}):", self.identity)
            add("Senha:", self.password)
        if conn.uses_psk:
            add("Chave PSK:", self.psk)

        show = Gtk.CheckButton(label="Mostrar senhas")
        show.connect("toggled", lambda b: [e.set_visibility(b.get_active())
                                           for e in (self.password, self.psk)])
        grid.attach(show, 1, row, 1, 1)
        row += 1

        hint = Gtk.Label(xalign=0, wrap=True, max_width_chars=48)
        hint.set_markup(
            "<small>Campos de senha em branco mantêm o valor atual. "
            "Os dados são gravados em /etc/ipsec.secrets (com backup) e "
            "valem a partir da próxima conexão.</small>"
        )
        grid.attach(hint, 0, row, 2, 1)

        self.identity.connect("changed", lambda *_: self.validate())
        self.validate()
        self.show_all()

    @staticmethod
    def secret_entry() -> Gtk.Entry:
        entry = Gtk.Entry(width_chars=32, visibility=False, activates_default=True,
                          input_purpose=Gtk.InputPurpose.PASSWORD)
        entry.set_placeholder_text("(manter atual)")
        return entry

    def validate(self) -> None:
        ok = True
        if self.user_auth:
            ident = self.identity.get_text().strip()
            ok = bool(ident) and not any(c in ident for c in ' \t"#:')
        self.set_response_sensitive(Gtk.ResponseType.OK, ok)

    def values(self) -> dict[str, str]:
        return {
            "identity": self.identity.get_text().strip(),
            "password": self.password.get_text(),
            "psk": self.psk.get_text(),
        }


class StatusWindow(Gtk.Window):
    def __init__(self, text: str) -> None:
        super().__init__(title=f"{APP_NAME} — status")
        self.set_default_size(820, 520)
        view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.NONE)
        view.get_buffer().set_text(text)
        scroll = Gtk.ScrolledWindow()
        scroll.add(view)
        self.add(scroll)
        self.show_all()


def last_lines(text: str, n: int = 4) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines[-n:]) or "(sem detalhes)"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/ipsec.conf",
                        help="arquivo ipsec.conf (padrão: %(default)s)")
    parser.add_argument("--interval", type=int, default=3,
                        help="intervalo de verificação em segundos (padrão: %(default)s)")
    parser.add_argument("--list", action="store_true",
                        help="lista as conexões e o estado atual e sai")
    args = parser.parse_args()

    if args.list:
        routes = tunnel_routes()
        print(f"charon: {'rodando' if daemon_running() else 'parado'}")
        for conn in parse_ipsec_conf(args.config):
            ip = connection_state(conn, routes)
            print(f"{conn.name:20} {','.join(conn.subnets) or '-':30} "
                  f"{'conectado ' + ip if ip else 'desconectado'}")
        return

    if AppIndicator is None:
        sys.exit(
            "Biblioteca AppIndicator não encontrada.\n"
            "Instale com: sudo apt install gir1.2-ayatanaappindicator3-0.1"
        )
    Tray(args.config, max(1, args.interval))
    Gtk.main()


if __name__ == "__main__":
    main()
