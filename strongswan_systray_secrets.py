#!/usr/bin/env python3
"""Helper privilegiado do StrongSwanSysTray: grava credenciais de uma conexão.

Executado como root via pkexec. Recebe um JSON pelo stdin (as senhas nunca
passam pela linha de comando) e:

  * grava PSK e usuário/senha (XAUTH ou EAP) num bloco gerenciado por conexão
    em /etc/ipsec.secrets, removendo linhas antigas que conflitem;
  * atualiza xauth_identity / eap_identity da conexão em /etc/ipsec.conf;
  * faz backup dos arquivos alterados (*.systray.bak, permissão 600);
  * aplica as mudanças no charon (ipsec rereadsecrets / ipsec update).

Entrada (campos vazios = manter o valor atual):
  {"conn": "...", "remote_ids": ["..."], "user_type": "XAUTH"|"EAP"|"",
   "user_key": "xauth_identity"|"eap_identity", "identity": "...",
   "old_identity": "...", "password": "...", "psk": "...",
   "config": "/etc/ipsec.conf", "secrets": "/etc/ipsec.secrets"}

Saída: JSON {"ok": bool, "message": str}
"""

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SECRET_RE = re.compile(r"^\s*(?P<ids>[^#\"]*?)\s*:\s*(?P<type>PSK|XAUTH|EAP)\s+(?P<value>.+?)\s*$")
NAME_RE = re.compile(r"^[A-Za-z0-9._@%+-]+$")
IDENTITY_RE = re.compile(r"^[^\s\"#:]+$")


def fail(message: str) -> None:
    print(json.dumps({"ok": False, "message": message}))
    sys.exit(1)


def quote(value: str) -> str:
    """Formata um segredo; usa base64 (0s...) se houver caracteres problemáticos."""
    if any(c in value for c in '"\\\n\r'):
        return "0s" + base64.b64encode(value.encode()).decode()
    return f'"{value}"'


def write_atomic(path: str, lines: list[str], mode: int) -> None:
    if os.path.exists(path):
        backup = path + ".systray.bak"
        shutil.copy2(path, backup)
        os.chmod(backup, 0o600)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".systray-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def update_secrets(path: str, req: dict) -> None:
    conn = req["conn"]
    begin = f"# BEGIN strongswan-systray: {conn}\n"
    end = f"# END strongswan-systray: {conn}\n"
    remote_ids = [r for r in req.get("remote_ids", []) if r]
    user_type = req.get("user_type", "")
    identity = req.get("identity", "")
    old_identity = req.get("old_identity", "") or identity

    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        lines = []
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"

    # separa o bloco gerenciado desta conexão do resto do arquivo
    block: list[str] = []
    rest: list[str] = []
    inside = False
    for line in lines:
        if line == begin:
            inside = True
        elif line == end and inside:
            inside = False
        elif inside:
            block.append(line)
        else:
            rest.append(line)

    def find(source: list[str], kind: str, ids: str | None = None) -> str | None:
        for line in source:
            m = SECRET_RE.match(line)
            if m and m["type"] == kind and (ids is None or m["ids"].split() == ids.split()):
                return m["value"]
        return None

    # valores atuais (para "deixe em branco para manter")
    psk_value = quote(req["psk"]) if req.get("psk") else find(block, "PSK")
    user_value = None
    if user_type:
        if req.get("password"):
            user_value = quote(req["password"])
        else:
            user_value = (find(block, user_type, old_identity)
                          or find(rest, user_type, old_identity))

    # remove do resto do arquivo as linhas que conflitariam com o bloco
    def conflicts(line: str) -> bool:
        m = SECRET_RE.match(line)
        if not m:
            return False
        ids = m["ids"].split()
        if m["type"] == "PSK" and psk_value and any(r in ids for r in remote_ids):
            return True
        if user_type and user_value and m["type"] == user_type and ids in ([identity], [old_identity]):
            return True
        return False

    rest = [ln for ln in rest if not conflicts(ln)]

    new_block = []
    if psk_value:
        selector = " ".join(["%any", *remote_ids]) if remote_ids else ""
        new_block.append(f"{selector} : PSK {psk_value}\n".lstrip())
    if user_type and user_value:
        new_block.append(f"{identity} : {user_type} {user_value}\n")

    if new_block:
        if rest and rest[-1].strip():
            rest.append("\n")
        rest += [begin, *new_block, end]

    write_atomic(path, rest, 0o600)


def update_config(path: str, conn: str, key: str, identity: str) -> bool:
    """Define key=identity na seção 'conn <conn>'. Retorna True se mudou."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()

    start = None
    for i, line in enumerate(lines):
        parts = line.split("#", 1)[0].split()
        if not line[:1].isspace() and parts[:2] == ["conn", conn]:
            start = i
            break
    if start is None:
        fail(f"Conexão '{conn}' não encontrada em {path}")

    stop = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.strip() and not line[:1].isspace() and not line.lstrip().startswith("#"):
            stop = i
            break

    key_re = re.compile(rf"^(\s+){re.escape(key)}\s*=\s*(.*?)\s*$")
    for i in range(start + 1, stop):
        m = key_re.match(lines[i].split("#", 1)[0].rstrip("\n"))
        if m:
            if m.group(2).strip('"') == identity:
                return False
            lines[i] = f"{m.group(1)}{key}={identity}\n"
            break
    else:
        lines.insert(start + 1, f"    {key}={identity}\n")

    write_atomic(path, lines, os.stat(path).st_mode & 0o777)
    return True


def charon_running() -> bool:
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                if fh.read().strip() == "charon":
                    return True
        except OSError:
            continue
    return False


def main() -> None:
    if os.geteuid() != 0:
        fail("Este helper precisa rodar como root (via pkexec).")
    try:
        req = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        fail(f"Entrada inválida: {exc}")

    conn = req.get("conn", "")
    if not NAME_RE.match(conn):
        fail("Nome de conexão inválido")
    user_type = req.get("user_type", "")
    if user_type not in ("", "XAUTH", "EAP"):
        fail("Tipo de usuário inválido")
    identity = req.get("identity", "")
    if user_type and not IDENTITY_RE.match(identity):
        fail("Usuário inválido (não use espaços, aspas, ':' ou '#')")
    if req.get("old_identity") and not IDENTITY_RE.match(req["old_identity"]):
        fail("Usuário anterior inválido")
    for rid in req.get("remote_ids", []):
        if not IDENTITY_RE.match(rid):
            fail(f"Identidade remota inválida: {rid}")

    config = req.get("config", "/etc/ipsec.conf")
    secrets = req.get("secrets", "/etc/ipsec.secrets")

    try:
        update_secrets(secrets, req)
        conf_changed = False
        if user_type:
            key = req.get("user_key") or ("xauth_identity" if user_type == "XAUTH" else "eap_identity")
            if key not in ("xauth_identity", "eap_identity"):
                fail("Chave de identidade inválida")
            conf_changed = update_config(config, conn, key, identity)
    except OSError as exc:
        fail(f"Erro ao gravar: {exc}")

    applied = ""
    if charon_running():
        subprocess.run(["ipsec", "rereadsecrets"], capture_output=True)
        if conf_changed:
            subprocess.run(["ipsec", "update"], capture_output=True)
        applied = " e aplicadas ao strongSwan"
    print(json.dumps({
        "ok": True,
        "message": f"Credenciais de '{conn}' salvas{applied}. "
                   "Valem a partir da próxima conexão.",
    }))


if __name__ == "__main__":
    main()
