#!/bin/bash
# Instala o StrongSwanSysTray para o usuário atual.
#   ./install.sh            instala atalho no menu e início automático
#   ./install.sh --polkit   também instala a regra polkit (sem senha para ipsec)
#   ./install.sh --remove   remove atalho, início automático e regra polkit
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
EXEC="$DIR/strongswan_systray.py"
APPS="$HOME/.local/share/applications"
AUTOSTART="$HOME/.config/autostart"
DESKTOP="strongswan-systray.desktop"
RULE="/etc/polkit-1/rules.d/49-strongswan-systray.rules"

if [[ "${1:-}" == "--remove" ]]; then
    rm -f "$APPS/$DESKTOP" "$AUTOSTART/$DESKTOP"
    [[ -f "$RULE" ]] && sudo rm -f "$RULE"
    echo "Removido."
    exit 0
fi

if ! python3 -c "import gi; gi.require_version('AyatanaAppIndicator3','0.1'); from gi.repository import AyatanaAppIndicator3" 2>/dev/null; then
    echo "Instalando dependência gir1.2-ayatanaappindicator3-0.1..."
    sudo apt install -y gir1.2-ayatanaappindicator3-0.1
fi

chmod +x "$EXEC"
mkdir -p "$APPS" "$AUTOSTART"
sed -e "s|@EXEC@|$EXEC|" -e "s|@ICON@|$DIR/icons/strongswan-systray-connected.svg|" "$DIR/data/$DESKTOP" > "$APPS/$DESKTOP"
cp "$APPS/$DESKTOP" "$AUTOSTART/$DESKTOP"
echo "Atalho instalado em $APPS e início automático em $AUTOSTART."

if [[ "${1:-}" == "--polkit" ]]; then
    sudo install -m 644 "$DIR/polkit/49-strongswan-systray.rules" "$RULE"
    echo "Regra polkit instalada em $RULE."
fi

echo "Para iniciar agora: $EXEC &"
