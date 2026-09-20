#!/usr/bin/env bash
# Guarda um segredo colado NO TERMINAL, sem passar pelo chat.
#
#   ./scripts/guardar-segredo.sh maven-token
#   (cole o que o site mostrou — XML, JSON, KEY=VALUE ou o valor puro — e tecle Ctrl-D)
#
# O arquivo vai para ~/.config/catalisa/<nome>.env com permissão 600. O script
# entende o formato do Maven Central (<server><username>…), do npm, e pares
# KEY=VALUE; qualquer outra coisa é guardada como valor único.
set -euo pipefail

NOME="${1:-}"
if [ -z "$NOME" ]; then
  echo "uso: $0 <nome>   (ex.: maven-token, npm-token, nuget-key)" >&2
  exit 1
fi

DESTINO=~/.config/catalisa/"$NOME".env
mkdir -p ~/.config/catalisa
umask 077

echo "Cole o conteúdo e tecle Ctrl-D:" >&2
ENTRADA="$(cat)"

extrair() { printf '%s' "$ENTRADA" | grep -oP "(?<=<$1>)[^<]+" | head -1; }

USUARIO="$(extrair username || true)"
SENHA="$(extrair password || true)"

{
  if [ -n "$USUARIO" ] && [ -n "$SENHA" ]; then
    printf 'USERNAME=%s\nPASSWORD=%s\n' "$USUARIO" "$SENHA"
  elif printf '%s' "$ENTRADA" | grep -qE '^[A-Z_][A-Z0-9_]*='; then
    printf '%s\n' "$ENTRADA"
  else
    printf 'VALUE=%s\n' "$(printf '%s' "$ENTRADA" | tr -d '[:space:]')"
  fi
} > "$DESTINO"

chmod 600 "$DESTINO"
echo "guardado em $DESTINO (600), chaves: $(grep -oE '^[A-Z_]+' "$DESTINO" | tr '\n' ' ')" >&2
