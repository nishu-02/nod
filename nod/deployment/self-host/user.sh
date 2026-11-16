#!/bin/sh
# Usage: sh user.sh <name> <compose args...>   e.g. sh user.sh alice up -d --build --wait
set -eu
cd "$(dirname "$0")"
umask 077
name=${1:?Usage: sh user.sh <name> <compose args...>}
shift
case "$name" in *[!a-z0-9]*) echo 'Name must be lowercase letters and digits.' >&2; exit 1 ;; esac
env=users/$name.env
if [ ! -e "$env" ]; then
  mkdir -p users
  # ponytail: port = 4311 + existing user count; set PORT by hand if a user is ever deleted
  port=$((4311 + $(find users -name '*.env' | wc -l)))
  {
    sed '/^COMPOSE_PROJECT_NAME=/d; /^PORT=/d; /^NOD_PUBLIC_URL=/d; /^NOD_AUTH_TOKEN=/d; /^NOD_VAULT_KEY=/d; /^NOD_POSTGRES_PASSWORD=/d' .env.example
    printf 'COMPOSE_PROJECT_NAME=nod-%s\n' "$name"
    printf 'PORT=%s\n' "$port"
    # Every user shares the gateway's origin; gateway.mjs routes by login
    printf 'NOD_PUBLIC_URL=%s\n' "${GATEWAY_URL:-http://localhost:4300}"
    printf 'NOD_AUTH_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'NOD_VAULT_KEY=%s\n' "$(openssl rand -base64 32)"
    printf 'NOD_POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)"
  } > "$env"
  echo "Created $env on port $port." >&2
fi
NOD_ENV_FILE=$env exec docker compose --file compose.yaml --file compose.selinux.yaml --env-file "$env" "$@"
