#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

config_file="config.ini"
if [[ ! -r "$config_file" ]]; then
    echo "Erreur : fichier de configuration illisible : $config_file" >&2
    exit 1
fi

host="localhost"
port=""
while IFS='=' read -r key value; do
    key="${key//[[:space:]]/}"
    value="${value//[[:space:]]/}"
    case "$key" in
        Host) host=$value ;;
        Port) port=$value ;;
    esac
done < <(grep -E '^[[:space:]]*(Host|Port)[[:space:]]*=' "$config_file" | sed 's/#.*//; s/;.*//')

if [[ "$host" != "localhost" && "$host" != "127.0.0.1" ]]; then
    echo "Erreur : le serveur est limité à localhost/127.0.0.1." >&2
    exit 1
fi
if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || ((10#$port < 1024 || 10#$port > 65535)); then
    echo "Erreur : Port invalide dans $config_file (valeur attendue : 1024-65535)." >&2
    exit 1
fi
port=$((10#$port))

server="bin/linux-x86_64/local-audit-server"
if [[ ! -x "$server" ]]; then
    echo "Erreur : serveur Linux précompilé absent : $server" >&2
    echo "Consultez README.md pour le reconstruire depuis tools/local_server.rs." >&2
    exit 1
fi

echo "Démarrage local sur http://127.0.0.1:$port"
exec "$server" "$PWD" "$port"
