#!/usr/bin/env bash
# Target selector — bring up exactly ONE vulnerable site at a time, published to
# http://localhost:8000.  ./select.sh [neuralnotes|chatforge|promptvault|down|status]
set -euo pipefail
cd "$(dirname "$0")"
CF="docker-compose.targets.yml"
declare -A PORT=( [neuralnotes]=5000 [chatforge]=3100 [promptvault]=8080 )
case "${1:-status}" in
  neuralnotes|chatforge|promptvault)
    site="$1"
    docker rm -f apts-target-neuralnotes apts-target-chatforge apts-target-promptvault >/dev/null 2>&1 || true
    docker compose -f "$CF" --profile "$site" up -d --build
    echo
    echo "ACTIVE: $site   your PC -> http://localhost:8000   internal -> http://$site:${PORT[$site]}"
    ;;
  down)   docker rm -f apts-target-neuralnotes apts-target-chatforge apts-target-promptvault >/dev/null 2>&1; echo "all targets down" ;;
  status) docker compose -f "$CF" ps ;;
  *) echo "usage: ./select.sh [neuralnotes|chatforge|promptvault|down|status]"; exit 1 ;;
esac
