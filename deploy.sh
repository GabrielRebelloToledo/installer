#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Deploy de uma imagem nova num service do Swarm.
# Chamado pelo GitHub Actions via SSH.
#
# Uso:
#   ./deploy.sh <slug> <service> <tag> [namespace]
#
# Exemplos:
#   ./deploy.sh homolog        api      sha-1f2a3b4
#   ./deploy.sh cantina        frontend 1.4.5
#   ./deploy.sh producao-food  api      sha-abc123  datatechsistemas
#
# Convenções:
#   <slug>     = nome do stack (cantina, homolog, producao-food, etc)
#   <service>  = api | frontend
#   <tag>      = qualquer tag válida do Docker Hub
#   namespace  = default datatechsistemas
# =========================================================

NAMESPACE="${4:-datatechsistemas}"

if [[ $# -lt 3 ]]; then
  echo "Uso: $0 <slug> <service> <tag> [namespace]" >&2
  exit 1
fi

SLUG="$1"
SERVICE="$2"
TAG="$3"

# Validações simples — defesa contra typo / injection
[[ "$SLUG" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo "slug inválido: $SLUG" >&2; exit 1; }
[[ "$TAG"  =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "tag inválida: $TAG" >&2; exit 1; }

case "$SERVICE" in
  api)      IMAGE_NAME="datatech-api" ;;
  frontend) IMAGE_NAME="datatech-front" ;;
  *)        echo "service inválido: $SERVICE (esperado: api | frontend)" >&2; exit 1 ;;
esac

IMAGE="${NAMESPACE}/${IMAGE_NAME}:${TAG}"
SERVICE_FULL="${SLUG}_${SERVICE}"

echo "→ deploy ${SERVICE_FULL} = ${IMAGE}"

# Confirma que o service existe (evita digitar slug errado e criar service novo silenciosamente)
if ! docker service inspect "$SERVICE_FULL" >/dev/null 2>&1; then
  echo "ERRO: service '$SERVICE_FULL' não existe no Swarm." >&2
  echo "Rode o installer primeiro: bash installer.sh" >&2
  exit 1
fi

# update_config no stack.yml já tem failure_action: rollback. --with-registry-auth
# pra puxar imagens privadas. --detach=false bloqueia até converge ou rollback.
docker service update \
  --image "$IMAGE" \
  --with-registry-auth \
  --detach=false \
  "$SERVICE_FULL"

echo "✔ ${SERVICE_FULL} agora está em ${IMAGE}"

# Mostra resumo
docker service ps --filter "desired-state=running" --format "table {{.Name}}\t{{.Image}}\t{{.CurrentState}}" "$SERVICE_FULL" | head -5
