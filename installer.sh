#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Datatech ERP - Installer (Swarm + Secrets + NPM + Client Stack)
# Docker Hub (pode puxar imagens privadas via PAT)
#
# - Gera infra/infra-npm-stack.yml
# - Sobe infra (Nginx Proxy Manager)
# - Cria secrets v1 do cliente (db_password, jwt_secret, update_hmac, master_key)
# - Gera <HOST_BASE_DIR>/<cliente>/stack.yml (api + frontend + updater)
#
# PADRÕES:
# - API porta interna fixa: 3000
# - FRONT porta interna fixa: 80
# - Dentro do container: /opt/datatech/<cliente>
# =========================================================

# =========================
# Inputs
# =========================
read -rp "Docker Hub namespace [ex: datatechsistemas]: " DOCKERHUB_NS

read -rp "Docker Hub username (para imagens privadas): " DOCKERHUB_USER
read -rsp "Docker Hub Access Token (PAT) (read-only): " DOCKERHUB_TOKEN; echo

read -rp "Base dir no HOST [default /opt/datatech]: " HOST_BASE_DIR
HOST_BASE_DIR="${HOST_BASE_DIR:-/opt/datatech}"

read -rp "Cliente (slug) [ex: clienteA]: " CLIENTE
read -rp "API domain [ex: api.cliente.com]: " API_DOMAIN
read -rp "APP domain [ex: app.cliente.com]: " APP_DOMAIN

read -rp "DB host (Postgres externo) [ex: 10.0.0.10]: " DB_HOST
read -rp "DB port [default 5432]: " DB_PORT
DB_PORT="${DB_PORT:-5432}"
read -rp "DB name: " DB_NAME
read -rp "DB user: " DB_USER
read -rsp "DB password: " DB_PASSWORD; echo

read -rsp "JWT secret: " JWT_SECRET; echo
read -rsp "Updater HMAC secret: " UPDATE_SECRET; echo

read -rp "API version/tag [ex: 1.4.0]: " API_TAG
read -rp "FRONT version/tag [ex: 1.4.0]: " FRONT_TAG
read -rp "UPDATER version/tag [default 1.0.0]: " UPDATER_TAG
UPDATER_TAG="${UPDATER_TAG:-1.0.0}"

# =========================
# Constantes
# =========================
API_PORT="3000"
FRONT_PORT="80"

# Imagens (Docker Hub público)
API_IMAGE="${DOCKERHUB_NS}/datatech-api:${API_TAG}"
FRONT_IMAGE="${DOCKERHUB_NS}/datatech-front:${FRONT_TAG}"
UPDATER_IMAGE="${DOCKERHUB_NS}/datatech-updater:${UPDATER_TAG}"

# Infra
NPM_IMAGE="jc21/nginx-proxy-manager:2.11.3"
INFRA_DIR="infra"
INFRA_FILE="${INFRA_DIR}/infra-npm-stack.yml"
INFRA_STACK_NAME="infra"
PROXY_NET="proxy_net"

# Host paths
HOST_CLIENT_DIR="${HOST_BASE_DIR}/${CLIENTE}"

# Container paths (fixo/padrão)
CONTAINER_BASE_DIR="/opt/datatech"
CONTAINER_CLIENT_DIR="${CONTAINER_BASE_DIR}/${CLIENTE}"

# =========================
# Helpers
# =========================
create_secret () {
  local NAME="$1"
  local VALUE="$2"
  if docker secret ls --format '{{.Name}}' | grep -qx "$NAME"; then
    echo "• Secret já existe: $NAME (skip)"
  else
    printf "%s" "$VALUE" | docker secret create "$NAME" -
    echo "• Secret criado: $NAME"
  fi
}

gen_master_key_b64 () {
  # 32 bytes em base64 (AES-256)
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
  else
    python - <<'PY'
import os, base64
print(base64.b64encode(os.urandom(32)).decode())
PY
  fi
}

echo "• Fazendo login no Docker Hub (para puxar imagens privadas)..."
echo "${DOCKERHUB_TOKEN}" | docker login -u "${DOCKERHUB_USER}" --password-stdin >/dev/null
echo "✔ Login OK"

# =========================
# 1) Swarm
# =========================
if ! docker info 2>/dev/null | grep -q "Swarm: active"; then
  echo "• Inicializando Docker Swarm..."
  docker swarm init
else
  echo "• Swarm já ativo."
fi

# =========================
# 2) proxy_net
# =========================
if ! docker network ls --format '{{.Name}}' | grep -qx "${PROXY_NET}"; then
  echo "• Criando rede overlay ${PROXY_NET}..."
  docker network create --driver overlay --attachable "${PROXY_NET}"
else
  echo "• Rede ${PROXY_NET} já existe."
fi

# =========================
# 3) Gerar e subir INFRA (NPM)
# =========================
mkdir -p "${INFRA_DIR}"

cat > "${INFRA_FILE}" <<EOF
version: "3.8"

services:
  npm:
    image: ${NPM_IMAGE}
    ports:
      - "80:80"
      - "443:443"
      - "81:81"
    volumes:
      - npm_data:/data
      - npm_letsencrypt:/etc/letsencrypt
    networks:
      - ${PROXY_NET}
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

volumes:
  npm_data:
  npm_letsencrypt:

networks:
  ${PROXY_NET}:
    external: true
EOF

echo "✔ Gerado: ${INFRA_FILE}"
echo "• Deploy do Nginx Proxy Manager stack (${INFRA_STACK_NAME})..."
docker stack deploy -c "${INFRA_FILE}" "${INFRA_STACK_NAME}"

# =========================
# 4) Diretórios do cliente no HOST (persistência)
# =========================
mkdir -p "${HOST_CLIENT_DIR}"
mkdir -p "${HOST_CLIENT_DIR}/data/uploads"
mkdir -p "${HOST_CLIENT_DIR}/certs"

# =========================
# 5) Secrets v1 (por cliente)
# =========================
create_secret "${CLIENTE}_db_password_v1" "$DB_PASSWORD"
create_secret "${CLIENTE}_jwt_secret_v1" "$JWT_SECRET"
create_secret "${CLIENTE}_update_hmac_v1" "$UPDATE_SECRET"

MASTER_KEY_B64="$(gen_master_key_b64)"
create_secret "${CLIENTE}_master_key_v1" "$MASTER_KEY_B64"

# =========================
# 6) Gerar stack do cliente (salva no HOST_CLIENT_DIR)
# =========================
cat > "${HOST_CLIENT_DIR}/stack.yml" <<EOF
version: "3.8"

services:
  api:
    image: ${API_IMAGE}
    environment:
      SPRING_PROFILES_ACTIVE: prod
      CLIENTE: ${CLIENTE}

      SERVER_PORT: "${API_PORT}"

      DB_HOST: ${DB_HOST}
      DB_PORT: "${DB_PORT}"
      DB_NAME: ${DB_NAME}
      DB_USER: ${DB_USER}

      DB_PASSWORD_FILE: /run/secrets/db_password
      JWT_SECRET_FILE: /run/secrets/jwt_secret
      MASTER_KEY_FILE: /run/secrets/master_key

      # PADRÃO dentro do container
      STORAGE_BASE: ${CONTAINER_BASE_DIR}
      RELATORIOS_PATH: ${CONTAINER_CLIENT_DIR}/data/uploads

      UPDATE_URL: http://updater:9100/update

    secrets:
      - source: ${CLIENTE}_db_password_v1
        target: db_password
      - source: ${CLIENTE}_jwt_secret_v1
        target: jwt_secret
      - source: ${CLIENTE}_master_key_v1
        target: master_key
      - source: ${CLIENTE}_update_hmac_v1
        target: update_hmac

    volumes:
      # HOST -> container sempre em /opt/datatech/<cliente>
      - ${HOST_CLIENT_DIR}:${CONTAINER_CLIENT_DIR}

    networks:
      - ${PROXY_NET}
      - ${CLIENTE}_net

    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

  frontend:
    image: ${FRONT_IMAGE}
    environment:
      API_BASE_URL: "https://${API_DOMAIN}"
    networks:
      - ${PROXY_NET}
      - ${CLIENTE}_net
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

  updater:
    image: ${UPDATER_IMAGE}
    environment:
      CLIENTE: ${CLIENTE}
      STACK_NAME: ${CLIENTE}

      API_HEALTH_URL: "http://api:${API_PORT}/actuator/health"
      FRONT_HEALTH_URL: "http://frontend:${FRONT_PORT}/"

      MAX_SKEW_SECONDS: "120"
      HEALTH_RETRIES: "30"
      HEALTH_INTERVAL_MS: "2000"

    secrets:
      - source: ${CLIENTE}_update_hmac_v1
        target: update_hmac

    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ${HOST_CLIENT_DIR}:${CONTAINER_CLIENT_DIR}

    networks:
      - ${CLIENTE}_net

    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

networks:
  ${CLIENTE}_net:
    driver: overlay

  ${PROXY_NET}:
    external: true

secrets:
  ${CLIENTE}_db_password_v1:
    external: true
  ${CLIENTE}_jwt_secret_v1:
    external: true
  ${CLIENTE}_master_key_v1:
    external: true
  ${CLIENTE}_update_hmac_v1:
    external: true
EOF

# =========================
# 7) Deploy do cliente
# =========================
docker stack deploy --with-registry-auth -c "${HOST_CLIENT_DIR}/stack.yml" "${CLIENTE}"

echo
echo "✔ Cliente ${CLIENTE} instalado."
echo
echo "HOST_BASE_DIR: ${HOST_BASE_DIR}"
echo "HOST_CLIENT_DIR: ${HOST_CLIENT_DIR}"
echo "CONTAINER_CLIENT_DIR: ${CONTAINER_CLIENT_DIR}"
echo
echo "Imagens:"
echo " - API:     ${API_IMAGE}"
echo " - FRONT:   ${FRONT_IMAGE}"
echo " - UPDATER: ${UPDATER_IMAGE}"
echo
echo "Arquivos do cliente:"
echo " - Stack:   ${HOST_CLIENT_DIR}/stack.yml"
echo " - Uploads: ${HOST_CLIENT_DIR}/data/uploads"
echo " - Certs:   ${HOST_CLIENT_DIR}/certs"
echo
echo "NPM UI: http://<IP_DO_SERVIDOR>:81 (login inicial: admin@example.com / changeme)"
echo
echo "Configure no NPM (Proxy Hosts) e gere SSL (HTTP-01):"
echo " - APP: ${APP_DOMAIN}"
echo "     Forward Hostname: ${CLIENTE}_frontend"
echo "     Forward Port:     80"
echo
echo " - API: ${API_DOMAIN}"
echo "     Forward Hostname: ${CLIENTE}_api"
echo "     Forward Port:     3000"
echo
echo "IMPORTANTE: DNS de ${APP_DOMAIN} e ${API_DOMAIN} devem apontar para o IP público do servidor."
echo "           Portas 80 e 443 precisam estar abertas para emissão do certificado."
