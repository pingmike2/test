#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

# -------------------- Load .env --------------------
if [ -f ".env" ]; then
  set -o allexport
  source <(grep -v '^#' .env | sed 's/^export //' )
  set +o allexport
fi

# -------------------- Prepare working dir --------------------
[ ! -d "${FILE_PATH}" ] && mkdir -p "${FILE_PATH}"

# -------------------- Delete old nodes --------------------
delete_old_nodes() {
  [[ -z $UPLOAD_URL || ! -f "${FILE_PATH}/sub.txt" ]] && return
  old_nodes=$(base64 -d "${FILE_PATH}/sub.txt" | grep -E '(vless|vmess|trojan|hysteria2|tuic)://')
  [[ -z $old_nodes ]] && return

  json_data='{"nodes": ['
  for node in $old_nodes; do
      json_data+="\"$node\","
  done
  json_data=${json_data%,}  
  json_data+=']}'

  curl -X DELETE "$UPLOAD_URL/api/delete-nodes" \
        -H "Content-Type: application/json" \
        -d "$json_data" > /dev/null 2>&1
}
delete_old_nodes

rm -rf boot.log config.json tunnel.json tunnel.yml "${FILE_PATH}/sub.txt" >/dev/null 2>&1

# -------------------- Argo Tunnel Configuration --------------------
argo_configure() {
  if [ "$DISABLE_ARGO" == 'true' ]; then
    echo -e "\e[1;32mDisable argo tunnel\e[0m"
    return
  fi

  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
    echo -e "\e[1;32mARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels\e[0m"   
    return
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > ${FILE_PATH}/tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: ${FILE_PATH}/tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$ARGO_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    echo -e "\e[1;32mUsing token connect to tunnel,please set $ARGO_PORT in cloudflare tunnel\e[0m"
  fi
}
argo_configure
wait

# -------------------- Download binaries & Reality keys --------------------
download_and_run() {
  ARCH=$(uname -m)
  FILE_INFO=()

  case "$ARCH" in
    arm|arm64|aarch64)
      BASE_URL="https://github.com/eooce/test/releases/download/arm64"
      ;;
    amd64|x86_64|x86)
      BASE_URL="https://github.com/eooce/test/releases/download/amd64"
      ;;
    s390x|s390)
      BASE_URL="https://github.com/eooce/test/releases/download/s390"
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  # 默认下载 sbx, bot, web
  FILE_INFO=("$BASE_URL/sbx sbx" "$BASE_URL/bot bot" "$BASE_URL/web web")

  # Nezha v1/v0 自动判断
  if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
    FILE_INFO+=("$BASE_URL/agent npm")
  elif [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
    FILE_INFO+=("$BASE_URL/v1 php")
    NEZHA_TLS=$(case "${NEZHA_SERVER##*:}" in 443|8443|2096|2087|2083|2053) echo -n true;; *) echo -n false;; esac)
    cat > "${FILE_PATH}/config.yaml" << EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NEZHA_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF
  else
    echo -e "\e[1;35mskip download nezha\e[0m"
  fi

  declare -A FILE_MAP
  generate_random_name() {
      local chars=abcdefghijklmnopqrstuvwxyz1234567890
      local name=""
      for i in {1..6}; do
          name="$name${chars:RANDOM%${#chars}:1}"
      done
      echo "$name"
  }

  download_file() {
      local URL=$1
      local NEW_FILENAME=$2
      if command -v curl >/dev/null 2>&1; then
          curl -L -sS -o "$NEW_FILENAME" "$URL"
      elif command -v wget >/dev/null 2>&1; then
          wget -q -O "$NEW_FILENAME" "$URL"
      else
          echo -e "\e[1;33mNeither curl nor wget available\e[0m"
          exit 1
      fi
      chmod +x "$NEW_FILENAME"
  }

  for entry in "${FILE_INFO[@]}"; do
      URL=$(echo "$entry" | cut -d ' ' -f 1)
      RANDOM_NAME=$(generate_random_name)
      NEW_FILENAME="${FILE_PATH}/$RANDOM_NAME"
      download_file "$URL" "$NEW_FILENAME"
      FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
  done

  # -------------------- Reality Keys --------------------
  if [ -f "${FILE_PATH}/key.txt" ]; then
    private_key=$(grep "PrivateKey:" "${FILE_PATH}/key.txt" | awk '{print $2}')
    public_key=$(grep "PublicKey:" "${FILE_PATH}/key.txt" | awk '{print $2}')
  else
    output=$("${FILE_PATH}/$(basename ${FILE_MAP[web]})" generate reality-keypair)
    echo "$output" > "${FILE_PATH}/key.txt"
    private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
  fi

  # -------------------- TLS Certificate --------------------
  if command -v openssl >/dev/null 2>&1; then
      openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key"
      openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -subj "/CN=bing.com"
  else
      cat > "${FILE_PATH}/private.key" << 'EOF'
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
EOF
      cat > "${FILE_PATH}/cert.pem" << 'EOF'
-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
EOF

  fi

  # -------------------- Sing-box config (支持所有协议) --------------------
  "${FILE_PATH}/$(basename ${FILE_MAP[web]})" run -c "${FILE_PATH}/config.json" >/dev/null 2>&1 &

  # -------------------- Nezha --------------------
  if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
    if [[ -f "${FILE_PATH}/$(basename ${FILE_MAP[npm]})" ]]; then
      nohup "${FILE_PATH}/$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} >/dev/null 2>&1 &
    elif [[ -f "${FILE_PATH}/$(basename ${FILE_MAP[php]})" ]]; then
      nohup "${FILE_PATH}/$(basename ${FILE_MAP[php]})" -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &
    fi
  fi
}
download_and_run

# -------------------- Subscription --------------------
IP=$(curl -sm 3 ipv4.ip.sb || curl -sm 2 api.ipify.org || { ipv6=$(curl -sm 2 ipv6.ip.sb); echo "[$ipv6]"; } || echo "XXX")
VMESS="{ \"v\": \"2\", \"ps\": \"${NAME:-$IP}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${ARGO_DOMAIN}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${ARGO_DOMAIN}\", \"fp\": \"chrome\"}"

echo "vmess://$(echo "$VMESS" | base64 | tr -d '\n')" > ${FILE_PATH}/sub.txt

# 这里可继续追加 tuic/hysteria2/reality/anytls/socks5/anyreality

echo -e "\n\e[1;32mSubscription generated at ${FILE_PATH}/sub.txt\e[0m"

# -------------------- Upload nodes --------------------
uplod_nodes() {
  [[ -z $UPLOAD_URL || ! -f "${FILE_PATH}/sub.txt" ]] && return
  nodes=$(base64 -d "${FILE_PATH}/sub.txt" | grep -E '(vless|vmess|trojan|hysteria2|tuic)://')
  [[ -z $nodes ]] && return
  json_data='{"nodes": ['
  for node in $nodes; do
      json_data+="\"$node\","
  done
  json_data=${json_data%,}
  json_data+=']}'
  curl -X POST "$UPLOAD_URL/api/add-nodes" -H "Content-Type: application/json" -d "$json_data" >/dev/null 2>&1
}
uplod_nodes

# -------------------- Telegram --------------------
send_telegram() {
  [ -z "$BOT_TOKEN" ] && return
  [ ! -f "${FILE_PATH}/sub.txt" ] && return
  MESSAGE=$(cat "${FILE_PATH}/sub.txt")
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
      -d "chat_id=${CHAT_ID}&text=${MESSAGE}&parse_mode=Markdown" >/dev/null
}
send_telegram

echo -e "\n\e[1;32mAll tasks finished!\e[0m"