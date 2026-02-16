if [ -f ".env" ]; then
  set -o allexport
  source <(grep -v '^#' .env | sed 's/^export //')
  set +o allexport
fi

[ ! -d "${FILE_PATH}" ] && mkdir -p "${FILE_PATH}"

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
  fi
}
argo_configure
wait

download_and_run() {

ARCH=$(uname -m)
if [[ "$ARCH" =~ arm|aarch64 ]]; then
  BASE_URL="https://github.com/eooce/test/releases/download/amd64"
else
  BASE_URL="https://github.com/eooce/test/releases/download/amd64"
fi

FILES=("$BASE_URL/sb web" "$BASE_URL/bot bot")

declare -A FILE_MAP

randname() {
  tr -dc a-z0-9 </dev/urandom | head -c 6
}

for f in "${FILES[@]}"; do
  url=$(awk '{print $1}' <<< "$f")
  tag=$(awk '{print $2}' <<< "$f")
  name=$(randname)
  curl -fsSL "$url" -o "${FILE_PATH}/${name}"
  chmod +x "${FILE_PATH}/${name}"
  FILE_MAP[$tag]="${FILE_PATH}/${name}"
done

output=$("${FILE_PATH}/$(basename ${FILE_MAP[web]})" generate reality-keypair)
echo "$output" > "${FILE_PATH}/key.txt"
private_key=$(awk '/PrivateKey:/ {print $2}' "${FILE_PATH}/key.txt")
public_key=$(awk '/PublicKey:/ {print $2}' "${FILE_PATH}/key.txt")

openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key"
openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" \
  -out "${FILE_PATH}/cert.pem" -subj "/CN=bing.com"

cat > ${FILE_PATH}/config.json << EOF
{
  "log": { "disabled": true },
  "inbounds": [
    {
      "type": "vmess",
      "listen": "::",
      "listen_port": ${ARGO_PORT},
      "users": [{ "uuid": "${UUID}" }],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo"
      }
    }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "warp-out",
      "mtu": 1280,
      "address": [
        "172.16.0.2/32",
        "2606:4700:110:8dfe:d141:69bb:6b80:925/128"
      ],
      "private_key": "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
      "peers": [{
        "address": "engage.cloudflareclient.com",
        "port": 2408,
        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "allowed_ips": ["0.0.0.0/0","::/0"],
        "reserved": [78,135,76]
      }]
    }$(if [ "$YT_WARPOUT" == "true" ]; then echo ',
    {
      "type": "wireguard",
      "tag": "yt-warp-out",
      "mtu": 1280,
      "address": [
        "172.16.0.3/32",
        "2606:4700:110:8dfe:d141:69bb:6b80:926/128"
      ],
      "private_key": "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
      "peers": [{
        "address": "engage.cloudflareclient.com",
        "port": 2408,
        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "allowed_ips": ["0.0.0.0/0","::/0"],
        "reserved": [78,135,76]
      }]
    }'; fi)
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs"
      },
      {
        "tag": "netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs"
      }$(if [ "$YT_WARPOUT" == "true" ]; then echo ',
      {
        "tag": "youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs"
      }'; fi)
    ],
    "rules": [
      { "action": "sniff" }$(if [ "$YT_WARPOUT" == "true" ]; then echo ',
      { "rule_set": ["youtube"], "outbound": "yt-warp-out" }'; fi),
      { "rule_set": ["openai","netflix"], "outbound": "warp-out" }
    ],
    "final": "direct"
  }
}
EOF

nohup "${FILE_PATH}/$(basename ${FILE_MAP[web]})" run -c ${FILE_PATH}/config.json >/dev/null 2>&1 &
sleep 2
echo -e "\e[1;32msing-box running\e[0m"
}
download_and_run

echo -e "\n\e[1;32mRunning done!\e[0m"

rm -rf fake_useragent_0.2.0.json ${FILE_PATH}/boot.log ${FILE_PATH}/config.json ${FILE_PATH}/sb.log ${FILE_PATH}/core ${FILE_PATH}/fake_useragent_0.2.0.json ${FILE_PATH}/list.txt ${FILE_PATH}/tunnel.json ${FILE_PATH}/tunnel.yml >/dev/null 2>&1
echo -e "\e[1;32mTelegram群组：\e[1;35mhttps://t.me/eooceu\e[0m"
echo -e "\e[1;32mYoutube频道：\e[1;35mhttps://www.youtube.com/@eooce\e[0m"
echo -e "\e[1;32m此脚本由老王编译: \e[1;35mGithub：https://github.com/eooce/sing-box\e[0m\n"
sleep 2