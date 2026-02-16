if [ -f ".env" ]; then
  set -o allexport 
  source <(grep -v '^#' .env | sed 's/^export //' )
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
  else
    echo -e "\e[1;32mUsing token connect to tunnel,please set $ARGO_PORT in cloudflare tunnel\e[0m"
  fi
}
argo_configure
wait

download_and_run() {
ARCH=$(uname -m) && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/arm64"
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/amd64"
elif [ "$ARCH" == "s390x" ] || [ "$ARCH" == "s390" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/s390"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
FILE_INFO=("$BASE_URL/sb web" "$BASE_URL/bot bot")

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
        echo -e "\e[1;32mDownloaded $NEW_FILENAME by curl\e[0m"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$NEW_FILENAME" "$URL"
        echo -e "\e[1;32mDownloaded $NEW_FILENAME by wget\e[0m"
    else
        echo -e "\e[1;33mNeither curl nor wget is available for downloading\e[0m"
        exit 1
    fi
}
for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="${FILE_PATH}/$RANDOM_NAME"
    
    download_file "$URL" "$NEW_FILENAME"
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

# 检查reality密钥文件是否存在，存在则读取，否则生成新的
if [ -f "${FILE_PATH}/key.txt" ]; then
    # 尝试读取密钥
    private_key=$(grep "PrivateKey:" "${FILE_PATH}/key.txt" | awk '{print $2}')
    public_key=$(grep "PublicKey:" "${FILE_PATH}/key.txt" | awk '{print $2}')
    
    if [ -n "$private_key" ] && [ -n "$public_key" ]; then
        true
    else
        # 读取失败，重新生成
        output=$("${FILE_PATH}/$(basename ${FILE_MAP[web]})" generate reality-keypair)
        echo "$output" > "${FILE_PATH}/key.txt"
        private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
        public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
    fi
else
    output=$("${FILE_PATH}/$(basename ${FILE_MAP[web]})" generate reality-keypair)
    echo "$output" > "${FILE_PATH}/key.txt"
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
fi

# 生成证书和私钥
if command -v openssl >/dev/null 2>&1; then
    openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key"
    openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -subj "/CN=bing.com"
else
    # 创建私钥文件
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

    # 创建证书文件
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

  cat > ${FILE_PATH}/config.json << EOF
{
    "log": {
      "disabled": true,
      "level": "error",
      "timestamp": true
    },
    "inbounds": [
    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": ${ARGO_PORT},
        "users": [
        {
          "uuid": "${UUID}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }$(if [ "$TUIC_PORT" != "" ]; then echo ',
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "::",
      "listen_port": '${TUIC_PORT}',
      "users": [
        {
          "uuid": "'${UUID}'",
          "password": "admin"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "'${FILE_PATH}'/cert.pem",
        "key_path": "'${FILE_PATH}'/private.key"
      }
    }'; fi)$(if [ "$HY2_PORT" != "" ]; then echo ',
    {
      "tag": "hysteria2-in",
      "type": "hysteria2",
      "listen": "::",
      "listen_port": '${HY2_PORT}',
        "users": [
          {
             "password": "'${UUID}'"
          }
      ],
      "masquerade": "https://bing.com",
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "'${FILE_PATH}'/cert.pem",
            "key_path": "'${FILE_PATH}'/private.key"
          }
      }'; fi)$(if [ "$REALITY_PORT" != "" ]; then echo ',
      {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "::",
        "listen_port": '${REALITY_PORT}',
          "users": [
              {
                "uuid": "'$UUID'",
                "flow": "xtls-rprx-vision"
              }
          ],
          "tls": {
              "enabled": true,
              "server_name": "www.nazhumi.com",
              "reality": {
                  "enabled": true,
                  "handshake": {
                      "server": "www.nazhumi.com",
                      "server_port": 443
                  },
                  "private_key": "'$private_key'",
                  "short_id": [
                    ""
                  ]
              }
          }
      }'; fi)$(if [ "$S5_PORT" != "" ]; then echo ',
    {
      "tag": "socks5-in",
      "type": "socks",
      "listen": "::",
      "listen_port": '$S5_PORT',
      "users": [
        {
          "username": "'${UUID:0:8}'",
          "password": "'${UUID: -12}'"
        }
      ]
    }'; fi)$(if [ "$ANYTLS_PORT" != "" ]; then echo ',
    {
      "tag": "anytls-in",
      "type": "anytls",
      "listen": "::",
      "listen_port": '$ANYTLS_PORT',
      "users": [
        {
          "password": "'${UUID}'"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "'${FILE_PATH}'/cert.pem",
        "key_path": "'${FILE_PATH}'/private.key"
      }
    }'; fi)$(if [ "$ANYREALITY_PORT" != "" ]; then echo ',
    {
      "tag": "anyreality-in",
      "type": "anytls",
      "listen": "::",
      "listen_port": '$ANYREALITY_PORT',
      "users": [
        {
          "password": "'${UUID}'"
        }
      ],
      "padding_scheme": [
        "stop=8",
        "0=30-30",
        "1=100-400",
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
        "3=9-9,500-1000",
        "4=500-1000",
        "5=500-1000",
        "6=500-1000",
        "7=500-1000"
      ],
      "tls": {
          "enabled": true,
          "server_name": "www.nazhumi.com",
          "reality": {
              "enabled": true,
              "handshake": {
                  "server": "www.nazhumi.com",
                  "server_port": 443
              },
              "private_key": "'$private_key'",
              "short_id": [
                ""
              ]
          }
      }
    }'; fi)
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
      "peers": [
        {
          "address": "engage.cloudflareclient.com",
          "port": 2408,
          "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "allowed_ips": [
            "0.0.0.0/0",
            "::/0"
          ],
          "reserved": [
            78,
            135,
            76
          ]
        }
      ]
    }
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
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs",
        "download_detour": "direct"
      },
      {
        "tag": "netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": ["openai", "netflix"], "outbound": "warp-out" }
    ],
    "final": "direct"
  }
}
EOF

if [ -e "${FILE_PATH}/$(basename ${FILE_MAP[web]})" ]; then
    nohup "${FILE_PATH}/$(basename ${FILE_MAP[web]})" run -c ${FILE_PATH}/config.json >/dev/null 2>&1 &
    sleep 2
    echo -e "\e[1;32m$(basename ${FILE_MAP[web]}) is running\e[0m"
fi

if [ "$DISABLE_ARGO" == 'false' ]; then
  if [ -e "${FILE_PATH}/$(basename ${FILE_MAP[bot]})" ]; then
      if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
        args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
      elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
        args="tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run"
      else
        args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:$ARGO_PORT"
      fi
      nohup "${FILE_PATH}/$(basename ${FILE_MAP[bot]})" $args >/dev/null 2>&1 &
      sleep 2
      echo -e "\e[1;32m$(basename ${FILE_MAP[bot]}) is running\e[0m" 
  fi
fi

if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "${FILE_PATH}/$(basename ${FILE_MAP[npm]})" ]; then
      tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
      [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]] && NEZHA_TLS="--tls" || NEZHA_TLS=""
      export TMPDIR=$(pwd)
      nohup "${FILE_PATH}/$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
      sleep 2
      echo -e "\e[1;32m$(basename ${FILE_MAP[npm]}) is running\e[0m"
    fi
elif [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "${FILE_PATH}/$(basename ${FILE_MAP[php]})" ]; then
      nohup "${FILE_PATH}/$(basename ${FILE_MAP[php]})" -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &
      echo -e "\e[1;32m$(basename ${FILE_MAP[php]}) is running\e[0m"
    fi
else
    echo -e "\e[1;35mNEZHA variable is empty, skip running\e[0m"
fi

for key in "${!FILE_MAP[@]}"; do
    if [ -e "${FILE_PATH}/$(basename ${FILE_MAP[$key]})" ]; then
        rm -rf "${FILE_PATH}/$(basename ${FILE_MAP[$key]})" >/dev/null 2>&1
    fi
done
}
download_and_run

get_argodomain() {
if [ "$DISABLE_ARGO" == 'false' ]; then
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    local retry=0
    local max_retries=8
    local argodomain=""
    while [[ $retry -lt $max_retries ]]; do
      ((retry++))
      argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' ${FILE_PATH}/boot.log)
      if [[ -n $argodomain ]]; then
        break
      fi
      sleep 1
    done
    echo "$argodomain"
  fi
fi
}

send_telegram() {
  [ -f "${FILE_PATH}/sub.txt" ] || return
  MESSAGE=$(cat "${FILE_PATH}/sub.txt")
  LOCAL_MESSAGE="*${NAME}节点推送通知*\`\`\`${MESSAGE}\`\`\`"
  BOT_MESSAGE="<b>${NAME}节点推送通知</b>\n<pre>${MESSAGE}</pre>"
  if [ -n "${BOT_TOKEN}" ] && [ -n "${CHAT_ID}" ]; then
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
      -d "chat_id=${CHAT_ID}&text=${LOCAL_MESSAGE}&parse_mode=Markdown" > /dev/null

  elif [ -n "${CHAT_ID}" ]; then
    curl -s -X POST "http://api.tg.gvrander.eu.org/api/notify" \
      -H "Authorization: Bearer eJWRgxC4LcznKLiUiDoUsw@nMgDBCCSUk6Iw0S9Pbs" \
      -H "Content-Type: application/json" \
      -d "$(printf '{"chat_id": "%s", "message": "%s"}' "${CHAT_ID}" "${BOT_MESSAGE}")" > /dev/null
  else
    echo -e "\n\e[1;35mTG variable is empty,skip sent\e[0m"
    return
  fi

  if [ $? -eq 0 ]; then
    echo -e "\n\e[1;32mNodes sent to TG successfully\e[0m"
  else
    echo -e "\n\e[1;31mFailed to send nodes to TG\e[0m"
  fi
}

uplod_nodes() {
    [[ -z $UPLOAD_URL || ! -f "${FILE_PATH}/list.txt" ]] && return
    content=$(cat ${FILE_PATH}/list.txt)
    nodes=$(echo "$content" | grep -E '(vless|vmess|trojan|hysteria2|tuic)://')
    [[ -z $nodes ]] && return
    nodes=($nodes)
    json_data='{"nodes": ['
    for node in "${nodes[@]}"; do
        json_data+="\"$node\","
    done
    json_data=${json_data%,}
    json_data+=']}'

    curl -X POST "$UPLOAD_URL/api/add-nodes" \
         -H "Content-Type: application/json" \
         -d "$json_data" > /dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        echo -e "\033[1;32mNodes uploaded successfully\033[0m"
    else
        echo -e "\033[1;31mFailed to upload nodes\033[0m"
    fi
}

argodomain=$(get_argodomain)
[ "$DISABLE_ARGO" == 'false' ] && echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m\n"
IP=$(curl -sm 3 ipv4.ip.sb || curl -sm 2 api.ipify.org || { ipv6=$(curl -sm 2 ipv6.ip.sb); echo "[$ipv6]"; } || echo "XXX")
ISP=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" | tr -d '\n' | awk -F\" '{c="";i="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="isp")i=$(x+2)};if(c&&i)print c"-"i}' | sed 's/ /_/g' || curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://ipapi.co/json" | tr -d '\n' | awk -F\" '{c="";o="";for(x=1;x<=NF;x++){if($x=="country_code")c=$(x+2);if($x=="org")o=$(x+2)};if(c&&o)print c"-"o}' | sed 's/ /_/g' || echo "unknown")
costom_name() { if [ -n "$NAME" ]; then echo "${NAME}_${ISP}"; else echo "${ISP}"; fi; }

VMESS="{ \"v\": \"2\", \"ps\": \"$(costom_name)\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"chrome\"}"

if [ "$DISABLE_ARGO" == 'false' ]; then
cat > ${FILE_PATH}/list.txt <<EOF
vmess://$(echo "$VMESS" | base64 | tr -d '\n')
EOF
fi

if [ "$TUIC_PORT" != "" ]; then
  echo -e "\ntuic://${UUID}:admin@${IP}:${TUIC_PORT}?sni=www.bing.com&alpn=h3&congestion_control=bbr#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

if [ "$HY2_PORT" != "" ]; then
  echo -e "\nhysteria2://${UUID}@${IP}:${HY2_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

if [ "$REALITY_PORT" != "" ]; then
  echo -e "\nvless://${UUID}@${IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

if [ "$ANYTLS_PORT" != "" ]; then
  echo -e "\nanytls://${UUID}@${IP}:${ANYTLS_PORT}?security=tls&sni=${IP}&fp=chrome&insecure=1&allowInsecure=1#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

if [ "$S5_PORT" != "" ]; then
  S5_AUTH=$(echo -n "${UUID:0:8}:${UUID: -12}" | base64 | tr -d '=')
  echo -e "\nsocks://${S5_AUTH}@${IP}:${S5_PORT}#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

if [ "$ANYREALITY_PORT" != "" ]; then
  echo -e "\nanytls://${UUID}@${IP}:${ANYREALITY_PORT}?security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#$(costom_name)" >> ${FILE_PATH}/list.txt
fi

base64 ${FILE_PATH}/list.txt | tr -d '\n' > ${FILE_PATH}/sub.txt
cat ${FILE_PATH}/list.txt
echo -e "\n\n\e[1;32m${FILE_PATH}/sub.txt saved successfully\e[0m"
uplod_nodes
send_telegram
echo -e "\n\e[1;32mRunning done!\e[0m\n"
sleep 2

rm -rf fake_useragent_0.2.0.json ${FILE_PATH}/boot.log ${FILE_PATH}/config.json ${FILE_PATH}/sb.log ${FILE_PATH}/core ${FILE_PATH}/fake_useragent_0.2.0.json ${FILE_PATH}/list.txt ${FILE_PATH}/tunnel.json ${FILE_PATH}/tunnel.yml >/dev/null 2>&1
echo -e "\e[1;32mTelegram群组：\e[1;35mhttps://t.me/eooceu\e[0m"
echo -e "\e[1;32mYoutube频道：\e[1;35mhttps://www.youtube.com/@eooce\e[0m"
echo -e "\e[1;32m此脚本由老王编译: \e[1;35mGithub：https://github.com/eooce/sing-box\e[0m\n"
sleep 2