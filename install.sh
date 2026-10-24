#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
REPOSITORY=being123321/singbox-mihomo-subscription-converter
REF=${REF:-main}
ROOT=/opt/subscription-forge
DATA=/var/lib/subscription-forge
TLS=${TLS:-}
HOST=${HOST:-}
EMAIL=${EMAIL:-}
CERT_FILE=${CERT_FILE:-}
KEY_FILE=${KEY_FILE:-}
PORT=${PORT:-80}
APP_PORT=${APP_PORT:-19088}
DRY_RUN=0
LOCAL_SOURCE=
usage() {
  echo 'Usage: bash install.sh [--host domain-or-ip] [--tls auto|custom|off] [--email address] [--cert file --key file] [--port 80] [--app-port 19088] [--source directory] [--dry-run]'
}
while (($#)); do
  case "$1" in
    --host) HOST=${2:?}; shift 2;;
    --tls) TLS=${2:?}; shift 2;;
    --email) EMAIL=${2:?}; shift 2;;
    --cert) CERT_FILE=${2:?}; shift 2;;
    --key) KEY_FILE=${2:?}; shift 2;;
    --port) PORT=${2:?}; shift 2;;
    --app-port) APP_PORT=${2:?}; shift 2;;
    --source) LOCAL_SOURCE=${2:?}; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage; exit 2;;
  esac
done
if [[ -z $HOST ]]; then read -rp '网站域名或 IPv4 地址（不含协议）: ' HOST; fi
if [[ -z $TLS ]]; then
  echo '证书选项：auto = 自动申请 HTTPS；custom = 使用现有证书；off = HTTP'
  read -rp '请选择 [auto]: ' TLS; TLS=${TLS:-auto}
fi
[[ $HOST =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && ${#HOST} -le 253 ]] || { echo '域名或 IPv4 地址无效'; exit 2; }
[[ $HOST != *..* ]] || exit 2
[[ $TLS =~ ^(auto|custom|off)$ ]] || { echo '无效的证书选项'; exit 2; }
for number in "$PORT" "$APP_PORT"; do
  [[ $number =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$number<=65535)) || { echo '端口无效'; exit 2; }
done
[[ $PORT != "$APP_PORT" ]] || { echo '网站端口与应用端口不能相同'; exit 2; }
if [[ $TLS != off ]]; then
  [[ $PORT == 80 ]] || { echo 'HTTPS 模式使用 80/443 端口，请不要指定其他网站端口'; exit 2; }
  PUBLIC_URL=https://$HOST
else
  PUBLIC_URL=http://$HOST
  [[ $PORT == 80 ]] || PUBLIC_URL+=:$PORT
fi
if [[ $TLS == auto ]]; then
  [[ $HOST == *.* && ! $HOST =~ ^[0-9.]+$ ]] || { echo '自动证书需要域名'; exit 2; }
  if [[ -z $EMAIL ]]; then read -rp '证书通知邮箱: ' EMAIL; fi
  [[ $EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || { echo '邮箱无效'; exit 2; }
fi
if [[ $TLS == custom ]]; then
  if [[ -z $CERT_FILE ]]; then read -rp '完整证书链绝对路径: ' CERT_FILE; fi
  if [[ -z $KEY_FILE ]]; then read -rp '私钥绝对路径: ' KEY_FILE; fi
  for file in "$CERT_FILE" "$KEY_FILE"; do
    [[ $file =~ ^/[a-zA-Z0-9/_.-]+$ && -f $file ]] || { echo '证书路径无效或文件不存在'; exit 2; }
  done
fi
echo "安装配置：$PUBLIC_URL；证书模式=$TLS；应用监听=127.0.0.1:$APP_PORT"
if ((DRY_RUN)); then echo '参数检查通过；未安装或修改系统'; exit 0; fi
[[ $EUID == 0 ]] || { echo '请使用 root 或 sudo 执行'; exit 1; }
[[ -f /etc/debian_version && -d /run/systemd/system ]] || { echo '仅支持使用 systemd 的 Debian/Ubuntu'; exit 1; }
# Never overwrite a different application or adopt an unrelated directory.
if [[ -e $ROOT && ! -f $ROOT/.subscription-forge ]]; then echo "$ROOT 已存在且不属于本安装器"; exit 1; fi
if [[ -f /etc/nginx/sites-available/subscription-forge && ! -f $ROOT/.subscription-forge ]]; then echo '检测到已有同名 Nginx 配置，请先检查'; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv nginx git curl ca-certificates openssl
STAGING=$(mktemp -d)
trap 'rm -rf -- "$STAGING"' EXIT
if [[ -n $LOCAL_SOURCE ]]; then
  SOURCE=$(realpath "$LOCAL_SOURCE")
else
  [[ $REF =~ ^[a-zA-Z0-9._/-]+$ && $REF != -* ]] || exit 2
  git clone --depth 1 --branch "$REF" "https://github.com/$REPOSITORY.git" "$STAGING/source"
  SOURCE=$STAGING/source
fi
for file in app.py converter.py subscriptions.py app.js index.html style.css requirements.txt; do
  [[ -f $SOURCE/$file ]] || { echo "缺少源码文件：$file"; exit 1; }
done
id subscription-forge >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin subscription-forge
install -d -m 755 "$ROOT"
install -d -m 700 -o subscription-forge -g subscription-forge "$DATA"
if [[ -f $ROOT/app.py ]]; then
  install -d -m 700 "$ROOT/previous"
  cp "$ROOT/"*.py "$ROOT/"*.js "$ROOT/"*.html "$ROOT/"*.css "$ROOT/requirements.txt" "$ROOT/previous/"
fi
for file in app.py converter.py subscriptions.py app.js index.html style.css requirements.txt; do install -m 644 "$SOURCE/$file" "$ROOT/$file"; done
touch "$ROOT/.subscription-forge"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --disable-pip-version-check -r "$ROOT/requirements.txt"
# The environment contains only public packages; let the unprivileged service execute them.
chmod -R a+rX "$ROOT/venv"
cat > /etc/subscription-forge.env <<EOF
PUBLIC_URL=$PUBLIC_URL
BIND=127.0.0.1
PORT=$APP_PORT
DATA_DIR=$DATA
EOF
chmod 600 /etc/subscription-forge.env
cat > /etc/systemd/system/subscription-forge.service <<EOF
[Unit]
Description=Subscription Forge
After=network-online.target
Wants=network-online.target
[Service]
User=subscription-forge
Group=subscription-forge
WorkingDirectory=$ROOT
EnvironmentFile=/etc/subscription-forge.env
ExecStart=$ROOT/venv/bin/python $ROOT/app.py
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
MemoryMax=256M
TasksMax=64
[Install]
WantedBy=multi-user.target
EOF
install -d -m 755 /var/www/subscription-forge
cat > "$STAGING/nginx.conf" <<EOF
# Managed by subscription-forge/install.sh
limit_req_zone \$binary_remote_addr zone=subscription_forge:10m rate=10r/m;
server {
    listen $PORT;
    server_name $HOST;
    access_log off;
    client_max_body_size 4m;
    location /.well-known/acme-challenge/ { root /var/www/subscription-forge; }
    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host \$host;
        proxy_read_timeout 180s;
    }
    location /api/ {
        limit_req zone=subscription_forge burst=5 nodelay;
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host \$host;
        proxy_read_timeout 180s;
    }
}
EOF
if [[ $TLS == custom ]]; then
  openssl x509 -in "$CERT_FILE" -noout >/dev/null
  openssl pkey -in "$KEY_FILE" -noout >/dev/null
  cert_pub=$(openssl x509 -in "$CERT_FILE" -pubkey -noout | openssl sha256)
  key_pub=$(openssl pkey -in "$KEY_FILE" -pubout | openssl sha256)
  [[ $cert_pub == "$key_pub" ]] || { echo '证书与私钥不匹配'; exit 1; }
  sed -i "s/listen $PORT;/listen 443 ssl;/" "$STAGING/nginx.conf"
  sed -i "/server_name $HOST;/a\\    ssl_certificate $CERT_FILE;\n    ssl_certificate_key $KEY_FILE;\n    ssl_protocols TLSv1.2 TLSv1.3;" "$STAGING/nginx.conf"
fi
NGINX_SITE=/etc/nginx/sites-available/subscription-forge
if [[ -f $NGINX_SITE ]]; then cp "$NGINX_SITE" "$STAGING/previous-nginx.conf"; fi
install -m 644 "$STAGING/nginx.conf" "$NGINX_SITE"
ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/subscription-forge
if ! nginx -t; then
  if [[ -f $STAGING/previous-nginx.conf ]]; then cp "$STAGING/previous-nginx.conf" "$NGINX_SITE"; else unlink /etc/nginx/sites-enabled/subscription-forge; fi
  echo 'Nginx 检查失败，未应用新配置'; exit 1
fi
systemctl daemon-reload
systemctl enable --now subscription-forge nginx
systemctl restart subscription-forge
systemctl reload nginx
if [[ $TLS == auto ]]; then
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx --non-interactive --agree-tos --email "$EMAIL" -d "$HOST" --redirect
  systemctl enable --now certbot.timer
fi
for attempt in {1..60}; do
  if curl -fsS "http://127.0.0.1:$APP_PORT/health" >/dev/null; then
    echo "安装成功：$PUBLIC_URL（无需访问口令）"
    echo '自动证书会续期；自有证书请自行维护。节点证书验证由网页独立控制。'
    exit 0
  fi
  sleep 2
done
echo '服务已安装，规则仍在初始化或下载失败；请检查 journalctl -u subscription-forge -n 50'
exit 1
