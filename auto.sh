#!/usr/bin/env bash
set -euo pipefail

NGINX_VERSION="1.26.2"
MODSEC_VERSION="3.0.12"
CONNECTOR_REPO="https://github.com/SpiderLabs/ModSecurity-nginx.git"
CRS_REPO="https://github.com/coreruleset/coreruleset.git"
BUILD_DIR="/usr/local/src/nginx-build"
PREFIX="/etc/nginx"

info()  { echo -e "\033[0;34m[INFO]\033[0m $*"; }
ok()    { echo -e "\033[0;32m[OK]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
fail()  { echo -e "\033[0;31m[FAIL]\033[0m $*" >&2; exit 1; }

install_packages() {
    local packages=("$@")
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf -y groupinstall "Development Tools"
        sudo dnf -y install "${packages[@]}"
    else
        fail "Only Fedora/RHEL-based systems with dnf are supported. Install dependencies manually."
    fi
}

clone_repo() {
    local repo_url="$1" dest_dir="$2" branch="${3:-}"
    if [[ -d "$dest_dir" ]]; then
        info "Repository already exists: $dest_dir (skipping)"
        return
    fi
    [[ -n "$branch" ]] && branch_arg=(-b "$branch") || branch_arg=()
    git clone --depth=1 "${branch_arg[@]}" "$repo_url" "$dest_dir"
}

download_file() {
    local url="$1" output="$2"
    wget -q "$url" -O "$output" || fail "Failed to download: $url"
}

info "Installing dependencies..."
install_packages \
    git wget curl unzip pcre2-devel zlib-devel openssl-devel \
    libxml2-devel curl-devel yajl-devel ssdeep-devel lmdb-devel \
    GeoIP-devel libmaxminddb-devel doxygen

sudo mkdir -p "$BUILD_DIR"

if ! id -u nginx >/dev/null 2>&1; then
    info "Creating nginx user..."
    sudo useradd --system --no-create-home --shell /sbin/nologin nginx
else
    ok "nginx user already exists"
fi

cd "$BUILD_DIR"
info "Cloning and building libModSecurity..."
clone_repo "https://github.com/SpiderLabs/ModSecurity" "ModSecurity" "v${MODSEC_VERSION}"

cd ModSecurity
git submodule update --init
./build.sh
./configure
make -j"$(nproc)"
sudo make install
cd "$BUILD_DIR"

info "Cloning ModSecurity-nginx connector..."
clone_repo "$CONNECTOR_REPO" "ModSecurity-nginx"

info "Downloading and building Nginx v${NGINX_VERSION}..."
download_file "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" "nginx-${NGINX_VERSION}.tar.gz"
tar -xzf "nginx-${NGINX_VERSION}.tar.gz"
cd "nginx-${NGINX_VERSION}"

./configure \
  --prefix="${PREFIX}" \
  --sbin-path=/usr/sbin/nginx \
  --conf-path="${PREFIX}/nginx.conf" \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_realip_module \
  --with-http_stub_status_module \
  --with-stream \
  --with-compat \
  --add-dynamic-module="${BUILD_DIR}/ModSecurity-nginx"

make -j"$(nproc)"
sudo make install

sudo mkdir -p /etc/nginx/modules
sudo cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules/
sudo chown -R root:nginx /etc/nginx/modules
sudo chmod 750 /etc/nginx/modules
sudo chmod 640 /etc/nginx/modules/ngx_http_modsecurity_module.so
ok "Nginx installed with ModSecurity module"

info "Installing OWASP CRS..."
sudo mkdir -p /etc/nginx/modsec/
cd "$BUILD_DIR"
clone_repo "$CRS_REPO" "crs"

sudo rm -rf /etc/nginx/modsec/crs
sudo cp -r crs /etc/nginx/modsec/crs
sudo cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf

info "Configuring ModSecurity..."
MODSEC_CONF_URL="https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v${MODSEC_VERSION}/modsecurity.conf-recommended"
MODSEC_CONF_PATH="/etc/nginx/modsec/modsecurity.conf"

download_file "$MODSEC_CONF_URL" "$MODSEC_CONF_PATH"
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$MODSEC_CONF_PATH"

UNICODE_MAPPING_PATH=$(find /usr/local -name unicode.mapping 2>/dev/null | head -n 1)
if [[ -f "$UNICODE_MAPPING_PATH" ]]; then
    sudo cp "$UNICODE_MAPPING_PATH" /etc/nginx/modsec/unicode.mapping
else
    warn "unicode.mapping not found, skipping..."
fi

sudo tee /etc/nginx/modsec/main.conf >/dev/null <<'EOF'
Include "/etc/nginx/modsec/modsecurity.conf"
Include "/etc/nginx/modsec/crs/crs-setup.conf"
Include "/etc/nginx/modsec/crs/rules/*.conf"
EOF

info "Creating directories and default files..."
sudo mkdir -p /var/log/nginx /usr/share/nginx/html

sudo tee /usr/share/nginx/html/index.html >/dev/null <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Welcome to nginx with ModSecurity!</title></head>
<body>
  <h1>nginx with ModSecurity is running.</h1>
  <p>Successfully installed and working.</p>
</body>
</html>
EOF

info "Writing nginx.conf..."
sudo tee /etc/nginx/nginx.conf >/dev/null <<'EOF'
load_module modules/ngx_http_modsecurity_module.so;

user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log;
pid        /var/run/nginx.pid;

events { worker_connections 1024; }

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    server {
        listen 80 default_server;
        server_name _;

        root /usr/share/nginx/html;
        location / { index index.html; }
    }
}
EOF

info "Creating systemd service..."
sudo tee /etc/systemd/system/nginx.service >/dev/null <<'EOF'
[Unit]
Description=NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable nginx
sudo systemctl restart nginx
ok "nginx service started"

nginx -v
if nginx -V 2>&1 | grep -qi modsecurity; then
    ok "ModSecurity compiled into nginx"
    if [[ -f /etc/nginx/modules/ngx_http_modsecurity_module.so ]] && \
       grep -q "load_module modules/ngx_http_modsecurity_module.so" /etc/nginx/nginx.conf; then
        ok "ModSecurity module loaded successfully"
    else
        warn "ModSecurity module not detected in nginx.conf"
    fi
else
    warn "ModSecurity not found in nginx build output"
fi

cat <<EOF
===============================================================================
Installation complete!
Config:   /etc/nginx/modsec/
Rules:    /etc/nginx/modsec/crs/rules/
Web root: /usr/share/nginx/html/
===============================================================================
EOF