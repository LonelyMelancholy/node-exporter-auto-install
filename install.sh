#!/bin/bash

# Создаем юзера
sudo useradd --no-create-home --shell /usr/sbin/nologin node_exporter

useradd -r -s /bin/false node_exporter
# Скачиваем, распаковываем
LATEST_TAG=$(
  curl -Ls -o /dev/null -w '%{url_effective}' \
    "https://github.com/prometheus/node_exporter/releases/latest" \
  | awk -F'/tag/' '{print $2}'
)

echo "$LATEST_TAG"  # v1.8.2

OS_ARCH="linux-amd64"
FILENAME="node_exporter-${LATEST_TAG#v}.${OS_ARCH}.tar.gz"

URL="https://github.com/prometheus/node_exporter/releases/download/$LATEST_TAG/$FILENAME"

curl -L -o "$FILENAME" "$URL"


tar -xvf node_exporter-1.9.1.linux-amd64.tar.gz


# Копируем в директорию к бинарникам
sudo cp node_exporter-*/node_exporter /usr/local/bin/

sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter

# Создаем демона
sudo nano /etc/systemd/system/node_exporter.service

[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target

# Запускаем
sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
sudo systemctl status node_exporter
