#!/bin/bash
# webvuln2tb: drupal 运行时启动 (替换官方 /start.sh; DB 已在构建期导入)。
# marker 兜底: 构建期导入意外缺失时运行时重导。
set -x
a2enmod rewrite >/dev/null 2>&1 || true
a2enmod ssl >/dev/null 2>&1 || true
chown -R mysql:mysql /var/lib/mysql
service mysql start
for i in $(seq 1 60); do
  mysqladmin --silent ping >/dev/null 2>&1 && break
  sleep 1
done
if [ ! -f /var/lib/mysql/.wv2tb_imported ]; then
  echo 'wv2tb: build-time import missing, re-importing at runtime' >&2
  mysql -e 'DROP DATABASE IF EXISTS drupal; CREATE DATABASE drupal;'
  mysql drupal < /tmp/drupal.sql
  touch /var/lib/mysql/.wv2tb_imported
fi
service apache2 start
exec tail -f /dev/null
