#!/bin/bash
# webvuln2tb: drupal 构建期初始化 (Dockerfile RUN 阶段执行一次)。
# 与 openemr 同因: 官方 start.sh 在 mysqld 未就绪时导入 -> 部分导入竞态
# (实测缺 semaphore 等表, 站点 500); 且每次启动重导慢。构建期导好, 运行时秒级就绪。
# drupal 插桩本来就是记输入格式, 无需 openemr 的证据补丁。
set -ex
chown -R mysql:mysql /var/lib/mysql
service mysql start
for i in $(seq 1 60); do
  mysqladmin --silent ping >/dev/null 2>&1 && break
  sleep 1
done
mysql -e 'DROP DATABASE IF EXISTS drupal; CREATE DATABASE drupal;'
mysql drupal < /tmp/drupal.sql
touch /var/lib/mysql/.wv2tb_imported
service mysql stop
