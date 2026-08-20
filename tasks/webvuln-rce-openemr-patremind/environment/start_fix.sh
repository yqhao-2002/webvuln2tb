#!/bin/bash
# webvuln2tb: openemr 运行时启动 (替换官方 /start.sh; DB 已在构建期导入, 秒级就绪)。
# 官方脚本的问题 (2026-08-19 实测): ① mysqld 未就绪即导入 -> 部分导入竞态
# (只进 180/233 张表, 缺 users 表, 登录必挂); ② 每次启动重导 ~150s+, 超出
# solve.sh 的就绪窗口。marker 兜底: 构建期导入意外缺失时运行时重导。
# skip-grant-tables 已写死在镜像 cnf (见 build_init.sh 注释), 无凭据步骤。
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
  mysql -e 'DROP DATABASE IF EXISTS openemr; CREATE DATABASE openemr;'
  mysql openemr < /tmp/openemr.sql
  touch /var/lib/mysql/.wv2tb_imported
fi
service apache2 start
exec tail -f /dev/null
