#!/bin/bash
# webvuln2tb: openemr 构建期初始化 (Dockerfile RUN 阶段执行一次)。
# 官方镜像运行时才导入 /tmp/openemr.sql (11MB, 233 表), 实测 ~7min (且官方
# start.sh 有 mysqld 未就绪即导入的竞态 -> 部分导入, 缺 users 表)。
# mysql datadir 只是文件 —— 构建期初始化好, 运行时 start 即用。
# 注意: 官方镜像 cnf 写死 skip-grant-tables (50-server.cnf), 任何凭据都能连;
# 应用自身用 dump 自带的 openemr/011024 账号 (sites/default/sqlconf.php),
# 官方 start.sh 的 ALTER USER root 在 skip-grant 下必失败且无必要 —— 不做。
set -ex
chown -R mysql:mysql /var/lib/mysql
service mysql start
for i in $(seq 1 60); do
  mysqladmin --silent ping >/dev/null 2>&1 && break
  sleep 1
done
mysql -e 'DROP DATABASE IF EXISTS openemr; CREATE DATABASE openemr;'
mysql openemr < /tmp/openemr.sql
touch /var/lib/mysql/.wv2tb_imported
service mysql stop
