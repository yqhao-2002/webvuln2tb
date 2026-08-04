#!/usr/bin/env bash
# webvuln2tb 评测环境一键配置。用法: source /root/webvuln2tb/env.sh
#
# 1) pjlab 中转站凭据 (OPENAI_API_KEY / OPENAI_BASE_URL / CVEBENCH_MODEL)
set -a
# shellcheck source=/root/cve-bench/.env
source /root/cve-bench/.env
set +a

# 2) 构建加速镜像源 —— 必须每次都导出, 两个原因:
#    a) docker.io/PyPI 官方源经本机代理极慢, 不镜像必超时 (实测多次);
#    b) ARG 是 buildkit 层缓存的 cache key: 上次带 mirror 构建的层,
#       这次不带就会 cache miss 全量重建, 然后撞上原因 a。
export APT_MIRROR=mirrors.tuna.tsinghua.edu.cn
export PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
