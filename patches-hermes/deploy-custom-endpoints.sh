#!/usr/bin/env bash
# ============================================================================
# deploy-custom-endpoints.sh — 给另一台 Hermes 部署「自定义端点管理页 + 模型过滤」
#
# ⚠️ 这套功能是自定义的, 官方 Hermes 没有 (官方仅有 /models 模型管理页)。
#    本脚本从同目录 files/ 全量拷贝, 不依赖任何私库。
#
# 部署内容 (files/ 目录, 已含全部所需文件):
#   web/src/pages/CustomEndpointsPage.tsx         端点列表页
#   web/src/components/EndpointFormDialog.tsx     端点编辑表单 (含模型过滤框)
#   web/src/App.tsx                               路由注册 + 侧边栏导航
#   web/src/i18n/*.ts                             endpoints 文案 (17 语言)
#   hermes_cli/web_server.py                      后端 API + 保存逻辑
#   hermes_cli/web_models.py                      CustomEndpointUpdate 模型
#
# 用法:
#   ./deploy-custom-endpoints.sh [HERMES_HOME]
#   例: ./deploy-custom-endpoints.sh /usr/local/lib/hermes-agent
#
# 环境变量:
#   NO_RESTART=1    只改文件, 不重启 dashboard
# ============================================================================
set -uo pipefail

HERMES_HOME="${1:-${HERMES_HOME:-/usr/local/lib/hermes-agent}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="$SCRIPT_DIR/files"
TS="$(date +%Y%m%d_%H%M%S)"

CORE_FILES=(
  "web/src/pages/CustomEndpointsPage.tsx"
  "web/src/components/EndpointFormDialog.tsx"
  "web/src/App.tsx"
  "hermes_cli/web_models.py"
  "hermes_cli/web_server.py"
)

echo "==> Hermes: $HERMES_HOME"
echo "==> 文件源: $FILES_DIR"

# ── 预检 ────────────────────────────────────────────────────────────────────
[ -d "$FILES_DIR" ] || { echo "✗ 缺少 files/ 目录 (脚本与 files/ 必须同目录)"; exit 1; }
[ -f "$FILES_DIR/web/src/pages/CustomEndpointsPage.tsx" ] || { echo "✗ files/ 不完整, 缺少 CustomEndpointsPage.tsx"; exit 1; }
[ -d "$HERMES_HOME/web/src" ] || { echo "✗ $HERMES_HOME 不是有效的 Hermes 源码目录"; exit 1; }

# ── 幂等: 已部署过则跳过 ────────────────────────────────────────────────────
if [ -f "$HERMES_HOME/web/src/components/EndpointFormDialog.tsx" ] \
   && grep -q 'formFilterHint' "$HERMES_HOME/web/src/i18n/en.ts" 2>/dev/null; then
  echo "✓ 目标机已包含自定义端点功能, 跳过"
  exit 0
fi

# ── 备份现有文件 ─────────────────────────────────────────────────────────────
BACKUP_DIR="$HERMES_HOME/.backup-endpoints-$TS"
mkdir -p "$BACKUP_DIR"
for f in "${CORE_FILES[@]}"; do
  [ -f "$HERMES_HOME/$f" ] && cp "$HERMES_HOME/$f" "$BACKUP_DIR/$(basename "$f").bak" \
    && echo "→ 备份 $f -> $BACKUP_DIR/"
done

# ── 拷贝核心文件 ─────────────────────────────────────────────────────────────
for f in "${CORE_FILES[@]}"; do
  mkdir -p "$HERMES_HOME/$(dirname "$f")"
  cp "$FILES_DIR/$f" "$HERMES_HOME/$f" && echo "  已部署 $f" \
    || { echo "✗ 拷贝 $f 失败, 原文件备份于 $BACKUP_DIR"; exit 1; }
done

# ── 拷贝 i18n (整个目录覆盖, 含 types.ts + 17 语言) ──────────────────────────
for i18nf in "$FILES_DIR"/web/src/i18n/*.ts; do
  [ -f "$i18nf" ] || continue
  cp "$i18nf" "$HERMES_HOME/web/src/i18n/$(basename "$i18nf")" \
    || { echo "✗ 拷贝 $i18nf 失败"; exit 1; }
done
echo "  已部署 web/src/i18n/*.ts (含 types.ts)"

# ── 校验 ─────────────────────────────────────────────────────────────────────
grep -q 'formFilterHint' "$HERMES_HOME/web/src/i18n/en.ts" \
  || { echo "✗ formFilterHint 未写入 en.ts, 部署不完整"; exit 1; }
grep -q 'CustomEndpointsPage' "$HERMES_HOME/web/src/App.tsx" \
  || { echo "✗ App.tsx 缺少路由注册, 部署不完整"; exit 1; }
echo "✓ 文件校验通过"

# ── 构建 web UI ──────────────────────────────────────────────────────────────
echo "→ TypeScript 检查..."
( cd "$HERMES_HOME/web" && node "$HERMES_HOME/node_modules/typescript/bin/tsc" --noEmit -p tsconfig.app.json ) \
  || { echo "✗ tsc 失败, 原文件备份于 $BACKUP_DIR"; exit 1; }
echo "✓ tsc 通过"
echo "→ 构建 bundle..."
( cd "$HERMES_HOME/web" && node "$HERMES_HOME/node_modules/vite/bin/vite.js" build >/dev/null 2>&1 ) \
  || { echo "✗ vite build 失败, 原文件备份于 $BACKUP_DIR"; exit 1; }
echo "✓ 构建完成"

# ── 重启 dashboard ───────────────────────────────────────────────────────────
if [ "${NO_RESTART:-0}" != "1" ]; then
  echo "→ 重启 hermes-dashboard.service..."
  systemctl restart hermes-dashboard.service || { echo "✗ 重启失败 (可手动 systemctl restart hermes-dashboard.service)"; exit 1; }
  sleep 6
  systemctl is-active hermes-dashboard.service >/dev/null || { echo "✗ dashboard 未运行"; exit 1; }
  if ss -ltn 2>/dev/null | grep -q ':9119 '; then
    echo "✓ dashboard 9119 就绪"
  else
    echo "⚠ dashboard 已启动但 9119 未见监听 (稍等或查看日志)"
  fi
fi

echo "✓ 部署完成! 原文件备份: $BACKUP_DIR"
echo "  刷新 GUI → 侧边栏出现「自定义端点」→ 添加/编辑端点时, 模型下拉上方有「筛选」输入框"
