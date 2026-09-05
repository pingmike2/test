# Hermes 自定义端点功能 — 全量部署包

> 公开镜像，替代私库 hermes-backup（私库无法被别的机器拉取）。
> 本目录是**完整可部署包**：文件都在 `files/` 里，直接拷到目标机即可，不依赖任何 git 分支或私库。

## 这是什么

给官方 Hermes 增加「**自定义端点管理页**」（官方没有此功能，仅有 /models 模型管理页）：

- 侧边栏新增 **自定义端点 (Endpoints)** 页面：增删改查 OpenAI 兼容端点、激活为当前模型
- 端点编辑表单带 **模型过滤** 输入框（支持逗号分隔多关键词，如 `free` / `deepseek-v4-flash, deepseek-v4-pro`，命中任一即保留，保存时只保留匹配模型）
- 保存时整体替换模型列表（`replace_models`），并自动固定 `discover_models=false`，防止自动拉全量覆盖筛选

## 包含文件

```
patches-hermes/
├── deploy-custom-endpoints.sh        # 一键部署脚本（files/ 同目录拷贝）
├── endpoint-model-filter-20260903.patch   # 增量补丁（旧版升级用）
├── endpoint-model-filter-multikeyword-20260905.patch  # 增量补丁（多关键词过滤升级用）
├── telegram-model-picker-full-name.patch  # 附带: TG 模型选择器显示完整模型名
└── files/                             # 全量文件（部署脚本的源）
    ├── web/src/pages/CustomEndpointsPage.tsx
    ├── web/src/components/EndpointFormDialog.tsx
    ├── web/src/App.tsx
    ├── web/src/i18n/*.ts              # 17 语言 + types.ts
    ├── hermes_cli/web_server.py
    └── hermes_cli/web_models.py
```

## 部署（推荐）

```bash
git clone https://github.com/pingmike2/test.git
cd test/patches-hermes
./deploy-custom-endpoints.sh /usr/local/lib/hermes-agent
# 环境变量: NO_RESTART=1 只改文件不重启
```

脚本会自动：备份原文件 → 拷贝整套文件 → tsc 校验 → vite 构建 → 重启 dashboard → 验证 9119 就绪。

## 注意

- 目标机 Hermes 版本应与本包来源版本接近（App.tsx / web_server.py 是整体文件，跨大版本可能冲突，冲突时以 tsc 报错为准，用备份还原）
- 原文件备份在 `<HERMES_HOME>/.backup-endpoints-<时间戳>/`
- 幂等：已部署过的机器再次运行会跳过

## 增量补丁（仅旧版升级）

目标机已有自定义端点功能、只想升级过滤逻辑时：

```bash
cd <HERMES_HOME>
git apply --3way patches-hermes/endpoint-model-filter-20260903.patch
cd web && node ../node_modules/vite/bin/vite.js build
```

---

生成自 hermes-backup 私库 local-custom 快照（commit 7b7e82c），2026-09-03。
