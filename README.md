# 自动化安全评估系统

这是一个面向已授权资产的自动化安全评估系统，当前实现聚焦低侵入、被动式检查流程，用于安全巡检、配置审查、基线核对和整改跟踪。

系统默认不包含攻击型自动化能力，不执行漏洞利用、口令爆破、绕过、持久化或横向移动。

## 当前能力

- 授权任务管理
  - 任务名称、工单号、授权人、负责人、范围白名单
- 范围校验
  - 仅允许命中主机白名单或 URL 前缀白名单的目标
- 本地持久化
  - 使用 SQLite 记录任务、目标、作业、发现和审计事件
- 被动检查插件
  - 安全响应头检查
  - Cookie 安全属性检查
  - TLS 元数据检查
- 控制方式
  - 命令行工具
  - 内置 Web 控制台
  - REST API
- 报告输出
  - Markdown
  - JSON
- 删除能力
  - 支持删除目标
  - 支持删除任务
  - 删除动作会同步清理关联发现、审计记录和作业数据

## 界面说明

当前 Web 控制台已经重构为完整站点式界面，默认访问地址为 `http://127.0.0.1:8081`，包含以下区域：

- 顶部导航和 API 状态区
- 首屏概览和运行指标
- 任务中心
- 目标资产区
- 被动检查作业区
- Markdown 报告预览区

界面为全中文，适合直接做本机演示、内部资产基线巡检演示和小型团队使用。

## 快速开始

### 1. 初始化数据库

```bash
python main.py init-db
```

### 2. 创建授权任务

```bash
python main.py create-engagement ^
  --name "内网资产基线检查" ^
  --description "办公网核心系统被动检查" ^
  --authorized-by "安全负责人" ^
  --ticket "SEC-2026-001" ^
  --owner "蓝队" ^
  --allow-host "app.internal.example.com" ^
  --allow-prefix "https://portal.internal.example.com"
```

### 3. 添加目标

```bash
python main.py add-target --engagement-id 1 --url "https://app.internal.example.com" --label "门户首页"
```

### 4. 运行作业

```bash
python main.py run-job --engagement-id 1 --requested-by "ops.user"
```

### 5. 导出报告

```bash
python main.py report --job-id 1 --format md
python main.py report --job-id 1 --format json
```

### 6. 启动 Web 控制台

```bash
python main.py serve
```

默认等价于：

```bash
python main.py serve --host 127.0.0.1 --port 8081
```

启动后访问：

`http://127.0.0.1:8081`

## Web 控制台操作流

1. 创建任务，填入工单、授权人、负责人和允许范围。
2. 在任务下添加目标 URL。
3. 点击“运行被动检查”执行作业。
4. 在执行结果区查看发现。
5. 在报告区查看 Markdown 报告。
6. 如需清理数据，可在页面中删除目标或删除当前任务。

## REST API 概览

### 健康检查

- `GET /api/health`

### 任务相关

- `GET /api/engagements`
- `POST /api/engagements`
- `GET /api/engagements/{id}`
- `DELETE /api/engagements/{id}`

### 目标相关

- `GET /api/engagements/{id}/targets`
- `POST /api/engagements/{id}/targets`
- `DELETE /api/targets/{id}`

### 作业与报告

- `POST /api/engagements/{id}/jobs`
- `GET /api/jobs/{id}`
- `GET /api/jobs/{id}/report?format=md`
- `GET /api/jobs/{id}/report?format=json`

## 自动化测试

运行完整测试：

```bash
python -m unittest discover -s tests -v
```

只运行 Web / API 相关测试：

```bash
python -m unittest tests.test_web_api -v
```

## 项目结构

```text
autopentest/
  api.py
  cli.py
  orchestrator.py
  reporting.py
  scope.py
  storage.py
  web.py
  web_static/
  plugins/
tests/
main.py
README.md
使用说明书.md
```

## 使用文档

- 详细说明见 [使用说明书](./使用说明书.md)

## 安全边界

- 仅对明确授权且位于白名单内的目标执行
- 仅发起基础 HTTP 请求和 TLS 握手，用于元数据采集
- 不执行漏洞利用、目录爆破、口令测试、代理绕过或植入行为
- 不适用于未授权目标

## 后续可扩展方向

- RBAC 与审批流
- 插件注册与签名校验
- 调度队列与并发控制
- 更完整的 Web API
- 对接 CMDB、资产平台和告警平台
