# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/evidence/{id}/versions`、`GET /api/evidence/{id}/versions?user_id=...`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/advisory/confirm`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 材料版本

- 每份材料首次提交即生成 v1；此后每次修改都**追加新版本**，旧版本内容、SHA-256 内容指纹、修改原因、提交人和提交时间全部保留可查（`GET /api/evidence/{id}/versions`），不会被协调员改说明覆盖。
- 追加版本需带 `expected_version`（你编辑时基于的版本号）和 `change_reason`。服务端在 `BEGIN IMMEDIATE` 事务内比对当前版本并分配新版本号（版本号有 UNIQUE 约束）：两人同时改同一材料时只有一人成功，后到者收到 **409 Conflict**，要求基于最新版本重试，不会出现相同版本号。
- 内容指纹为正文的 SHA-256；新旧版本指纹相同（内容没变化）不生成新版本。
- 报告详情页（内部）与公告接口（公开）都列出每版的版本号、指纹、原因、提交人和时间，以及当前公开内容。
- 已公开报告的公告只允许追加版本：公开后新增/修改材料（或编辑公告正文）时公告状态从 `published` 变为 `pending`（待确认），**对外仍展示确认前的公开内容**，材料快照标注 `changed_since_publish`；协调员调用确认接口后新正文与材料新版本才成为公开内容。
