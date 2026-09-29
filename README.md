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
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`、`POST /api/reports/{id}/advisory/confirm`
- `POST /api/reports/{id}/evidence/{eid}/versions`、`GET /api/reports/{id}/evidence/{eid}/versions?user_id=...`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 材料版本化

每份取证材料的正文都不可覆盖，只追加版本：

- 首次提交即 v1，之后每次修改调用 `.../evidence/{eid}/versions` 追加 v2、v3……每版保存内容（含 SHA-256 指纹）、提交人、时间和修改原因，旧版永久可查（版本历史接口与报告详情页均含完整链路）。
- 请求必须带 `expected_version`（所基于的基准版本号）。两人同时改同一材料时只有一人成功，基准过期的后到请求返回 **409**，请刷新到最新版后重试；`(材料, 版本号)` 有唯一约束，不会出现相同版本号。
- 已公开报告不允许改正文，只能追加版本。一旦追加，公告状态由 `published` 变为 `pending`（待确认），外部用户在确认前仍只能看到旧的公开版本；协调员调用 `.../advisory/confirm` 重新确认后，公开快照更新到最新版本。
- 报告详情页展示每份材料每版的指纹、修改原因、当前版本标记、已公开版本标记及当前公开内容。

