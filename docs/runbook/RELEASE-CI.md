# CI 发布 Runbook（npm-publish.yml · 2026-09-08 首次全绿验证）

> 验证记录：run 34235521297（dispatch dry-run）preflight/publish 全绿、
> publish steps 正确 skip、smoke 正确 skip。NPM_TOKEN secret 已配置
> （npm granular token，read-write / all packages / 1 年期，2026-10-08 前
> 无需轮换——到期前 CI 会 401，重新生成后更新 secret 即可）。

## 发版检查单（tag 触发全自动发布）

1. **手动 bump 非 SCAN 包**——release-bump 的 SCAN 列表不含以下 5 包，
   先手动同步版本（版本线：三件套独立 minor 线随发布列车，cli/mcp 独立
   minor 线；首次 coordinated release 实际落点 2026-09-09：三件套 0.1.0→
   0.2.0，cli/mcp 0.1.0→0.2.0）：
   - packages/guardrail-x402、packages/guardrail-ap2、packages/registry-8004
   - packages/agent-keys-cli、packages/agent-keys-mcp
   - 注意交叉引用：examples + cli/mcp 依赖的 `aegis-vault`/`aegis-agent-sdk`
     版本范围要指向**即将发布**的版本，否则全新安装 404
2. `node scripts/release-bump.mjs --apply`（SCAN 内 6 包 lockstep + 交叉引用）
3. `npm run test:release-packages`（本地预跑，与 CI 同一命令）
4. commit → 打 tag `vX.Y.Z` → `git push origin vX.Y.Z`
5. CI 自动执行：preflight（foundry build + deny-list 校验 + release-preflight
   + 全量回归）→ publish 11 包（**全部 --provenance**）→ registry smoke
6. 验证 provenance：npmjs 包页应显示
   "Published from GitHub Actions · nexus-genesis/aegis-vault"
7. 验证 smoke：CI 第三个 job 绿 = 发布的精确版本（非 latest）安装可用

## Dry-run 预览（发布前可选）

Actions → Publish to npm → Run workflow，保持 dry_run=true：
- 跑 preflight + 回归 + bump 预览，**publish steps 被 PUBLISH_ENABLED 守卫跳过**
- 首次运行曾暴露两类问题（已修）：缺 foundry 编译（873258e）、
  dry-run 无发布守卫（536487e）——下次环境变更（node 版本、依赖大版本）
  建议先 dry-run 一次

## 应急

- **CI 401/403 on publish**：token 过期或权限丢失 → npm 网页重新生成
  granular token（read-write）→ 更新 GitHub secret `NPM_TOKEN`
- **403 "Two-factor authentication or granular access token with bypass
  2fa enabled is required"**（v0.7.0 三次 run 的实际根因，2026-09-09
  定位）：granular token 创建时未勾选 bypass 2FA，且该选项无法事后修改
  → npm 网页重新生成 token 时勾选 bypass 2FA（或改用 classic
  **Automation** token，该类型设计上免 OTP）→ 更新 secret 后移动 tag 重跑
  （`git tag -f vX.Y.Z && git push -f origin vX.Y.Z`，仅当该版本确认未
  落 npm 时可安全移动）
- **publish 失败但看不到日志**：step 日志/job summary 对匿名访客截断、
  job-logs API 需 admin——publish 步骤失败时会自动创建公开诊断 issue
  （含 npm 错误原文 + `npm whoami` 三态 + provenance 状态），直接读
  issue 即可；34240906601/34242536018 两次 run 因此曾无法诊断，issue
  通道自 run 34287865194 起生效
- **403 cannot-publish-over**：某包版本已存在 → 检查第 1 步手动 bump 是否遗漏
- **regression 挂在 CI 但本地绿**：确认是否 out/ artifact 相关——CI 每次
  冷检出，依赖 forge build 步骤存在且在测试之前
- 紧急撤回：npm unpublish 只允许 72h 内（会破坏生态信任，非供应链事故不用）；
  一般用 deprecate + 升版重发
