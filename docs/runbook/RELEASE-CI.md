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
- **403 cannot-publish-over**：某包版本已存在 → 检查第 1 步手动 bump 是否遗漏
- **regression 挂在 CI 但本地绿**：确认是否 out/ artifact 相关——CI 每次
  冷检出，依赖 forge build 步骤存在且在测试之前
- 紧急撤回：npm unpublish 只允许 72h 内（会破坏生态信任，非供应链事故不用）；
  一般用 deprecate + 升版重发
