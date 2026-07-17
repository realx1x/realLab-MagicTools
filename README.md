# Dev Process Manager

Dev Process Manager 是一个本地优先的开发进程管理桌面工具，目标平台为 Windows 10/11 x64 与 macOS 13+ Intel/Apple Silicon。

项目采用 Tauri 2、Rust、React、TypeScript 与 SQLite。独立的 per-user Supervisor 是托管进程、日志、运行状态和数据库写入的唯一事实来源；桌面 UI 只负责展示、输入与确认。

## 编译检查

```powershell
pnpm install --frozen-lockfile
pnpm format:check
pnpm typecheck
pnpm build:web
cargo fmt --all --check
cargo check --workspace --all-targets
git diff --check
```

这些命令不会启动应用、Supervisor、测试 fixture 或真实开发进程。平台能力的“已编译”和“实机通过”状态分开记录在 `docs/architecture/implementation-status.md`。
