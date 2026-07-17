# Windows Job Object 生命周期 Spike

- 任务 ID：P0-T02
- 平台：Windows 10/11 x64
- 架构：x86_64
- 工具链：Rust stable MSVC，`windows = 0.61.3`
- 日期：2026-07-14
- 状态：已编译（Windows x64），未进行实机验证

## 问题

验证 Supervisor 能否在目标进程执行任何用户代码之前建立 Job Object 控制边界，并区分正常停止、强制停止、breakaway 和中间失败清理。

## 约束

- 遵循 ADR-0001、ADR-0002、ADR-0004 和 ADR-0005。
- 不使用递归 PID 枚举模拟进程树控制。
- 不允许 `AssignProcessToJobObject` 失败后恢复线程。
- 本任务只编译，不启动实验程序或真实子进程。

## 实验实现

独立 crate 位于 `experiments/windows-job-object`，通过空 `[workspace]` 与未来根 Workspace 隔离。依赖固定为 `windows = 0.61.3`，直接调用以下 Win32 API：

1. `CreateJobObjectW` 创建匿名 Job。
2. `SetInformationJobObject` 始终设置 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`；仅在调用方明确选择时增加 `JOB_OBJECT_LIMIT_BREAKAWAY_OK`。
3. `CreateProcessW` 始终设置 `CREATE_SUSPENDED`；只有需要正常控制台停止时增加 `CREATE_NEW_PROCESS_GROUP`。
4. `AssignProcessToJobObject` 成功后才调用 `ResumeThread`。
5. 适用时使用 `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process_group_id)` 请求正常停止。
6. 超时或明确强制停止时使用 `TerminateJobObject`。

非 Windows 目标通过 `compile_error!` 明确拒绝编译，不提供空实现。

## 停止语义

### 正常停止

只有以 `CREATE_NEW_PROCESS_GROUP` 创建、仍与 Supervisor 共享可用控制台且目标支持 `CTRL_BREAK_EVENT` 的控制台任务才调用 `GenerateConsoleCtrlEvent`。API 失败只返回错误并进入上层超时状态机，不会降级为递归 PID 停止。GUI、脱离控制台或控制台关系不满足时不宣称支持正常信号。

### 强制停止

`TerminateJobObject` 作用于创建时建立的 Job 控制边界。Job 始终启用 `KILL_ON_JOB_CLOSE`，Supervisor 意外关闭 Job 句柄时仍有最终回收边界。

### Breakaway

默认不设置 breakaway 标志。显式启用 `JOB_OBJECT_LIMIT_BREAKAWAY_OK` 时，Job 内进程可按 Windows 规则创建脱离 Job 的后代；该后代不受 `TerminateJobObject` 或 `KILL_ON_JOB_CLOSE` 保证，应在产品状态中标记 `Orphaned` 或 `NotFullyManaged`。禁止使用 `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`，因为它会隐藏控制边界丢失。

## 失败路径

| 失败点 | 已获得资源 | 处理 |
|---|---|---|
| `CreateJobObjectW` | 无 | 返回 Win32 错误 |
| `SetInformationJobObject` | Job 句柄 | 关闭 Job，未创建进程 |
| `CreateProcessW` | Job 句柄 | 关闭 Job，未创建进程 |
| `AssignProcessToJobObject` | Job、悬挂进程和线程句柄 | 保持主线程悬挂，以进程句柄调用 `TerminateProcess`，等待退出后关闭全部句柄 |
| `ResumeThread` | 已分配 Job 的悬挂进程 | 调用 `TerminateJobObject`，等待主进程退出后关闭全部句柄 |

失败清理使用 `CreateProcessW` 返回的受控句柄，不依赖 PID。清理守卫在显式清理失败时会在析构阶段再次尝试，且不会恢复未受控进程。

## 当前结论

代码层面已落实先悬挂、后入 Job、最后恢复的顺序，以及正常和强制停止的不同 API。`cargo fmt --check` 和 Windows x64 `cargo check` 已通过。编译只能证明 Win32 类型和调用签名成立，不能证明控制台信号、嵌套 Job、breakaway 或真实进程树行为。

## 剩余验证

- Windows 10 22H2 x64 与 Windows 11 x64 的真实生命周期。
- 控制台共享、无控制台和已脱离控制台三种 `CTRL_BREAK_EVENT` 行为。
- Supervisor 自身位于 Job 中时的嵌套 Job 行为。
- 明确允许和禁止 breakaway 时的后代进程归属。
- `AssignProcessToJobObject`、`ResumeThread` 故障注入后的句柄与进程清理。

以上实机验证需另行获得授权；本轮不得标记为“实机通过”。
