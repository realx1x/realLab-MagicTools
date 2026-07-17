# Supervisor 持有关系 Spike

- 任务 ID：P0-T05
- 平台：跨平台所有权模型，在 Windows x64 主机编译
- 工具链：Rust stable MSVC、`tokio = 1.47.1`、`thiserror = 2.0.17`
- 日期：2026-07-14
- 状态：已编译（Windows x64），未进行实机验证

## 问题

验证 UI 生命周期与托管进程生命周期可以彻底分离：独立 per-user Supervisor 是 `Child`、运行表和日志采集任务的唯一所有者，UI 断开、隐藏或崩溃不会直接释放这些资源。

## 实验实现

独立 crate 位于 `experiments/supervisor-ownership`，自带空 `[workspace]`，不依赖根 Workspace。实现以下编译级边界：

- `SupervisorActor` 独占 `HashMap<RunId, ManagedRun>`。
- `ManagedRun` 持有 `tokio::process::Child`、stdout/stderr 磁盘复制任务的 `JoinHandle` 和运行快照。
- `UiSession` 只有一个有界命令 `Sender` 和一个有界事件 `Receiver`，不包含 `Child`、PID 控制句柄、日志任务或运行表引用。
- 丢弃 `UiSession` 只关闭会话通道；actor 在事件发送时清理失效订阅，不触发停止。
- Supervisor 命令通道关闭但仍有活动任务时，actor 继续进行退出对账，直到运行表为空。
- 升级交接移动实际 `ManagedRun` 资源批次到新 actor；持久化 `ProcessInstanceKey` 只能用于历史对账，不能构造 `ManagedRun`。

本轮没有调用 crate 中的启动 API，没有启动子进程、服务或测试。

## 生命周期语义

### UI 隐藏

关闭窗口等价于隐藏 UI。Supervisor 不接收停止命令，运行表、子进程句柄和日志任务保持不变；之后可建立新的 `UiSession`。

### 显式退出

- `KeepRunning`：返回“UI 可退出，任务保留”，不修改运行表。
- `StopAll`：对当前运行表中的每个任务幂等登记 `StopRequested`；真实平台树停止由 P4 生命周期适配层在重新校验完整 `ProcessInstanceKey` 后完成。本 Spike 不直接发送信号。
- `Cancel`：取消退出，不修改任务。

显式 UI 退出与 Supervisor 进程退出是不同命令，不得共用布尔参数。

### UI 崩溃或 IPC 断线

UI 会话资源被释放，Supervisor actor 及其运行表不受影响。慢 UI 的有界事件队列满时丢弃本次事件，不能反向阻塞日志或被托管进程；P2 revision 协议负责检测缺口并重新同步。

### Supervisor 正常终止

没有活动任务时允许终止；存在活动任务时返回 `RefusedActiveRuns`。不能因为 UI 已退出就隐式终止 Supervisor。

### Supervisor 崩溃

进程级崩溃会失去内存运行表、`Child` 和日志管道所有权。目标进程是否继续由平台控制边界决定：Windows Job 关闭策略可能结束任务，macOS 进程组中的任务可能继续。新 Supervisor 只能按完整实例身份做历史对账，并标记 `ExitedWhileOffline`、`IdentityMismatch` 或 `Orphaned`；不得凭旧 PID 重获控制权或伪造日志管道所有权。

### Supervisor 升级

存在活动任务时只能拒绝退出，或将实际 `Child`、运行表和日志任务资源交给已启动的新 actor。Spike 使用同进程 actor 间的资源移动证明 Rust 所有权关系；真实跨进程升级仍需要 P8 的版本协商、平台句柄传递和失败回滚协议。若无法证明资源已交接，旧 Supervisor 必须继续持有并拒绝退出。

### 系统注销与重启

V1 不自动恢复注销或重启前的开发任务。下次启动只进行历史对账，不自动重新启动任务，也不根据持久化 PID 重新建立托管关系。

## 失败路径

- 创建日志目录或文件失败发生在进程启动之前，直接返回错误。
- 进程启动失败时空日志文件可保留，但不会产生运行表项。
- 停止请求只登记状态并保留运行表项；P4 生命周期适配器完成身份复核前不发送信号。
- 升级目标不可用或已有任务时，实际资源批次返回旧 actor，旧 Supervisor 继续运行。
- 资源已进入目标命令队列但确认丢失时返回 `AcknowledgementLost`，不得伪造交接成功；这也是 P8 跨进程交接必须使用耐久确认和回滚门禁的原因。
- 事件接收端断开或队列满不会停止任务。

## 当前结论

类型和 actor 边界能够表达 UI 与运行所有权分离、显式退出三选项、活动任务终止门禁和实际资源交接。编译通过只能证明所有权与异步 API 关系成立，不能证明 UI 崩溃、真实日志洪流、跨进程升级或系统注销行为。

Windows x64 上的 `cargo fmt --check` 和 `cargo check` 已通过。本轮未调用任何启动、停止或日志采集 API。

## 剩余验证

- UI 进程隐藏、退出和强制结束后的 Supervisor/任务状态。
- Supervisor 崩溃时 Windows Job 与 macOS PGID 的真实行为。
- stdout/stderr 持续输出期间 UI 多次重连和慢消费者行为。
- 带活动任务的真实跨进程版本交接、失败回滚和二进制文件锁。
- Windows 注销以及 macOS logout/reboot 后的历史对账。

以上场景需明确授权后执行；本轮仅编译，不标记“实机通过”。
