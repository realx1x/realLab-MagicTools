# AGENTS.md

- 所有文件统一使用 UTF-8 编码，注意注释、字符串、配置文件、SQL、Markdown 等文本内容不要出现中文乱码。
- 只做与需求相关的最小必要修改，不要随意重构无关代码或改变无关业务逻辑。
- 修改完成后只需确保编译通过，例如 `mvn compile`、`go build ./...`、`tsc` 等；不要主动启动服务或运行应用，除非用户明确要求。
- 对 Maven 后端项目，编译前先检查 `pom.xml` 或父级 `pom.xml` 是否配置了 `spring-javaformat` 插件；如果存在，先执行 `mvn spring-javaformat:apply`，再执行 `mvn compile`。
- 最后简要说明修改内容、执行过的命令和编译结果；如果编译失败，只反馈关键错误原因，不要擅自扩大修改范围。

本仓库的实施任务还必须遵守 `docs/architecture/implementation-status.md` 中记录的平台验证边界：默认只执行格式、类型和编译检查，不启动桌面应用、Supervisor、测试 fixture 或真实开发进程。
