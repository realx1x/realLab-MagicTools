# Platform Spike: Title

- Task ID: P0-TNN
- Platform and version:
- Architecture:
- Toolchain:
- Date:
- Status: Planned | Implemented | Compiled | Real-system validated | Blocked

## Question

State the native behavior or security property being investigated.

## Constraints

Record the relevant ADRs, permission boundary, and prohibited fallbacks.

## Experiment

Describe the isolated crate, APIs, lifecycle, failure injection, and compile command. Do not record a runtime result unless execution was explicitly authorized.

## Observations

Separate compiler evidence from real-system observations. Include OS error codes and access-limited behavior without secrets or personal paths.

## Decision

State whether the approach is viable, what guarantees it provides, and what it cannot guarantee.

## Failure Paths

Document cleanup after every partial-success point. A failure must never silently fall back to PID-only or recursive PID-tree control.

## Remaining Validation

List target runners, architectures, permission cases, and real-system scenarios still required.
