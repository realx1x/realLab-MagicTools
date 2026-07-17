pub mod method {
    pub const SYSTEM_GET_SNAPSHOT: &str = "system.get_snapshot";
    pub const SYSTEM_GET_EXIT_IMPACT: &str = "system.get_exit_impact";
    pub const PROCESS_GET_DETAILS: &str = "process.get_details";
    pub const PROCESS_REQUEST_ENRICHMENT: &str = "process.request_enrichment";
    pub const PROCESS_STOP_EXTERNAL: &str = "process.stop_external";
    pub const PROFILE_LIST: &str = "profile.list";
    pub const PROFILE_SAVE: &str = "profile.save";
    pub const PROFILE_DELETE: &str = "profile.delete";
    pub const PROFILE_PREVIEW: &str = "profile.preview";
    pub const RUN_START: &str = "run.start";
    pub const RUN_STOP: &str = "run.stop";
    pub const RUN_FORCE_STOP: &str = "run.force_stop";
    pub const RUN_STOP_ALL_FOR_EXIT: &str = "run.stop_all_for_exit";
    pub const RUN_GET_HISTORY: &str = "run.get_history";
    pub const RUN_GET_LOG_RANGE: &str = "run.get_log_range";
    pub const PROJECT_LIST: &str = "project.list";
    pub const PROJECT_SAVE: &str = "project.save";
    pub const PROJECT_DELETE: &str = "project.delete";
    pub const RULE_LIST: &str = "rule.list";
    pub const RULE_SAVE: &str = "rule.save";
    pub const RULE_DELETE: &str = "rule.delete";
    pub const SETTINGS_GET: &str = "settings.get";
    pub const SETTINGS_UPDATE: &str = "settings.update";
    pub const DIAGNOSTICS_GET_MANIFEST: &str = "diagnostics.get_manifest";
    pub const DIAGNOSTICS_EXPORT: &str = "diagnostics.export";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MethodMetadata {
        pub name: &'static str,
        pub mutating: bool,
    }

    pub const ALL: &[MethodMetadata] = &[
        MethodMetadata {
            name: SYSTEM_GET_SNAPSHOT,
            mutating: false,
        },
        MethodMetadata {
            name: SYSTEM_GET_EXIT_IMPACT,
            mutating: false,
        },
        MethodMetadata {
            name: PROCESS_GET_DETAILS,
            mutating: false,
        },
        MethodMetadata {
            name: PROCESS_REQUEST_ENRICHMENT,
            mutating: false,
        },
        MethodMetadata {
            name: PROCESS_STOP_EXTERNAL,
            mutating: true,
        },
        MethodMetadata {
            name: PROFILE_LIST,
            mutating: false,
        },
        MethodMetadata {
            name: PROFILE_SAVE,
            mutating: true,
        },
        MethodMetadata {
            name: PROFILE_DELETE,
            mutating: true,
        },
        MethodMetadata {
            name: PROFILE_PREVIEW,
            mutating: false,
        },
        MethodMetadata {
            name: RUN_START,
            mutating: true,
        },
        MethodMetadata {
            name: RUN_STOP,
            mutating: true,
        },
        MethodMetadata {
            name: RUN_FORCE_STOP,
            mutating: true,
        },
        MethodMetadata {
            name: RUN_STOP_ALL_FOR_EXIT,
            mutating: true,
        },
        MethodMetadata {
            name: RUN_GET_HISTORY,
            mutating: false,
        },
        MethodMetadata {
            name: RUN_GET_LOG_RANGE,
            mutating: false,
        },
        MethodMetadata {
            name: PROJECT_LIST,
            mutating: false,
        },
        MethodMetadata {
            name: PROJECT_SAVE,
            mutating: true,
        },
        MethodMetadata {
            name: PROJECT_DELETE,
            mutating: true,
        },
        MethodMetadata {
            name: RULE_LIST,
            mutating: false,
        },
        MethodMetadata {
            name: RULE_SAVE,
            mutating: true,
        },
        MethodMetadata {
            name: RULE_DELETE,
            mutating: true,
        },
        MethodMetadata {
            name: SETTINGS_GET,
            mutating: false,
        },
        MethodMetadata {
            name: SETTINGS_UPDATE,
            mutating: true,
        },
        MethodMetadata {
            name: DIAGNOSTICS_GET_MANIFEST,
            mutating: false,
        },
        MethodMetadata {
            name: DIAGNOSTICS_EXPORT,
            mutating: true,
        },
    ];

    pub fn metadata(value: &str) -> Option<&'static MethodMetadata> {
        ALL.iter().find(|metadata| metadata.name == value)
    }

    pub fn is_known(value: &str) -> bool {
        metadata(value).is_some()
    }

    pub fn is_mutating(value: &str) -> bool {
        metadata(value).is_some_and(|metadata| metadata.mutating)
    }
}

pub mod event {
    pub const PROCESS_DELTA: &str = "process.delta";
    pub const PORT_DELTA: &str = "port.delta";
    pub const RUN_STATE_CHANGED: &str = "run.state_changed";
    pub const LOG_CHUNK: &str = "log.chunk";
    pub const SUPERVISOR_HEALTH: &str = "supervisor.health";
    pub const SETTINGS_CHANGED: &str = "settings.changed";

    pub const ALL: &[&str] = &[
        PROCESS_DELTA,
        PORT_DELTA,
        RUN_STATE_CHANGED,
        LOG_CHUNK,
        SUPERVISOR_HEALTH,
        SETTINGS_CHANGED,
    ];

    pub fn is_known(value: &str) -> bool {
        ALL.contains(&value)
    }
}
