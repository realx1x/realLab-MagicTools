use std::ffi::OsString;

use super::FixtureError;

const MAX_ARGS: usize = 16;
const MAX_ARG_BYTES: usize = 128;
const EXTERNAL_FLAG: &str = "--allow-test-fixture";
const AUTHORIZATION_ENV: &str = "MAGICTOOLS_TEST_FIXTURE_AUTHORIZATION";
const AUTHORIZATION_VALUE: &str = "I_ACKNOWLEDGE_FIXTURE_SIDE_EFFECTS";
const INTERNAL_AUTHORIZATION_ENV: &str = "MAGICTOOLS_TEST_FIXTURE_INTERNAL_AUTHORIZATION";
const INTERNAL_CHILD_ARG: &str = "--internal-process-child";
const INTERNAL_GRANDCHILD_ARG: &str = "--internal-process-grandchild";
const SESSION_NONCE_HEX_BYTES: usize = 64;

#[derive(Debug)]
pub(crate) enum AuthorizedInvocation {
    External(Vec<String>),
    Internal(InternalAuthorization),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternalAuthorization {
    ProcessChild,
    ProcessGrandchild,
}

pub(crate) fn authorize() -> Result<AuthorizedInvocation, FixtureError> {
    let arguments = collect_arguments()?;
    if arguments.len() == 2 && arguments[0] == EXTERNAL_FLAG {
        let role = match arguments[1].as_str() {
            INTERNAL_CHILD_ARG => Some(InternalAuthorization::ProcessChild),
            INTERNAL_GRANDCHILD_ARG => Some(InternalAuthorization::ProcessGrandchild),
            _ => None,
        };
        if let Some(role) = role {
            authorize_internal()?;
            return Ok(AuthorizedInvocation::Internal(role));
        }
    }

    authorize_external(&arguments)
}

fn collect_arguments() -> Result<Vec<String>, FixtureError> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    if arguments.is_empty() || arguments.len() > MAX_ARGS {
        return Err(FixtureError::Authorization);
    }

    arguments
        .into_iter()
        .map(|argument| {
            let argument = argument
                .into_string()
                .map_err(|_| FixtureError::Authorization)?;
            if argument.is_empty() || argument.len() > MAX_ARG_BYTES {
                return Err(FixtureError::Authorization);
            }
            Ok(argument)
        })
        .collect()
}

fn authorize_external(arguments: &[String]) -> Result<AuthorizedInvocation, FixtureError> {
    if arguments.first().map(String::as_str) != Some(EXTERNAL_FLAG)
        || arguments[1..]
            .iter()
            .any(|argument| argument == EXTERNAL_FLAG)
        || std::env::var(AUTHORIZATION_ENV).as_deref() != Ok(AUTHORIZATION_VALUE)
    {
        return Err(FixtureError::Authorization);
    }

    if arguments.len() == 1 {
        return Err(FixtureError::InvalidArguments);
    }

    Ok(AuthorizedInvocation::External(arguments[1..].to_vec()))
}

fn authorize_internal() -> Result<(), FixtureError> {
    if std::env::var(AUTHORIZATION_ENV).as_deref() != Ok(AUTHORIZATION_VALUE) {
        return Err(FixtureError::Authorization);
    }
    let value =
        std::env::var(INTERNAL_AUTHORIZATION_ENV).map_err(|_| FixtureError::Authorization)?;
    if value.len() != SESSION_NONCE_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FixtureError::Authorization);
    }
    Ok(())
}

pub(crate) const fn external_authorization_env() -> &'static str {
    AUTHORIZATION_ENV
}

pub(crate) const fn external_authorization_flag() -> &'static str {
    EXTERNAL_FLAG
}

pub(crate) const fn external_authorization_value() -> &'static str {
    AUTHORIZATION_VALUE
}

pub(crate) const fn internal_authorization_env() -> &'static str {
    INTERNAL_AUTHORIZATION_ENV
}

pub(crate) const fn internal_child_arg() -> &'static str {
    INTERNAL_CHILD_ARG
}

pub(crate) const fn internal_grandchild_arg() -> &'static str {
    INTERNAL_GRANDCHILD_ARG
}
