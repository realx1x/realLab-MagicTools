/// Returns whether a structured field or environment name conventionally
/// carries secret material. Matching is ASCII case-insensitive and recognizes
/// separator-delimited and camel-case tokens without treating words such as
/// `TOKENIZER` or `SECRETARY` as sensitive.
pub fn is_sensitive_field_name(name: &str) -> bool {
    let mut canonical = String::with_capacity(name.len());
    let mut token = String::new();
    let mut previous_lower_or_digit = false;

    for character in name.chars() {
        if !character.is_ascii_alphanumeric() {
            if sensitive_token(&token) {
                return true;
            }
            token.clear();
            previous_lower_or_digit = false;
            continue;
        }

        if character.is_ascii_uppercase() && previous_lower_or_digit {
            if sensitive_token(&token) {
                return true;
            }
            token.clear();
        }
        let lower = character.to_ascii_lowercase();
        canonical.push(lower);
        token.push(lower);
        previous_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }

    sensitive_token(&token)
        || [
            "apikey",
            "accesskey",
            "privatekey",
            "clientsecret",
            "sessiontoken",
            "authtoken",
        ]
        .iter()
        .any(|pattern| canonical.contains(pattern))
}

fn sensitive_token(token: &str) -> bool {
    matches!(
        token,
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "token"
            | "authorization"
            | "credential"
            | "cookie"
            | "session"
    )
}

#[cfg(test)]
mod tests {
    use super::is_sensitive_field_name;

    #[test]
    fn recognizes_common_sensitive_names_without_matching_unrelated_words() {
        for name in [
            "GITHUB_TOKEN",
            "clientSecret",
            "AWS_SECRET_ACCESS_KEY",
            "api-key",
            "Authorization",
            "session_id",
        ] {
            assert!(is_sensitive_field_name(name), "{name}");
        }
        for name in ["TOKENIZER_MODEL", "SECRETARY", "SESSIONNAME", "PATH"] {
            assert!(!is_sensitive_field_name(name), "{name}");
        }
    }
}
