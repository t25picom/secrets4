use std::ops::Range;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub name: String,
    pub span: Range<usize>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unterminated $env[ at byte {0}")]
    Unterminated(usize),
    #[error("invalid name at byte {0}: {1}")]
    InvalidName(usize, String),
}

pub fn find_tokens(cmd: &str) -> Result<Vec<Token>, ParseError> {
    let bytes = cmd.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b"$env[" {
            let start = i;
            let name_start = i + 5;
            let mut j = name_start;
            while j < bytes.len() && bytes[j] != b']' {
                j += 1;
            }
            if j == bytes.len() {
                return Err(ParseError::Unterminated(start));
            }
            let name_bytes = &bytes[name_start..j];
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                ParseError::InvalidName(start, "non-utf8 in name".into())
            })?;
            validate_name(name).map_err(|e| ParseError::InvalidName(start, e))?;
            tokens.push(Token {
                name: name.to_string(),
                span: start..j + 1,
            });
            i = j + 1;
        } else {
            i += 1;
        }
    }
    Ok(tokens)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty name".into());
    }
    let bytes = name.as_bytes();
    let first = bytes[0];
    if !((first.is_ascii_uppercase()) || first == b'_') {
        return Err(format!("name must start with [A-Z_], got {:?}", first as char));
    }
    for b in &bytes[1..] {
        if !(b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_') {
            return Err(format!("name has invalid char {:?}", *b as char));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_token() {
        let cmd = r#"curl -H "Bearer $env[GITHUB_PAT]" https://x"#;
        let toks = find_tokens(cmd).unwrap();
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].name, "GITHUB_PAT");
        assert_eq!(&cmd[toks[0].span.clone()], "$env[GITHUB_PAT]");
    }

    #[test]
    fn finds_multiple() {
        let cmd = "echo $env[A] $env[B_2] $env[_C]";
        let toks = find_tokens(cmd).unwrap();
        assert_eq!(toks.len(), 3);
        assert_eq!(toks[0].name, "A");
        assert_eq!(toks[1].name, "B_2");
        assert_eq!(toks[2].name, "_C");
    }

    #[test]
    fn no_tokens_returns_empty() {
        assert!(find_tokens("echo hello").unwrap().is_empty());
    }

    #[test]
    fn rejects_lowercase_name() {
        assert!(find_tokens("$env[bad]").is_err());
    }

    #[test]
    fn rejects_unterminated() {
        assert!(find_tokens("$env[FOO").is_err());
    }

    #[test]
    fn rejects_starting_digit() {
        assert!(find_tokens("$env[1FOO]").is_err());
    }

    #[test]
    fn rejects_empty_name() {
        assert!(find_tokens("$env[]").is_err());
    }

    #[test]
    fn does_not_match_dollar_NAME_form() {
        assert!(find_tokens("$NAME and ${NAME}").unwrap().is_empty());
    }
}
