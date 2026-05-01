use super::parser::Token;

pub fn rewrite(cmd: &str, tokens: &[Token]) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut cur = 0usize;
    for tok in tokens {
        out.push_str(&cmd[cur..tok.span.start]);
        out.push_str("${");
        out.push_str(&tok.name);
        out.push('}');
        cur = tok.span.end;
    }
    out.push_str(&cmd[cur..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::injection::parser::find_tokens;

    fn rt(cmd: &str) -> String {
        let toks = find_tokens(cmd).unwrap();
        rewrite(cmd, &toks)
    }

    #[test]
    fn rewrites_single() {
        assert_eq!(
            rt(r#"curl -H "Bearer $env[GITHUB_PAT]" https://x"#),
            r#"curl -H "Bearer ${GITHUB_PAT}" https://x"#
        );
    }

    #[test]
    fn rewrites_multiple() {
        assert_eq!(
            rt("echo $env[A] $env[B] $env[C]"),
            "echo ${A} ${B} ${C}"
        );
    }

    #[test]
    fn passes_through_no_tokens() {
        assert_eq!(rt("echo hello"), "echo hello");
    }
}
