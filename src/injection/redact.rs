use std::io::{Read, Write};
use zeroize::Zeroizing;

pub struct Redactor<'a> {
    /// (name, value) pairs sorted by value length descending
    patterns: Vec<(&'a str, &'a [u8])>,
    /// Bytes held back across reads so a pattern split at a chunk boundary still matches.
    held: Vec<u8>,
    max_pat_len: usize,
}

impl<'a> Redactor<'a> {
    pub fn new<I>(patterns: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a [u8])>,
    {
        let mut v: Vec<_> = patterns.into_iter().collect();
        v.sort_by_key(|(_, b)| std::cmp::Reverse(b.len()));
        let max_pat_len = v.first().map(|(_, b)| b.len()).unwrap_or(0);
        Self { patterns: v, held: Vec::new(), max_pat_len }
    }

    /// Consume new bytes, return what is safe to emit downstream.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(chunk);
        let (emit, hold) = self.scan(&buf, false);
        self.held = hold;
        emit
    }

    /// Flush remaining held bytes (call once after EOF).
    pub fn flush(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.held);
        let (emit, _) = self.scan(&buf, true);
        emit
    }

    fn scan(&self, buf: &[u8], final_pass: bool) -> (Vec<u8>, Vec<u8>) {
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0usize;
        let scan_limit = if final_pass {
            buf.len()
        } else {
            buf.len().saturating_sub(self.max_pat_len.saturating_sub(1))
        };

        while i < buf.len() {
            if i < scan_limit {
                if let Some((name, plen)) = self.match_at(buf, i) {
                    out.extend_from_slice(format!("[REDACTED:{}]", name).as_bytes());
                    i += plen;
                    continue;
                }
                out.push(buf[i]);
                i += 1;
            } else {
                break;
            }
        }
        let hold = buf[i..].to_vec();
        (out, hold)
    }

    fn match_at(&self, buf: &[u8], i: usize) -> Option<(&'a str, usize)> {
        for (name, pat) in &self.patterns {
            if pat.is_empty() {
                continue;
            }
            if i + pat.len() <= buf.len() && &buf[i..i + pat.len()] == *pat {
                return Some((name, pat.len()));
            }
        }
        None
    }
}

/// Streaming copy: read from `src` in chunks, redact, write to `dst`.
pub fn copy_redacting<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    secrets: &[(String, Zeroizing<Vec<u8>>)],
) -> std::io::Result<u64> {
    let pattern_refs: Vec<(&str, &[u8])> = secrets
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect();
    let mut r = Redactor::new(pattern_refs);
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let emit = r.feed(&buf[..n]);
        dst.write_all(&emit)?;
        total += emit.len() as u64;
    }
    let tail = r.flush();
    dst.write_all(&tail)?;
    total += tail.len() as u64;
    dst.flush()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_all(input: &[u8], pats: &[(&str, &[u8])]) -> Vec<u8> {
        let mut r = Redactor::new(pats.iter().copied());
        let mut out = r.feed(input);
        out.extend(r.flush());
        out
    }

    #[test]
    fn redacts_simple_match() {
        let out = redact_all(b"prefix SECRET suffix", &[("X", b"SECRET")]);
        assert_eq!(out, b"prefix [REDACTED:X] suffix");
    }

    #[test]
    fn redacts_multiple_occurrences() {
        let out = redact_all(b"a SECRET b SECRET c", &[("X", b"SECRET")]);
        assert_eq!(out, b"a [REDACTED:X] b [REDACTED:X] c");
    }

    #[test]
    fn handles_no_match() {
        let out = redact_all(b"nothing to see", &[("X", b"SECRET")]);
        assert_eq!(out, b"nothing to see");
    }

    #[test]
    fn redacts_across_chunk_boundary() {
        let mut r = Redactor::new([("X", b"SECRET" as &[u8])]);
        let mut out = r.feed(b"prefix SEC");
        out.extend(r.feed(b"RET suffix"));
        out.extend(r.flush());
        assert_eq!(out, b"prefix [REDACTED:X] suffix");
    }

    #[test]
    fn longest_pattern_wins() {
        let out = redact_all(
            b"AAABBB end",
            &[("SHORT", b"AAA"), ("LONG", b"AAABBB")],
        );
        assert_eq!(out, b"[REDACTED:LONG] end");
    }

    #[test]
    fn special_char_value_redacted() {
        let val: &[u8] = b"p@ssw\"rd$with$specials";
        let out = redact_all(b"got: [p@ssw\"rd$with$specials]", &[("X", val)]);
        assert_eq!(out, b"got: [[REDACTED:X]]");
    }

    #[test]
    fn copy_redacting_streams() {
        let val: &[u8] = b"TOPSECRET";
        let input = b"alpha TOPSECRET beta TOPSECRET gamma".to_vec();
        let mut output = Vec::new();
        let secrets = vec![("X".to_string(), Zeroizing::new(val.to_vec()))];
        copy_redacting(&input[..], &mut output, &secrets).unwrap();
        assert_eq!(output, b"alpha [REDACTED:X] beta [REDACTED:X] gamma");
    }
}
