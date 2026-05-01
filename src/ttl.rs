use anyhow::{anyhow, Result};

pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty duration"));
    }
    let (num_str, unit) = s.split_at(
        s.find(|c: char| c.is_alphabetic())
            .unwrap_or(s.len()),
    );
    let n: u64 = num_str
        .parse()
        .map_err(|_| anyhow!("invalid duration number: {num_str}"))?;
    let mult: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(anyhow!("unknown duration unit: {other}; use s/m/h/d")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("duration overflow"))
}

pub fn humanize_remaining(secs: u64) -> String {
    if secs >= 86400 {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h > 0 { format!("{d}d{h}h") } else { format!("{d}d") }
    } else if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 { format!("{h}h{m}m") } else { format!("{h}h") }
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("20d").unwrap(), 20 * 86400);
        assert_eq!(parse_duration("100").unwrap(), 100);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
    }

    #[test]
    fn humanize_round_trips_visually() {
        assert_eq!(humanize_remaining(45), "45s");
        assert_eq!(humanize_remaining(120), "2m");
        assert_eq!(humanize_remaining(3700), "1h1m");
        assert_eq!(humanize_remaining(86400 * 20), "20d");
        assert_eq!(humanize_remaining(86400 * 20 + 3600), "20d1h");
    }
}
