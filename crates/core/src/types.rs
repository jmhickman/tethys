use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("exactly one of dst_host / dst_ip / dst_net must be set (got {0})")]
    TargetCardinality(usize),
    #[error("invalid host: {0}")]
    BadHost(String),
    #[error("invalid ip/net: {0}")]
    BadIp(#[from] std::net::AddrParseError),
    #[error("invalid net: {0}")]
    BadNet(#[from] ipnet::PrefixLenError),
    #[error("port spec: from ({from}) > to ({to})")]
    BadPortRange { from: u16, to: u16 },
    #[error("invalid ttl {0:?}: expected e.g. 30s / 15m / 2h")]
    BadTtl(String),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// String spelling accepted (and emitted) by the nft JSON API.
    pub fn nft_key(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.nft_key())
    }
}

/// Wire form: always an object; `{0,0}` means all ports.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortSpec {
    pub from: u16,
    pub to: u16,
}

impl PortSpec {
    pub fn validate(self) -> Result<Self, SpecError> {
        if self.from > self.to && !(self.from == 0 && self.to == 0) {
            return Err(SpecError::BadPortRange {
                from: self.from,
                to: self.to,
            });
        }
        Ok(self)
    }
    pub fn is_all(self) -> bool {
        self.from == 0 && self.to == 0
    }
    /// Normalized nft element range; `{0,0}` wildcard maps to full space.
    pub fn nft_range(self) -> (u16, u16) {
        if self.is_all() {
            (0, 65535)
        } else {
            (self.from, self.to)
        }
    }
}

/// A target after cardinality validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Host(String),
    Ip(IpAddr),
    Net(IpNet),
}

impl Target {
    /// Stable canonical string used for dedup keys + ledger display.
    pub fn canonical(&self) -> String {
        match self {
            Target::Host(h) => format!("host:{h}"),
            Target::Ip(i) => format!("ip:{i}"),
            Target::Net(n) => format!("net:{n}"),
        }
    }
}

/// Parse ttl grammar `Ns | Nm | Nh` (single unit only).
pub fn parse_ttl(s: &str) -> Result<Duration, SpecError> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => return Err(SpecError::BadTtl(s.to_string())),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| SpecError::BadTtl(s.to_string()))?;
    if n == 0 {
        return Err(SpecError::BadTtl(s.to_string()));
    }
    Ok(Duration::from_secs(n * mult))
}

pub fn fmt_ttl(d: Duration) -> String {
    let s = d.as_secs();
    if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_roundtrip() {
        assert_eq!(parse_ttl("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_ttl("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_ttl("15").is_err());
        assert!(parse_ttl("0m").is_err());
        assert!(parse_ttl("1d").is_err());
        assert_eq!(fmt_ttl(Duration::from_secs(900)), "15m");
        assert_eq!(fmt_ttl(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn port_validation() {
        assert_eq!(
            PortSpec { from: 80, to: 443 }.validate().unwrap().nft_range(),
            (80, 443)
        );
        let all = PortSpec { from: 0, to: 0 }.validate().unwrap();
        assert!(all.is_all());
        assert_eq!(all.nft_range(), (0, 65535));
        assert!(PortSpec { from: 443, to: 80 }.validate().is_err());
    }

    #[test]
    fn target_canonical() {
        assert_eq!(
            Target::Net("172.16.0.0/12".parse().unwrap()).canonical(),
            "net:172.16.0.0/12"
        );
        assert_eq!(
            Target::Ip("10.0.0.1".parse().unwrap()).canonical(),
            "ip:10.0.0.1"
        );
    }
}
