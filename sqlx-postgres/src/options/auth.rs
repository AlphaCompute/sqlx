use crate::error::Error;
use std::str::FromStr;

/// Whether SCRAM authentication binds itself to the TLS connection, as libpq's
/// `channel_binding`.
///
/// It is used by the [`channel_binding`](super::PgConnectOptions::channel_binding) method.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PgChannelBinding {
    /// Never use channel binding.
    Disable,

    /// Use `SCRAM-SHA-256-PLUS` with `tls-server-end-point` when the connection is over TLS and
    /// the server offers it.
    ///
    /// This is the default if no other mode is specified.
    #[default]
    Prefer,

    /// Fail unless the server authenticates with `SCRAM-SHA-256-PLUS`. This refuses every other
    /// authentication request, and a server that skips authentication.
    Require,
}

impl FromStr for PgChannelBinding {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match &*s.to_ascii_lowercase() {
            "disable" => PgChannelBinding::Disable,
            "prefer" => PgChannelBinding::Prefer,
            "require" => PgChannelBinding::Require,

            _ => {
                return Err(Error::Configuration(
                    format!("unknown value {s:?} for `channel_binding`").into(),
                ));
            }
        })
    }
}

/// An authentication method the server may ask for, as named in libpq's `require_auth`.
///
/// It is used by the [`require_auth`](super::PgConnectOptions::require_auth) method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAuthMethod {
    /// The server does not ask for authentication.
    None,
    /// A cleartext password.
    Password,
    /// An MD5-hashed password.
    Md5,
    /// SASL `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS`.
    ScramSha256,
}

impl PgAuthMethod {
    const ALL: [PgAuthMethod; 4] = [
        PgAuthMethod::None,
        PgAuthMethod::Password,
        PgAuthMethod::Md5,
        PgAuthMethod::ScramSha256,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            PgAuthMethod::None => "none",
            PgAuthMethod::Password => "password",
            PgAuthMethod::Md5 => "md5",
            PgAuthMethod::ScramSha256 => "scram-sha-256",
        }
    }

    /// Parses libpq's `require_auth`: a comma-separated list of methods to allow, or of methods
    /// to forbid, each prefixed with `!`.
    pub(crate) fn parse_list(s: &str) -> Result<Vec<PgAuthMethod>, Error> {
        let mut negated = None;
        let mut listed = Vec::new();
        for item in s.split(',') {
            let (negate, name) = match item.strip_prefix('!') {
                Some(name) => (true, name),
                None => (false, item),
            };
            if *negated.get_or_insert(negate) != negate {
                return Err(Error::Configuration(
                    "`require_auth` cannot mix negated and non-negated methods".into(),
                ));
            }
            let method = Self::ALL
                .into_iter()
                .find(|m| m.name() == name)
                .ok_or_else(|| {
                    Error::Configuration(
                        format!("unknown method {name:?} for `require_auth`").into(),
                    )
                })?;
            listed.push(method);
        }
        Ok(if negated == Some(true) {
            Self::ALL
                .into_iter()
                .filter(|m| !listed.contains(m))
                .collect()
        } else {
            listed
        })
    }
}

#[test]
fn it_parses_require_auth() {
    use PgAuthMethod::*;

    assert_eq!(
        PgAuthMethod::parse_list("scram-sha-256").unwrap(),
        [ScramSha256]
    );
    assert_eq!(
        PgAuthMethod::parse_list("md5,none").unwrap(),
        [Md5, PgAuthMethod::None]
    );
    assert_eq!(
        PgAuthMethod::parse_list("!password,!md5").unwrap(),
        [PgAuthMethod::None, ScramSha256]
    );
    assert!(PgAuthMethod::parse_list("!password,md5").is_err());
    assert!(PgAuthMethod::parse_list("gss").is_err());
    assert!(PgAuthMethod::parse_list("").is_err());
}
