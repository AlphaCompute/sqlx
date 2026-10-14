use crate::connection::stream::PgStream;
use crate::error::Error;
use crate::message::{Authentication, AuthenticationSasl, SaslInitialResponse, SaslResponse};
use crate::rt;
use crate::{PgChannelBinding, PgConnectOptions};
use hmac::{Hmac, Mac};
use hmac::{HmacReset, KeyInit};
use sha2::{Digest, Sha256, Sha384, Sha512};
use stringprep::saslprep;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use rand::RngExt;

const CHANNEL_ATTR: &str = "c";
const USERNAME_ATTR: &str = "n";
const CLIENT_PROOF_ATTR: &str = "p";
const NONCE_ATTR: &str = "r";

pub(crate) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationSasl,
) -> Result<(), Error> {
    let mut has_sasl = false;
    let mut has_sasl_plus = false;
    let mut unknown = Vec::new();

    for mechanism in data.mechanisms() {
        match mechanism {
            "SCRAM-SHA-256" => {
                has_sasl = true;
            }

            "SCRAM-SHA-256-PLUS" => {
                has_sasl_plus = true;
            }

            _ => {
                unknown.push(mechanism.to_owned());
            }
        }
    }

    if !has_sasl_plus && !has_sasl {
        return Err(err_protocol!(
            "unsupported SASL authentication mechanisms: {}",
            unknown.join(", ")
        ));
    }

    let end_point = match options.channel_binding {
        PgChannelBinding::Disable => None,
        _ => stream
            .socket()
            .peer_certificate()
            .and_then(|cert| tls_server_end_point(&cert)),
    };
    let (gs2_header, cbind_data) =
        channel_binding(options.channel_binding, has_sasl, has_sasl_plus, end_point)?;

    // channel-binding = "c=" base64(gs2-header [cbind-data])
    let mut channel_binding = format!("{CHANNEL_ATTR}=");
    BASE64_STANDARD.encode_string(
        [
            gs2_header.as_bytes(),
            cbind_data.as_deref().unwrap_or_default(),
        ]
        .concat(),
        &mut channel_binding,
    );

    // "n=" saslname ;; Usernames are prepared using SASLprep.
    let username = format!("{}={}", USERNAME_ATTR, options.username);
    let username = match saslprep(&username) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep username: {:?}", error).into(),
            ))
        }
    };

    // nonce = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    let nonce = gen_nonce();

    // client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
    let client_first_message_bare = format!("{username},{nonce}");

    let client_first_message = format!("{gs2_header}{client_first_message_bare}");

    stream
        .send(SaslInitialResponse {
            response: &client_first_message,
            plus: cbind_data.is_some(),
        })
        .await?;

    let cont = match stream.recv_expect().await? {
        Authentication::SaslContinue(data) => data,

        auth => {
            return Err(err_protocol!(
                "expected SASLContinue but received {:?}",
                auth
            ));
        }
    };

    // Normalize(password):
    let password = options.password.as_deref().unwrap_or_default();
    let password = match saslprep(password) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep password: {:?}", error).into(),
            ))
        }
    };

    // SaltedPassword := Hi(Normalize(password), salt, i)
    let salted_password = hi(&password, &cont.salt, cont.iterations).await?;

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Client Key");

    let client_key = mac.finalize().into_bytes();

    // StoredKey := H(ClientKey)
    let stored_key = Sha256::digest(client_key);

    // client-final-message-without-proof
    let client_final_message_wo_proof = format!(
        "{channel_binding},r={nonce}",
        channel_binding = channel_binding,
        nonce = &cont.nonce
    );

    // AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
    let auth_message = format!(
        "{client_first_message_bare},{server_first_message},{client_final_message_wo_proof}",
        client_first_message_bare = client_first_message_bare,
        server_first_message = cont.message,
        client_final_message_wo_proof = client_final_message_wo_proof
    );

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&stored_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    let client_signature = mac.finalize().into_bytes();

    // ClientProof := ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Server Key");

    let server_key = mac.finalize().into_bytes();

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&server_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    // client-final-message = client-final-message-without-proof "," proof
    let mut client_final_message = format!("{client_final_message_wo_proof},{CLIENT_PROOF_ATTR}=");
    BASE64_STANDARD.encode_string(client_proof, &mut client_final_message);

    stream.send(SaslResponse(&client_final_message)).await?;

    let data = match stream.recv_expect().await? {
        Authentication::SaslFinal(data) => data,

        auth => {
            return Err(err_protocol!("expected SASLFinal but received {:?}", auth));
        }
    };

    // authentication is only considered valid if this verification passes
    mac.verify_slice(&data.verifier).map_err(Error::protocol)?;

    Ok(())
}

/// Picks the GS2 header and, for `SCRAM-SHA-256-PLUS`, the channel binding data.
fn channel_binding(
    mode: PgChannelBinding,
    server_offers_scram: bool,
    server_offers_plus: bool,
    end_point: Option<Vec<u8>>,
) -> Result<(&'static str, Option<Vec<u8>>), Error> {
    match (end_point, server_offers_plus) {
        (Some(end_point), true) => Ok(("p=tls-server-end-point,,", Some(end_point))),
        _ if mode == PgChannelBinding::Require => Err(err_protocol!(
            "channel binding is required, but the connection is not over TLS with a usable \
             server certificate, or the server does not offer SCRAM-SHA-256-PLUS"
        )),
        _ if !server_offers_scram => Err(err_protocol!(
            "the server offers only SCRAM-SHA-256-PLUS, but channel binding is disabled or the \
             connection is not over TLS with a usable server certificate"
        )),
        // "y": the client supports channel binding but thinks the server does not, so a server
        // that does support it detects the downgrade.
        (Some(_), false) => Ok(("y,,", None)),
        (None, _) => Ok(("n,,", None)),
    }
}

/// `tls-server-end-point` (RFC 5929): the certificate's hash under its signature's hash
/// function, SHA-256 for MD5 and SHA-1. `None` for signatures without one, like Ed25519.
fn tls_server_end_point(cert: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (certificate, _) = der_element(cert, 0x30)?;
    let (_tbs, rest) = der_element(certificate, 0x30)?;
    let (algorithm, _) = der_element(rest, 0x30)?;
    let (oid, _) = der_element(algorithm, 0x06)?;

    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    const ECDSA_SHA2: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];
    const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04];

    let (&last, prefix) = oid.split_last()?;
    let hash = match (last, prefix) {
        // {md5,sha1,sha256}WithRSAEncryption, ecdsa-with-SHA1, ecdsa-with-SHA256
        (4 | 5 | 11, RSA) | (1, ECDSA) | (2, ECDSA_SHA2) => Sha256::digest(cert).to_vec(),
        (12, RSA) => Sha384::digest(cert).to_vec(),
        (13, RSA) => Sha512::digest(cert).to_vec(),
        (3, ECDSA_SHA2) => Sha384::digest(cert).to_vec(),
        (4, ECDSA_SHA2) => Sha512::digest(cert).to_vec(),
        _ => return None,
    };
    Some(hash)
}

/// Splits a DER element with the given tag off `input`: its contents and what follows it.
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, input) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, input) = input.split_first()?;
    let (len, input) = if first < 0x80 {
        (usize::from(first), input)
    } else {
        let (len_bytes, input) = input.split_at_checked(usize::from(first & 0x7f))?;
        if len_bytes.is_empty() || len_bytes.len() > size_of::<usize>() {
            return None;
        }
        let len = len_bytes
            .iter()
            .fold(0usize, |len, &b| (len << 8) | usize::from(b));
        (len, input)
    };
    input.split_at_checked(len)
}

// nonce is a sequence of random printable bytes
fn gen_nonce() -> String {
    let mut rng = rand::rng();
    let count = rng.random_range(64..128);

    // printable = %x21-2B / %x2D-7E
    // ;; Printable ASCII except ",".
    // ;; Note that any "printable" is also
    // ;; a valid "value".
    let nonce: String = std::iter::repeat(())
        .map(|()| {
            let mut c = rng.random_range(0x21u8..0x7F);

            while c == 0x2C {
                c = rng.random_range(0x21u8..0x7F);
            }

            c
        })
        .take(count)
        .map(|c| c as char)
        .collect();

    format!("{NONCE_ATTR}={nonce}")
}

// Hi(str, salt, i):
async fn hi<'a>(s: &'a str, salt: &'a [u8], iter_count: u32) -> Result<[u8; 32], Error> {
    let mut mac = HmacReset::<Sha256>::new_from_slice(s.as_bytes()).map_err(Error::protocol)?;

    mac.update(salt);
    mac.update(&1u32.to_be_bytes());

    let mut u = mac.finalize_reset().into_bytes();
    let mut hi = u;

    for i in 1..iter_count {
        mac.update(u.as_slice());
        u = mac.finalize_reset().into_bytes();
        hi = hi.iter().zip(u.iter()).map(|(&a, &b)| a ^ b).collect();

        // For large iteration counts, this process can take a long time and block the event loop.
        // It was measured as taking ~50ms for 4096 iterations (the default) on a developer machine.
        // If we want to yield every 10-100us (as generally advised for tokio), then we can yield
        // every 5 iterations which should be every ~50us.
        if i % 5 == 0 {
            rt::yield_now().await;
        }
    }

    Ok(hi.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(pem: &str) -> Vec<u8> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        BASE64_STANDARD.decode(body).unwrap()
    }

    #[test]
    fn it_hashes_the_certificate_with_its_signature_hash() {
        let rsa_sha256 = der(include_str!("../../../tests/certs/rsa/server.crt"));
        assert_eq!(
            tls_server_end_point(&rsa_sha256),
            Some(Sha256::digest(&rsa_sha256).to_vec())
        );

        let ecdsa_sha384 = BASE64_STANDARD.decode("MIIBqzCCATKgAwIBAgIUcOPlxgwlO8iwJ0pUOnwPvgsJzdUwCgYIKoZIzj0EAwMwDDEKMAgGA1UEAwwBeDAgFw0yNjEwMTQwNTEwMjFaGA8yMTI2MDkyMDA1MTAyMVowDDEKMAgGA1UEAwwBeDB2MBAGByqGSM49AgEGBSuBBAAiA2IABLlNkQsuEYOBN4Dt6xipnEOuO8zHD2XMLtqPISM02bLYwk+veZwkMm0pi91uIMJF2p38BC0CQVXA3xLSSyBnGn8NWQ1wrZh/9Q/SwHb7/MaQiUwWWTnmIaaqURL/hV43k6NTMFEwHQYDVR0OBBYEFHkbeaWps1dKGxtFykxfVT+oZnRYMB8GA1UdIwQYMBaAFHkbeaWps1dKGxtFykxfVT+oZnRYMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDZwAwZAIwEik4/zVyEmnumLnxJwr4dHOZzMpA3zHPwIFMrIN0yYuR+gWPK06vs81D/+N10zUiAjAj3XLoy81V+oRdpcd5NWvE8kqandQA6PQ6zhcnoCzLYqeH/sufoPk7dwBuInpts1s=").unwrap();
        assert_eq!(
            tls_server_end_point(&ecdsa_sha384),
            Some(Sha384::digest(&ecdsa_sha384).to_vec())
        );

        let ed25519 = der(include_str!("../../../tests/certs/server.crt"));
        assert_eq!(tls_server_end_point(&ed25519), None);
        assert_eq!(
            tls_server_end_point(&rsa_sha256[..rsa_sha256.len() - 1]),
            None
        );
    }

    #[test]
    fn it_binds_to_the_end_point_when_the_server_offers_plus() {
        let end_point = Some(vec![0xab; 32]);
        for mode in [PgChannelBinding::Prefer, PgChannelBinding::Require] {
            assert_eq!(
                channel_binding(mode, true, true, end_point.clone()).unwrap(),
                ("p=tls-server-end-point,,", end_point.clone())
            );
        }
    }

    #[test]
    fn it_falls_back_without_plus_unless_required() {
        let end_point = Some(vec![0xab; 32]);
        assert_eq!(
            channel_binding(PgChannelBinding::Prefer, true, false, end_point.clone()).unwrap(),
            ("y,,", None)
        );
        assert_eq!(
            channel_binding(PgChannelBinding::Prefer, true, true, None).unwrap(),
            ("n,,", None)
        );

        assert!(channel_binding(PgChannelBinding::Require, true, false, end_point).is_err());
        assert!(channel_binding(PgChannelBinding::Require, true, true, None).is_err());
        assert!(channel_binding(PgChannelBinding::Prefer, false, true, None).is_err());
    }
}
