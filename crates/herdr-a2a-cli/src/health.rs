use std::{
    io::{self, Read, Write},
    net::{SocketAddrV4, TcpStream},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::DynError;

const HEALTH_PROOF_HEADER: &str = "x-herdr-a2a-health-proof";
const HEALTH_INSTANCE_HEADER: &str = "x-herdr-a2a-instance";
const HEALTH_PROOF_DOMAIN: &[u8] = b"herdr-a2a-proof-v2\0";
const NONCE_BYTES: usize = 32;
const MAX_SYNC_RESPONSE_HEADER_BYTES: usize = 8 * 1024;

fn fresh_nonce() -> Result<([u8; NONCE_BYTES], String), DynError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|error| io::Error::other(format!("secure randomness unavailable: {error}")))?;
    let encoded = URL_SAFE_NO_PAD.encode(nonce);
    Ok((nonce, encoded))
}

fn instance_id_is_valid(broker_instance_id: &str) -> bool {
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(broker_instance_id) else {
        return false;
    };
    broker_instance_id.len() == 43
        && decoded.len() == 32
        && URL_SAFE_NO_PAD.encode(decoded) == broker_instance_id
}

fn proof_is_valid(
    bearer_token: &str,
    broker_instance_id: &str,
    nonce: &[u8; NONCE_BYTES],
    encoded_proof: &str,
) -> bool {
    if !instance_id_is_valid(broker_instance_id) {
        return false;
    }
    let Ok(proof) = URL_SAFE_NO_PAD.decode(encoded_proof) else {
        return false;
    };
    if proof.len() != 32 || URL_SAFE_NO_PAD.encode(&proof) != encoded_proof {
        return false;
    }
    let key = Sha256::digest(bearer_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("SHA-256 digest is a valid HMAC key");
    mac.update(HEALTH_PROOF_DOMAIN);
    mac.update(broker_instance_id.as_bytes());
    mac.update(nonce);
    let expected = mac.finalize().into_bytes();
    bool::from(proof.as_slice().ct_eq(expected.as_slice()))
}

pub(crate) async fn verify_broker_proof(
    client: &Client,
    base_url: &str,
    bearer_token: &str,
    broker_instance_id: &str,
) -> Result<(), DynError> {
    if !instance_id_is_valid(broker_instance_id) {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "broker instance ID is invalid").into(),
        );
    }
    let (nonce, encoded_nonce) = fresh_nonce()?;
    let proof_url = format!("{base_url}/health/proof/{encoded_nonce}");
    let response = client.get(&proof_url).send().await?;
    if response.url().as_str() != proof_url {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker identity proof changed origin or URL",
        )
        .into());
    }
    if response.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker identity proof was rejected",
        )
        .into());
    }
    let mut proofs = response.headers().get_all(HEALTH_PROOF_HEADER).iter();
    let proof = proofs
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|_| proofs.next().is_none())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker identity proof header is missing or malformed",
            )
        })?;
    let mut instances = response.headers().get_all(HEALTH_INSTANCE_HEADER).iter();
    let response_instance = instances
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|_| instances.next().is_none())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker instance header is missing or malformed",
            )
        })?;
    if response_instance != broker_instance_id
        || !proof_is_valid(bearer_token, broker_instance_id, &nonce, proof)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "broker identity proof is invalid",
        )
        .into());
    }
    Ok(())
}

pub(crate) fn verify_broker_proof_sync(
    base_url: &str,
    bearer_token: &str,
    broker_instance_id: &str,
    timeout: Duration,
) -> bool {
    if !instance_id_is_valid(broker_instance_id) {
        return false;
    }
    let Some(address) = base_url
        .strip_prefix("http://")
        .and_then(|origin| origin.parse::<SocketAddrV4>().ok())
    else {
        return false;
    };
    let Ok((nonce, encoded_nonce)) = fresh_nonce() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    let Ok(mut connection) = TcpStream::connect_timeout(&address.into(), timeout) else {
        return false;
    };
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return false;
    };
    if connection.set_write_timeout(Some(remaining)).is_err() {
        return false;
    }
    let request = format!(
        "GET /health/proof/{encoded_nonce} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    );
    if connection.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while headers.len() < MAX_SYNC_RESPONSE_HEADER_BYTES
        && !headers.windows(4).any(|window| window == b"\r\n\r\n")
    {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        if connection.set_read_timeout(Some(remaining)).is_err() {
            return false;
        }
        match connection.read(&mut byte) {
            Ok(0) | Err(_) => return false,
            Ok(_) => headers.push(byte[0]),
        }
    }
    if !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        return false;
    }
    let Ok(headers) = std::str::from_utf8(&headers) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    if !status
        .strip_prefix("HTTP/1.1 200")
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(' '))
    {
        return false;
    }
    let mut proof = None;
    let mut response_instance = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.eq_ignore_ascii_case(HEALTH_PROOF_HEADER) && proof.replace(value.trim()).is_some() {
            return false;
        }
        if name.eq_ignore_ascii_case(HEALTH_INSTANCE_HEADER)
            && response_instance.replace(value.trim()).is_some()
        {
            return false;
        }
    }
    response_instance == Some(broker_instance_id)
        && proof
            .is_some_and(|proof| proof_is_valid(bearer_token, broker_instance_id, &nonce, proof))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use reqwest::Client;
    use sha2::{Digest, Sha256};

    use super::{
        HEALTH_PROOF_DOMAIN, proof_is_valid, verify_broker_proof, verify_broker_proof_sync,
    };

    const TOKEN: &str = "test-private-bearer-token";
    const INSTANCE_ID: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
    const OTHER_INSTANCE_ID: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
    const PROOF: &str = "iCUUJsJp_Vu75rupynVWPU4WuJj6dFQcV7DGxOnvZrc";

    #[test]
    fn proof_validation_accepts_the_protocol_vector() {
        // Break caught: the client derives a different HMAC key/message or decodes the proof
        // differently from the broker protocol.
        assert!(proof_is_valid(TOKEN, INSTANCE_ID, &[0x11; 32], PROOF));
    }

    #[test]
    fn proof_validation_rejects_wrong_replayed_and_malformed_proofs() {
        // Break caught: a proof is accepted for the wrong descriptor token, a fresh nonce, or a
        // noncanonical/malformed proof header.
        assert!(!proof_is_valid(
            "wrong-token",
            INSTANCE_ID,
            &[0x11; 32],
            PROOF
        ));
        assert!(!proof_is_valid(
            TOKEN,
            OTHER_INSTANCE_ID,
            &[0x11; 32],
            PROOF
        ));
        assert!(!proof_is_valid(TOKEN, INSTANCE_ID, &[0x12; 32], PROOF));
        assert!(!proof_is_valid(
            TOKEN,
            INSTANCE_ID,
            &[0x11; 32],
            "not-base64!"
        ));
        assert!(!proof_is_valid(
            TOKEN,
            INSTANCE_ID,
            &[0x11; 32],
            &format!("{PROOF}=")
        ));
        assert!(!proof_is_valid(TOKEN, INSTANCE_ID, &[0x11; 32], ""));
    }

    #[test]
    fn proof_validation_rejects_instance_less_hmac() {
        // Break caught: dropping the instance ID from the v2 HMAC makes one proof valid for every
        // broker generation that happens to share the bearer token and nonce.
        const INSTANCE_LESS_PROOF: &str = "BBhkKgLtrqvqM5bKsCncO0T1pNk-5xWvPwLIkyRtNtc";
        assert!(!proof_is_valid(
            TOKEN,
            OTHER_INSTANCE_ID,
            &[0x11; 32],
            INSTANCE_LESS_PROOF,
        ));
    }

    #[tokio::test]
    async fn proof_probes_reject_invalid_instance_ids_before_network_access() {
        // Break caught: malformed or old instance IDs reach an untrusted endpoint before the
        // descriptor identity is proven to be a canonical 32-byte value.
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for invalid in [
            "",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi+",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi",
        ] {
            assert!(
                verify_broker_proof(&client, "http://127.0.0.1:9", TOKEN, invalid)
                    .await
                    .is_err(),
                "async proof accepted {invalid:?}"
            );
            assert!(!verify_broker_proof_sync(
                "http://127.0.0.1:9",
                TOKEN,
                invalid,
                Duration::from_millis(1),
            ));
        }
    }

    #[tokio::test]
    async fn valid_proof_for_the_wrong_instance_is_rejected_without_bearer_disclosure() {
        // Break caught: a process that knows the token can replay its valid proof as a different
        // descriptor instance, or the proof request itself discloses the bearer before proof.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                connection.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request_text = String::from_utf8(request).unwrap();
            let nonce = request_text
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .strip_prefix("/health/proof/")
                .unwrap();
            let nonce = URL_SAFE_NO_PAD.decode(nonce).unwrap();
            let key = Sha256::digest(TOKEN.as_bytes());
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(HEALTH_PROOF_DOMAIN);
            mac.update(OTHER_INSTANCE_ID.as_bytes());
            mac.update(&nonce);
            let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
            let response = format!(
                "HTTP/1.1 200 OK\r\nx-herdr-a2a-health-proof: {proof}\r\nx-herdr-a2a-instance: {OTHER_INSTANCE_ID}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            connection.write_all(response.as_bytes()).unwrap();
            request_tx.send(request_text).unwrap();
        });
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        assert!(
            verify_broker_proof(&client, &format!("http://{address}"), TOKEN, INSTANCE_ID,)
                .await
                .is_err()
        );
        let request = request_rx.recv().unwrap();
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.contains(TOKEN));
        server.join().unwrap();
    }

    #[test]
    fn synchronous_proof_probe_has_a_wall_clock_bound_against_slow_drip() {
        // Break caught: applying the timeout separately to every response byte lets a listener
        // keep broker startup blocked indefinitely by sending bytes just before each deadline.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                connection.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            for byte in b"HTTP/1.1 200 OK\r\nx-herdr-a2a-health-proof: never-completes\r\n\r\n" {
                thread::sleep(Duration::from_millis(30));
                if connection.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();

        assert!(!verify_broker_proof_sync(
            &format!("http://{address}"),
            TOKEN,
            INSTANCE_ID,
            Duration::from_millis(50),
        ));
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "probe exceeded its wall-clock bound: {:?}",
            started.elapsed()
        );
        server.join().unwrap();
    }
}
