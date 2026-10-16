//! Bounded HTTP response bodies; request and disclosure policy stays with callers.
use crate::Result;

pub async fn body(
    mut response: reqwest::Response,
    limit: usize,
    oversized: &str,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(oversized.into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| e.without_url().to_string())?
    {
        if chunk.len() > limit - bytes.len() {
            return Err(oversized.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    #[test]
    fn limits_fixed_and_chunked_bodies_and_rejects_truncation() {
        for (reply, expected) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest",
                Some("test"),
            ),
            ("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntests", None),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nte\r\n2\r\nst\r\n0\r\n\r\n",
                Some("test"),
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nte\r\n3\r\nsts\r\n0\r\n\r\n",
                None,
            ),
            ("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nte", None),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 4096);
                }
                let _ = stream.write_all(reply.as_bytes());
            });
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let response = reqwest::Client::builder()
                        .no_proxy()
                        .timeout(Duration::from_secs(3))
                        .build()
                        .unwrap()
                        .get(format!("http://{address}"))
                        .send()
                        .await
                        .unwrap();
                    body(response, 4, "too big").await
                });
            server.join().unwrap();
            if let Some(expected) = expected {
                assert_eq!(result.unwrap(), expected.as_bytes());
            } else {
                assert!(result.is_err());
            }
        }
    }
}
