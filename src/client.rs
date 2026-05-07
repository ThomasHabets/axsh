use std::pin::Pin;
use std::task::{Context, Poll};

use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    ClientHello, ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, ServerHello,
    format_sha256_digest, hdlc, random_u64, sha256_bytes, transport::PayloadStream,
};

/// Wrap an async byte stream with the client handshake and payload packet transport.
pub struct ClientStream<T> {
    server_hello: ServerHello,
    transport: PayloadStream<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> ClientStream<T> {
    /// Complete the client handshake over `stream` after looking up or requesting the server public key.
    ///
    /// # Arguments
    ///
    /// * `stream`: The underlying stream, like AGW or TCP stream.
    /// * `conn_sign`: The connection signer for client to server
    ///   authentication.
    /// * `lookup_server_pubkey`: sha256 -> server pubkey cache lookup callback.
    /// * `accept_server_pubkey`: server pubkey verification.
    ///
    /// ## Look up server pubkey
    ///
    /// The application can use this callback to speed up the handshake, by
    /// providing the pubkey. ML-DSA-44 keys are 1312 bytes, so a cache hit here
    /// saves almost 9 seconds at 1200bps.
    ///
    /// If this function returns `None`, it falls back to downloading the full
    /// public key from the server.
    ///
    /// If this function returns `Some`, then this is the only server key
    /// allowed.
    ///
    /// ## Accept server pubkey
    ///
    /// This callback can be used to implement a `known_hosts` "do you accept
    /// this key" check.
    ///
    /// This callback doesn't need to check that the key returned by
    /// `lookup_server_pubkey` is actually the one used.
    #[allow(clippy::too_many_lines)]
    pub async fn new_with_server_pubkey_lookup<Lookup, AcceptCheck>(
        mut stream: T,
        conn_sign: ConnSign,
        lookup_server_pubkey: Lookup,
        accept_server_pubkey: AcceptCheck,
    ) -> std::io::Result<Self>
    where
        Lookup: FnOnce(&ServerHello) -> std::io::Result<Option<Vec<u8>>>,
        AcceptCheck: FnOnce(&ServerHello, &[u8]) -> std::io::Result<()>,
    {
        // Read ServerHello.
        let frame = hdlc::read_frame_async(&mut stream).await?;
        let server_hello_wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
        let packet =
            Packet::deserialize(&server_hello_wire, None, None).map_err(std::io::Error::other)?;
        let Packet::ServerHello(server_hello) = packet else {
            return Err(std::io::Error::other(format!(
                "expected ServerHello, got {packet:?}"
            )));
        };
        debug!(
            "axsh: Received ServerHello: server_unique={}, conn_key={}, packet_key={} bytes",
            server_hello.unique(),
            format_sha256_digest(&server_hello.conn_sign_public_key_sha256()),
            server_hello.packet_sign_public_key().len()
        );

        // Get server connection public key from cache or by requesting it.
        let server_conn_sign_public_key = if let Some(public_key) =
            lookup_server_pubkey(&server_hello)?
        {
            debug!(
                "axsh: Server key matching {} found in cache",
                format_sha256_digest(&server_hello.conn_sign_public_key_sha256()),
            );
            public_key
        } else {
            debug!(
                "axsh: Requesting key matching {}",
                format_sha256_digest(&server_hello.conn_sign_public_key_sha256()),
            );

            // Request public key.
            let request = Packet::RequestServerPubkey
                .serialize(&conn_sign)
                .map_err(std::io::Error::other)?;
            stream.write_all(&hdlc::encode(&request)).await?;
            stream.flush().await?;

            // Retrieve public key.
            let frame = hdlc::read_frame_async(&mut stream).await?;
            let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&wire, None, None).map_err(std::io::Error::other)?;
            let Packet::ServerPubkey(server_pubkey) = packet else {
                return Err(std::io::Error::other(format!(
                    "expected ServerPubkey, got {packet:?}"
                )));
            };
            debug!("axsh: Receiver ServerPubkey");
            server_pubkey.conn_sign_public_key().to_vec()
        };

        // Confirm that we actually got the public key mentioned in `ServerHello`.
        {
            let hash = sha256_bytes(&server_conn_sign_public_key);
            if server_hello.conn_sign_public_key_sha256() != hash {
                return Err(std::io::Error::other(format!(
                    "server ConnSign key hash does not match ServerHello digest (presented {})",
                    format_sha256_digest(&server_hello.conn_sign_public_key_sha256())
                )));
            }
        }

        // Ask application if this is a acceptable public key.
        accept_server_pubkey(&server_hello, &server_conn_sign_public_key)?;

        let server_conn_verify = ConnVerify::new(server_conn_sign_public_key);
        let server_packet_verify = PacketVerify::new(server_hello.packet_sign_public_key());

        // Generate packet signing keypair for client.
        let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
        let client_conn_sign_public_key = conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;

        // Reply with ClientHello.
        let packet = Packet::ClientHello(ClientHello::new(
            server_hello.unique(),
            random_u64()?,
            sha256_bytes(&client_conn_sign_public_key),
            packet_sign.public_key_bytes(),
        ));
        let client_hello_wire = packet
            .serialize(&conn_sign)
            .map_err(std::io::Error::other)?;
        let frame = hdlc::encode(&client_hello_wire);
        stream.write_all(&frame).await?;
        stream.flush().await?;

        // Read ServerComplete.
        let frame = hdlc::read_frame_async(&mut stream).await?;
        let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
        let packet = Packet::deserialize(&wire, None, None).map_err(std::io::Error::other)?;
        match packet {
            Packet::ServerComplete(complete) => {
                debug!(
                    "axsh: received ServerComplete: signature={} bytes",
                    complete.signature().len()
                );
                let mut transcript = server_hello_wire;
                transcript.extend(&client_hello_wire);
                if !server_conn_verify.verify_detached(complete.signature(), &transcript) {
                    return Err(std::io::Error::other(
                        "server complete transcript signature verification failed",
                    ));
                }
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "expected ServerComplete, got {other:?}"
                )));
            }
        }

        Ok(Self {
            server_hello,
            transport: PayloadStream::new(stream, packet_sign, server_packet_verify),
        })
    }

    /// Return the negotiated server hello.
    pub fn server_hello(&self) -> &ServerHello {
        &self.server_hello
    }

    /// Return the underlying stream.
    pub fn into_inner(self) -> T {
        self.transport.into_inner()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().transport.poll_read_payload(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().transport.poll_write_payload(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().transport.poll_flush_payload(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().transport.poll_shutdown_payload(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::ClientStream;
    use crate::{ConnSign, ServerStream, sha256_bytes};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn authorized_keys(conn_sign: &ConnSign) -> std::io::Result<HashMap<[u8; 32], Vec<u8>>> {
        let public_key = conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;
        Ok(HashMap::from([(sha256_bytes(&public_key), public_key)]))
    }

    #[tokio::test]
    async fn client_and_server_streams_handshake_and_transport_payloads() -> std::io::Result<()> {
        let server_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let client_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let authorized_keys = authorized_keys(&client_conn_sign)?;
        let (server_stream, client_stream) = tokio::io::duplex(4096);
        let expected_server_payloads = [b"server payload one".as_slice(), b"server payload two"];
        let expected_server_key = server_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;
        let expected_client_key = client_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;

        let server = tokio::spawn(async move {
            let mut server =
                ServerStream::new(server_stream, &server_conn_sign, &authorized_keys).await?;
            assert_eq!(
                server.client_hello().conn_sign_public_key_sha256(),
                sha256_bytes(&expected_client_key)
            );

            for payload in expected_server_payloads {
                server.write_all(payload).await?;
                server.flush().await?;
            }

            let mut received = vec![0u8; b"client payload one".len()];
            server.read_exact(&mut received).await?;
            assert_eq!(received, b"client payload one");

            let mut received = vec![0u8; b"client payload two".len()];
            server.read_exact(&mut received).await?;
            assert_eq!(received, b"client payload two");
            Ok::<(), std::io::Error>(())
        });

        let mut client = ClientStream::new_with_server_pubkey_lookup(
            client_stream,
            client_conn_sign,
            |_| Ok(None),
            |_server_hello, key| {
                if key != expected_server_key {
                    return Err(std::io::Error::other(
                        "server ConnSign key does not match known-hosts entry",
                    ));
                }
                Ok(())
            },
        )
        .await?;

        let mut received = vec![0u8; b"server payload one".len()];
        client.read_exact(&mut received).await?;
        assert_eq!(received, b"server payload one");

        let mut received = vec![0u8; b"server payload two".len()];
        client.read_exact(&mut received).await?;
        assert_eq!(received, b"server payload two");

        client.write_all(b"client payload one").await?;
        client.flush().await?;
        client.write_all(b"client payload two").await?;
        client.flush().await?;
        server.await.expect("server task panicked")?;
        Ok(())
    }

    #[tokio::test]
    async fn client_stream_rejects_unknown_server_key() -> std::io::Result<()> {
        let server_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let client_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let authorized_keys = authorized_keys(&client_conn_sign)?;
        let (server_stream, client_stream) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            ServerStream::new(server_stream, &server_conn_sign, &authorized_keys)
                .await
                .map(|_| ())
        });

        let Err(err) = ClientStream::new_with_server_pubkey_lookup(
            client_stream,
            client_conn_sign,
            |_| Ok(None),
            |server_hello, key| {
                assert_eq!(
                    server_hello.conn_sign_public_key_sha256(),
                    crate::sha256_bytes(key)
                );
                Err(std::io::Error::other("ServerHello digest mismatched"))
            },
        )
        .await
        else {
            panic!("client accepted unexpected server key")
        };
        assert!(
            err.to_string().contains("ServerHello digest"),
            "unexpected error: {err}"
        );

        let server_result = server.await.expect("server task panicked");
        assert!(
            server_result.is_err(),
            "server unexpectedly completed handshake"
        );
        Ok(())
    }

    #[tokio::test]
    async fn client_stream_requests_server_pubkey_when_unknown() -> std::io::Result<()> {
        let server_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let expected_server_key = server_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;
        let client_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let authorized_keys = authorized_keys(&client_conn_sign)?;
        let (server_stream, client_stream) = tokio::io::duplex(4096);
        let seen_server_key = Arc::new(Mutex::new(None));
        let seen_server_key_for_client = Arc::clone(&seen_server_key);

        let server = tokio::spawn(async move {
            ServerStream::new(server_stream, &server_conn_sign, &authorized_keys)
                .await
                .map(|_| ())
        });

        let _client = ClientStream::new_with_server_pubkey_lookup(
            client_stream,
            client_conn_sign,
            |_server_hello| Ok(None),
            move |_server_hello, server_pubkey| {
                *seen_server_key_for_client.lock().expect("poisoned mutex") =
                    Some(server_pubkey.to_vec());
                Ok(())
            },
        )
        .await?;

        assert_eq!(
            seen_server_key.lock().expect("poisoned mutex").as_deref(),
            Some(expected_server_key.as_slice())
        );

        server.await.expect("server task panicked")?;
        Ok(())
    }
}
