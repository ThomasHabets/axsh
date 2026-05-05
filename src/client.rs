use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    ClientHello, ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, ServerHello, hdlc,
    random_u64, transport::PayloadStream,
};

/// Wrap an async byte stream with the client handshake and payload packet transport.
pub struct ClientStream<T> {
    server_hello: ServerHello,
    transport: PayloadStream<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> ClientStream<T> {
    /// Complete the client handshake over `stream` after checking the server key.
    pub async fn new(
        stream: T,
        conn_sign: ConnSign,
        expected_server_conn_sign_public_key: &[u8],
    ) -> std::io::Result<Self> {
        Self::new_with_server_hello_validator(stream, conn_sign, |server_hello| {
            if server_hello.conn_sign_public_key() != expected_server_conn_sign_public_key {
                return Err(std::io::Error::other(
                    "server ConnSign key does not match known-hosts entry",
                ));
            }
            Ok(())
        })
        .await
    }

    /// Complete the client handshake over `stream` after validating `ServerHello`.
    pub async fn new_with_server_hello_validator<F>(
        mut stream: T,
        conn_sign: ConnSign,
        validate_server_hello: F,
    ) -> std::io::Result<Self>
    where
        F: FnOnce(&ServerHello) -> std::io::Result<()>,
    {
        let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;

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
        log::debug!(
            "received ServerHello: server_unique={}, conn_key={} bytes, packet_key={} bytes",
            server_hello.unique(),
            server_hello.conn_sign_public_key().len(),
            server_hello.packet_sign_public_key().len()
        );
        validate_server_hello(&server_hello)?;
        // Set up verifiers from ServerHello.
        let server_conn_verify = ConnVerify::new(server_hello.conn_sign_public_key().to_vec());
        let server_packet_verify = PacketVerify::new(server_hello.packet_sign_public_key());

        // Reply with ClientHello.
        let packet = Packet::ClientHello(ClientHello::new(
            server_hello.unique(),
            random_u64()?,
            conn_sign
                .public_key_bytes()
                .map_err(std::io::Error::other)?,
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
                log::debug!(
                    "received ServerComplete: signature={} bytes",
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
    use crate::{ConnSign, ServerStream};
    use std::collections::HashSet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_and_server_streams_handshake_and_transport_payloads() -> std::io::Result<()> {
        let server_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let client_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let authorized_keys = HashSet::from([client_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?]);
        let (server_stream, client_stream) = tokio::io::duplex(4096);
        let expected_server_payloads = [b"server payload one".as_slice(), b"server payload two"];
        let expected_server_key = server_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;

        let server = tokio::spawn(async move {
            let mut server =
                ServerStream::new(server_stream, &server_conn_sign, &authorized_keys).await?;
            assert_eq!(
                server.client_hello().conn_sign_public_key(),
                authorized_keys.iter().next().expect("missing key")
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

        let mut client =
            ClientStream::new(client_stream, client_conn_sign, &expected_server_key).await?;

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
        let wrong_server_key = ConnSign::new()
            .and_then(|sign| sign.public_key_bytes())
            .map_err(std::io::Error::other)?;
        let authorized_keys = HashSet::from([client_conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?]);
        let (server_stream, client_stream) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            ServerStream::new(server_stream, &server_conn_sign, &authorized_keys)
                .await
                .map(|_| ())
        });

        let Err(err) = ClientStream::new(client_stream, client_conn_sign, &wrong_server_key).await
        else {
            panic!("client accepted unexpected server key")
        };
        assert!(
            err.to_string().contains("known-hosts"),
            "unexpected error: {err}"
        );

        let server_result = server.await.expect("server task panicked");
        assert!(
            server_result.is_err(),
            "server unexpectedly completed handshake"
        );
        Ok(())
    }
}
