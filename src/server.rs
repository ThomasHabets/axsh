use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};

use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    ClientHello, ConnSign, Packet, PacketSign, PacketVerify, ServerComplete, ServerHello,
    ServerPubkey, hdlc, random_u64, sha256_bytes, transport::PayloadStream,
};

/// Wrap an async byte stream with the server handshake and payload packet transport.
pub struct ServerStream<T> {
    client_hello: ClientHello,
    transport: PayloadStream<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> ServerStream<T> {
    /// Complete the server handshake over `stream`.
    pub async fn new(
        mut stream: T,
        conn_sign: &ConnSign,
        authorized_keys: &HashSet<Vec<u8>>,
    ) -> std::io::Result<Self> {
        let packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
        let unique = random_u64()?;
        let conn_sign_public_key = conn_sign
            .public_key_bytes()
            .map_err(std::io::Error::other)?;
        let conn_sign_public_key_sha256 = sha256_bytes(&conn_sign_public_key);

        // Send ServerHello.
        let packet = Packet::ServerHello(ServerHello::new(
            unique,
            conn_sign_public_key_sha256,
            packet_sign.public_key_bytes(),
        ));
        let server_hello_wire = packet.serialize(conn_sign).map_err(std::io::Error::other)?;
        stream.write_all(&hdlc::encode(&server_hello_wire)).await?;
        stream.flush().await?;

        // Read either RequestServerPubkey or ClientHello.
        let (client_hello_wire, client_hello) = loop {
            let frame = hdlc::read_frame_async(&mut stream).await?;
            let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&wire, None, None).map_err(std::io::Error::other)?;
            match packet {
                Packet::RequestServerPubkey => {
                    debug!("axsh: Server pubkey requested");
                    let packet =
                        Packet::ServerPubkey(ServerPubkey::new(conn_sign_public_key.clone()));
                    let wire = packet.serialize(conn_sign).map_err(std::io::Error::other)?;
                    stream.write_all(&hdlc::encode(&wire)).await?;
                    stream.flush().await?;
                }
                Packet::ClientHello(client_hello) => break (wire, client_hello),
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected RequestServerPubkey or ClientHello, got {other:?}"
                    )));
                }
            }
        };
        debug!(
            "axsh: received ClientHello: server_unique={}, client_unique={}, conn_key={} bytes, packet_key={} bytes",
            client_hello.server_unique(),
            client_hello.unique(),
            client_hello.conn_sign_public_key().len(),
            client_hello.packet_sign_public_key().len()
        );
        if client_hello.server_unique() != unique {
            return Err(std::io::Error::other(format!(
                "client echoed server_unique={} but expected {}",
                client_hello.server_unique(),
                unique
            )));
        }
        if !authorized_keys.contains(client_hello.conn_sign_public_key()) {
            return Err(std::io::Error::other(
                "client ConnSign key is not authorized",
            ));
        }
        let client_packet_verify = PacketVerify::new(client_hello.packet_sign_public_key());

        // Send ServerComplete.
        let mut transcript = server_hello_wire;
        transcript.extend(&client_hello_wire);
        let packet = Packet::ServerComplete(ServerComplete::new(
            conn_sign
                .sign_detached(&transcript)
                .map_err(std::io::Error::other)?,
        ));
        let wire = packet.serialize(conn_sign).map_err(std::io::Error::other)?;
        stream.write_all(&hdlc::encode(&wire)).await?;
        stream.flush().await?;

        // Connection is now established.

        Ok(Self {
            client_hello,
            transport: PayloadStream::new(stream, packet_sign, client_packet_verify),
        })
    }

    /// Return the negotiated client hello.
    pub fn client_hello(&self) -> &ClientHello {
        &self.client_hello
    }

    /// Return the underlying stream.
    pub fn into_inner(self) -> T {
        self.transport.into_inner()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ServerStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().transport.poll_read_payload(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ServerStream<T> {
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
