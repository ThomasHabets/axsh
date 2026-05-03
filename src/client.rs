use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    ClientHello, ConnSign, ConnVerify, Packet, PacketSign, PacketVerify, ServerHello, hdlc,
};

/// Wrap an async byte stream with the client handshake and payload packet transport.
pub struct ClientStream<T> {
    stream: T,
    server_hello: ServerHello,
    packet_sign: PacketSign,
    server_packet_verify: PacketVerify,
    frame_reader: hdlc::AsyncFrameReader,
    read_buffer: Vec<u8>,
    read_offset: usize,
    write_buffer: Vec<u8>,
    write_offset: usize,
}

impl<T: AsyncRead + AsyncWrite + Unpin> ClientStream<T> {
    /// Complete the client handshake over `stream`.
    pub async fn new(mut stream: T, conn_sign: ConnSign) -> std::io::Result<Self> {
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
        eprintln!(
            "received ServerHello: server_unique={}, conn_key={} bytes, packet_key={} bytes",
            server_hello.unique(),
            server_hello.conn_sign_public_key().len(),
            server_hello.packet_sign_public_key().len()
        );
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
                eprintln!(
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
            stream,
            server_hello,
            packet_sign,
            server_packet_verify,
            frame_reader: hdlc::AsyncFrameReader::new(),
            read_buffer: Vec::new(),
            read_offset: 0,
            write_buffer: Vec::new(),
            write_offset: 0,
        })
    }

    /// Return the negotiated server hello.
    pub fn server_hello(&self) -> &ServerHello {
        &self.server_hello
    }

    /// Return the underlying stream.
    pub fn into_inner(self) -> T {
        self.stream
    }

    fn poll_fill_read_buffer(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        loop {
            let frame = ready!(
                self.frame_reader
                    .poll_read_frame(cx, Pin::new(&mut self.stream))
            )?;
            let Some(frame) = frame else {
                return Poll::Ready(Ok(false));
            };
            let wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&wire, None, Some(&self.server_packet_verify))
                .map_err(std::io::Error::other)?;
            match packet {
                Packet::Payload(data) => {
                    eprintln!("received Payload: {} bytes", data.len());
                    if data.is_empty() {
                        continue;
                    }
                    self.read_buffer = data;
                    self.read_offset = 0;
                    return Poll::Ready(Ok(true));
                }
                other => {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "expected Payload, got {other:?}"
                    ))));
                }
            }
        }
    }

    fn poll_drain_write_buffer(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write framed payload",
                )));
            }
            self.write_offset += written;
        }
        if self.write_offset == self.write_buffer.len() {
            self.write_buffer.clear();
            self.write_offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.read_offset == this.read_buffer.len() {
            if !ready!(this.poll_fill_read_buffer(cx))? {
                return Poll::Ready(Ok(()));
            }
        }

        let available = this.read_buffer.len() - this.read_offset;
        let to_copy = available.min(buf.remaining());
        buf.put_slice(&this.read_buffer[this.read_offset..this.read_offset + to_copy]);
        this.read_offset += to_copy;
        if this.read_offset == this.read_buffer.len() {
            this.read_buffer.clear();
            this.read_offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClientStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buffer(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let packet = Packet::Payload(buf.to_vec());
        let wire = packet
            .serialize(&this.packet_sign)
            .map_err(std::io::Error::other)?;
        this.write_buffer = hdlc::encode(&wire);
        this.write_offset = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buffer(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write_buffer(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

/// Generate a random `u64` using `/dev/urandom`.
fn random_u64() -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    let mut file = std::fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::ClientStream;
    use crate::{ConnSign, Packet, PacketSign, PacketVerify, ServerComplete, ServerHello, hdlc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_stream_handshakes_and_transports_payloads() -> std::io::Result<()> {
        let server_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let server_packet_sign = PacketSign::new().map_err(std::io::Error::other)?;
        let client_conn_sign = ConnSign::new().map_err(std::io::Error::other)?;
        let (mut server_stream, client_stream) = tokio::io::duplex(4096);
        let expected_payload = b"server payload".to_vec();
        let expected_payload_for_server = expected_payload.clone();

        let server = tokio::spawn(async move {
            let server_hello = Packet::ServerHello(ServerHello::new(
                0x0123_4567_89ab_cdef,
                server_conn_sign
                    .public_key_bytes()
                    .map_err(std::io::Error::other)?,
                server_packet_sign.public_key_bytes(),
            ));
            let server_hello_wire = server_hello
                .serialize(&server_conn_sign)
                .map_err(std::io::Error::other)?;
            server_stream
                .write_all(&hdlc::encode(&server_hello_wire))
                .await?;

            let frame = hdlc::read_frame_async(&mut server_stream).await?;
            let client_hello_wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&client_hello_wire, None, None)
                .map_err(std::io::Error::other)?;
            let client_packet_verify = match packet {
                Packet::ClientHello(hello) => PacketVerify::new(hello.packet_sign_public_key()),
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected ClientHello, got {other:?}"
                    )));
                }
            };

            let mut transcript = server_hello_wire.clone();
            transcript.extend(&client_hello_wire);
            let complete = Packet::ServerComplete(ServerComplete::new(
                server_conn_sign
                    .sign_detached(&transcript)
                    .map_err(std::io::Error::other)?,
            ));
            let complete_wire = complete
                .serialize(&server_conn_sign)
                .map_err(std::io::Error::other)?;
            server_stream
                .write_all(&hdlc::encode(&complete_wire))
                .await?;

            let payload = Packet::Payload(expected_payload_for_server);
            let payload_wire = payload
                .serialize(&server_packet_sign)
                .map_err(std::io::Error::other)?;
            server_stream
                .write_all(&hdlc::encode(&payload_wire))
                .await?;

            let frame = hdlc::read_frame_async(&mut server_stream).await?;
            let payload_wire = hdlc::decode(&frame).map_err(std::io::Error::other)?;
            let packet = Packet::deserialize(&payload_wire, None, Some(&client_packet_verify))
                .map_err(std::io::Error::other)?;
            assert_eq!(packet, Packet::Payload(b"client payload".to_vec()));
            Ok::<(), std::io::Error>(())
        });

        let mut client = ClientStream::new(client_stream, client_conn_sign).await?;
        assert_eq!(client.server_hello().unique(), 0x0123_4567_89ab_cdef);

        let mut received = vec![0u8; expected_payload.len()];
        client.read_exact(&mut received).await?;
        assert_eq!(received, expected_payload);

        client.write_all(b"client payload").await?;
        client.flush().await?;
        server.await.expect("server task panicked")?;
        Ok(())
    }
}
