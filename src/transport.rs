use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Packet, PacketSign, PacketVerify, hdlc};

/// Wrap an async byte stream with signed payload packet transport.
pub(crate) struct PayloadStream<T> {
    stream: T,
    packet_sign: PacketSign,
    peer_packet_verify: PacketVerify,
    frame_reader: hdlc::AsyncFrameReader,
    read_buffer: Vec<u8>,
    read_offset: usize,
    write_buffer: Vec<u8>,
    write_offset: usize,
}

impl<T: AsyncRead + AsyncWrite + Unpin> PayloadStream<T> {
    /// Create a payload transport from an underlying stream and packet keys.
    pub(crate) fn new(
        stream: T,
        packet_sign: PacketSign,
        peer_packet_verify: PacketVerify,
    ) -> Self {
        Self {
            stream,
            packet_sign,
            peer_packet_verify,
            frame_reader: hdlc::AsyncFrameReader::new(),
            read_buffer: Vec::new(),
            read_offset: 0,
            write_buffer: Vec::new(),
            write_offset: 0,
        }
    }

    /// Return the underlying stream.
    pub(crate) fn into_inner(self) -> T {
        self.stream
    }

    pub(crate) fn poll_read_payload(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.read_offset == self.read_buffer.len() && !ready!(self.poll_fill_read_buffer(cx))? {
            return Poll::Ready(Ok(()));
        }

        let available = self.read_buffer.len() - self.read_offset;
        let to_copy = available.min(buf.remaining());
        buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + to_copy]);
        self.read_offset += to_copy;
        if self.read_offset == self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_write_payload(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        ready!(self.poll_drain_write_buffer(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let packet = Packet::Payload(buf.to_vec());
        let wire = packet
            .serialize_packet_signed(&self.packet_sign)
            .map_err(std::io::Error::other)?;
        self.write_buffer = hdlc::encode(&wire);
        self.write_offset = 0;
        Poll::Ready(Ok(buf.len()))
    }

    pub(crate) fn poll_flush_payload(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.poll_drain_write_buffer(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    pub(crate) fn poll_shutdown_payload(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.poll_drain_write_buffer(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
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
            let packet = Packet::deserialize(&wire, None, None, Some(&mut self.peer_packet_verify))
                .map_err(std::io::Error::other)?;
            match packet {
                Packet::Payload(data) => {
                    log::debug!("received Payload: {} bytes", data.len());
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
