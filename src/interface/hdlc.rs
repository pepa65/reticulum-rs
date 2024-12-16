use std::io::Read;
use std::io::Write;

use crate::{buffer::OutputBuffer, error::RnsError};

const HDLC_FRAME_FLAG: u8 = 0x7e;
const HDLC_ESCAPE_BYTE: u8 = 0x7d;
const HDLC_ESCAPE_MASK: u8 = 0b00100000;

pub struct Hdlc<I, const N: usize> {
    inner: I,
    read_buffer: [u8; N],
    write_buffer: [u8; N],
}

impl<I, const N: usize> Hdlc<I, N> {
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            read_buffer: [0u8; N],
            write_buffer: [0u8; N],
        }
    }

    pub fn encode(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(HDLC_FRAME_FLAG)?;

        for &byte in data {
            match byte {
                HDLC_FRAME_FLAG | HDLC_ESCAPE_BYTE => {
                    buffer.write(&[HDLC_ESCAPE_BYTE, byte ^ HDLC_ESCAPE_MASK])?;
                }
                _ => {
                    buffer.write_byte(byte)?;
                }
            }
        }

        buffer.write_byte(HDLC_FRAME_FLAG)?;

        Ok(buffer.offset())
    }

    pub fn decode(data: &[u8], output: &mut OutputBuffer) -> Result<usize, RnsError> {
        let mut started = false;
        let mut finished = false;
        let mut escape = false;

        for &byte in data {
            if escape {
                escape = false;
                output.write_byte(byte ^ HDLC_ESCAPE_MASK)?;
            } else {
                match byte {
                    HDLC_FRAME_FLAG => {
                        if started {
                            finished = true;
                            break;
                        }

                        started = true;
                    }
                    HDLC_ESCAPE_BYTE => {
                        escape = true;
                    }
                    _ => {
                        output.write_byte(byte)?;
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::OutOfMemory);
        }

        Ok(output.offset())
    }

    pub fn get_ref(&self) -> &I {
        return &self.inner;
    }

    pub fn get_mut(&mut self) -> &mut I {
        return &mut self.inner;
    }
}

impl<I: Write, const N: usize> Write for Hdlc<I, N> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut output = OutputBuffer::new(&mut self.write_buffer);

        Hdlc::<I, N>::encode(buf, &mut output)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "buffer to small"))?;

        self.inner.write(output.as_slice())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<I: Read, const N: usize> Read for Hdlc<I, N> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(&mut self.read_buffer[..])?;

        let mut output = OutputBuffer::new(buf);

        Hdlc::<I, N>::decode(&self.read_buffer[..count], &mut output)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "buffer to small"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use crate::interface::hdlc::Hdlc;

    #[test]
    fn encode_decode_data() {
        let expected_message = b"#--TEST-MESSAGE--#";

        let mut buffer = Vec::<u8>::new();
        let cursor = Cursor::new(&mut buffer);
        let mut hdlc = Hdlc::<_, 1024>::new(cursor);

        hdlc.write(expected_message).expect("write failed");

        hdlc.get_mut().set_position(0);

        let mut actual_buf = [0u8; 1024];
        let actual_buf_len = hdlc.read(&mut actual_buf[..]).expect("read failed");

        let actual_message = &actual_buf[..actual_buf_len];

        assert_eq!(expected_message, actual_message);
    }
}
