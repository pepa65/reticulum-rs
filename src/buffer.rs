use core::fmt;

use crate::error::RnsError;

pub struct OutputBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> OutputBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, RnsError> {
        let data_size = data.len();

        // Nothing to write
        if data_size == 0 {
            return Ok(0);
        }

        if (self.offset + data_size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.offset..(self.offset + data_size)].copy_from_slice(data);
        self.offset += data_size;

        Ok(data_size)
    }

    pub fn reset(&mut self) {
        self.offset = 0;
    }

    pub fn is_full(&self) -> bool {
        self.offset == self.buffer.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.offset]
    }

    pub fn local_buffer(&mut self) -> OutputBuffer {
        OutputBuffer::new(&mut self.buffer[self.offset..])
    }
}

impl<'a> fmt::Display for OutputBuffer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ 0x")?;

        for i in 0..self.offset {
            write!(f, "{:0>2x}", self.buffer[i])?;
        }

        write!(f, " ]",)
    }
}
