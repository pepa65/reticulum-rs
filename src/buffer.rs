use crate::error::RnsError;

pub struct OutputBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> OutputBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), RnsError> {
        if (self.offset + data.len()) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.offset..data.len()].copy_from_slice(data);
        self.offset += data.len();

        Ok(())
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
}
