use crate::{buffer::OutputBuffer, error::RnsError};

const HDLC_FRAME_FLAG: u8 = 0x7e;
const HDLC_ESCAPE_BYTE: u8 = 0x7d;
const HDLC_ESCAPE_MASK: u8 = 0b00100000;

pub struct Hdlc {}

impl Hdlc {
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
}
