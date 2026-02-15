use std::io::{self, Read, Write};

use crate::MAX_FRAME_SIZE;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("frame too large: {len} > {max}")]
    FrameTooLarge { len: usize, max: usize },
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_be = [0u8; 4];
    r.read_exact(&mut len_be)?;
    let len = u32::from_be_bytes(len_be) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            len: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }

    let len_be = (payload.len() as u32).to_be_bytes();
    w.write_all(&len_be)?;
    w.write_all(payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip() {
        let payload = b"hello".to_vec();
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).unwrap();

        let mut cursor: &[u8] = &buf;
        let got = read_frame(&mut cursor).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn framing_rejects_large_frame() {
        let payload = vec![0u8; MAX_FRAME_SIZE + 1];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &payload).unwrap_err();
        match err {
            FrameError::FrameTooLarge { len, max } => {
                assert_eq!(len, MAX_FRAME_SIZE + 1);
                assert_eq!(max, MAX_FRAME_SIZE);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
