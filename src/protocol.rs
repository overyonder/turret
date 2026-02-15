use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::Signature;
use std::io::{self, Read, Write};

use crate::MAX_FRAME_SIZE;

pub const ENVELOPE_MAGIC: &[u8; 4] = b"TRT1";
pub const PROTOCOL_VERSION: u16 = 1;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Register = 1,
    Invoke = 2,
    Result = 3,
    Error = 4,
}

impl MessageType {
    fn from_u16(v: u16) -> Result<Self, ProtocolError> {
        match v {
            1 => Ok(Self::Register),
            2 => Ok(Self::Invoke),
            3 => Ok(Self::Result),
            4 => Ok(Self::Error),
            _ => Err(ProtocolError::BadRequest("unknown message type")),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Unauthenticated = 1,
    Replay = 2,
    Denied = 3,
    UnknownAction = 4,
    NoRepeater = 5,
    BadRequest = 6,
    Internal = 7,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub msg_type: MessageType,
    pub principal: Vec<u8>,
    pub ts_ms: u64,
    pub nonce: Vec<u8>,
    pub body: Vec<u8>,
    pub sig: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("bad request: {0}")]
    BadRequest(&'static str),
}

fn read_bstr<R: Read>(r: &mut R) -> Result<Vec<u8>, ProtocolError> {
    let len_be = r.read_u32::<byteorder::BigEndian>()? as usize;
    if len_be > MAX_FRAME_SIZE {
        return Err(ProtocolError::BadRequest("bstr too large"));
    }
    let mut b = vec![0u8; len_be];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn write_bstr<W: Write>(w: &mut W, b: &[u8]) -> Result<(), ProtocolError> {
    if b.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::BadRequest("bstr too large"));
    }
    w.write_u32::<byteorder::BigEndian>(b.len() as u32)?;
    w.write_all(b)?;
    Ok(())
}

impl Envelope {
    pub fn decode(mut bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut magic = [0u8; 4];
        bytes.read_exact(&mut magic)?;
        if &magic != ENVELOPE_MAGIC {
            return Err(ProtocolError::BadRequest("bad magic"));
        }

        let version = bytes.read_u16::<LittleEndian>()?;
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::BadRequest("bad version"));
        }

        let t = MessageType::from_u16(bytes.read_u16::<LittleEndian>()?)?;
        let principal = read_bstr(&mut bytes)?;
        let ts_ms = bytes.read_u64::<LittleEndian>()?;
        let nonce = read_bstr(&mut bytes)?;
        let body = read_bstr(&mut bytes)?;
        let sig_bytes = read_bstr(&mut bytes)?;
        if sig_bytes.len() != 64 {
            return Err(ProtocolError::BadRequest("bad signature length"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        Ok(Self {
            msg_type: t,
            principal,
            ts_ms,
            nonce,
            body,
            sig,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.write_u16::<LittleEndian>(PROTOCOL_VERSION)?;
        out.write_u16::<LittleEndian>(self.msg_type as u16)?;
        write_bstr(&mut out, &self.principal)?;
        out.write_u64::<LittleEndian>(self.ts_ms)?;
        write_bstr(&mut out, &self.nonce)?;
        write_bstr(&mut out, &self.body)?;
        write_bstr(&mut out, &self.sig)?;
        Ok(out)
    }

    pub fn signature(&self) -> Signature {
        Signature::from_bytes(&self.sig)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterBody {
    pub repeater_id: Vec<u8>,
    pub actions: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeBody {
    pub request_id: Vec<u8>,
    pub action: Vec<u8>,
    pub params: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultBody {
    pub request_id: Vec<u8>,
    pub result: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorBody {
    pub request_id: Vec<u8>,
    pub code: ErrorCode,
    pub message: Vec<u8>,
}

impl RegisterBody {
    pub fn decode(mut b: &[u8]) -> Result<Self, ProtocolError> {
        let repeater_id = read_bstr(&mut b)?;
        let action_count = b.read_u32::<LittleEndian>()? as usize;
        let mut actions = Vec::with_capacity(action_count);
        for _ in 0..action_count {
            actions.push(read_bstr(&mut b)?);
        }
        Ok(Self { repeater_id, actions })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        write_bstr(&mut out, &self.repeater_id)?;
        out.write_u32::<LittleEndian>(self.actions.len() as u32)?;
        for a in &self.actions {
            write_bstr(&mut out, a)?;
        }
        Ok(out)
    }
}

impl InvokeBody {
    pub fn decode(mut b: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            request_id: read_bstr(&mut b)?,
            action: read_bstr(&mut b)?,
            params: read_bstr(&mut b)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        write_bstr(&mut out, &self.request_id)?;
        write_bstr(&mut out, &self.action)?;
        write_bstr(&mut out, &self.params)?;
        Ok(out)
    }
}

impl ResultBody {
    pub fn decode(mut b: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            request_id: read_bstr(&mut b)?,
            result: read_bstr(&mut b)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        write_bstr(&mut out, &self.request_id)?;
        write_bstr(&mut out, &self.result)?;
        Ok(out)
    }
}

impl ErrorBody {
    pub fn decode(mut b: &[u8]) -> Result<Self, ProtocolError> {
        let request_id = read_bstr(&mut b)?;
        let code = b.read_u16::<LittleEndian>()?;
        let message = read_bstr(&mut b)?;

        let code = match code {
            1 => ErrorCode::Unauthenticated,
            2 => ErrorCode::Replay,
            3 => ErrorCode::Denied,
            4 => ErrorCode::UnknownAction,
            5 => ErrorCode::NoRepeater,
            6 => ErrorCode::BadRequest,
            7 => ErrorCode::Internal,
            _ => return Err(ProtocolError::BadRequest("unknown error code")),
        };

        Ok(Self {
            request_id,
            code,
            message,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut out = Vec::new();
        write_bstr(&mut out, &self.request_id)?;
        out.write_u16::<LittleEndian>(self.code as u16)?;
        write_bstr(&mut out, &self.message)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let env = Envelope {
            msg_type: MessageType::Invoke,
            principal: b"agent-1".to_vec(),
            ts_ms: 123,
            nonce: b"nonce".to_vec(),
            body: b"body".to_vec(),
            sig: [7u8; 64],
        };

        let enc = env.encode().unwrap();
        let dec = Envelope::decode(&enc).unwrap();
        assert_eq!(dec, env);
    }

    #[test]
    fn body_roundtrip_register() {
        let b = RegisterBody {
            repeater_id: b"r".to_vec(),
            actions: vec![b"a".to_vec(), b"b".to_vec()],
        };
        assert_eq!(RegisterBody::decode(&b.encode().unwrap()).unwrap(), b);
    }

    #[test]
    fn body_roundtrip_invoke() {
        let b = InvokeBody {
            request_id: b"req".to_vec(),
            action: b"act".to_vec(),
            params: b"p".to_vec(),
        };
        assert_eq!(InvokeBody::decode(&b.encode().unwrap()).unwrap(), b);
    }
}
