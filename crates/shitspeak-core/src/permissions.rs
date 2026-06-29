use enumflags2::bitflags;
use serde::{Deserialize, Serialize};

#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ACLPermissions {
    Write = 0x1,
    Traverse = 0x2,
    Enter = 0x4,
    Speak = 0x8,
    MuteDeafen = 0x10,
    Move = 0x20,
    MakeChannel = 0x40,
    LinkChannel = 0x80,
    Whisper = 0x100,
    TextMessage = 0x200,
    TempChannel = 0x400,
    Listen = 0x800,
    Kick = 0x10000,
    Ban = 0x20000,
    Register = 0x40000,
    SelfRegister = 0x80000,
    ResetUserContent = 0x100000,
}
