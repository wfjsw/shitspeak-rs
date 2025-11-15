use enumflags2::{bitflags, make_bitflags, BitFlags};

pub struct ACL {
    user_id: Option<i32>,
    group: Option<String>,

    apply_here: bool,
    apply_subs: bool,

    allow: BitFlags<ACLPermissions>,
    deny: BitFlags<ACLPermissions>,
}

#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ACLPermissions {
	// None        = 0x0,
	Write       = 0x1,
	Traverse    = 0x2,
	Enter       = 0x4,
	Speak       = 0x8,
	MuteDeafen  = 0x10,
	Move        = 0x20,
	MakeChannel = 0x40,
	LinkChannel = 0x80,
	Whisper     = 0x100,
	TextMessage = 0x200,
	TempChannel = 0x400,
	Listen      = 0x800,

	// Root channel only
	Kick         = 0x10000,
	Ban          = 0x20000,
	Register     = 0x40000,
	SelfRegister = 0x80000,
	ResetUserContent       = 0x100000,
}
