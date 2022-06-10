//! Wrapper types for converting packet data to/from network and host byte order.
//!
//! Adapted from [Capsule primitive wrapper types](https://docs.rs/capsule/0.1.5/capsule/packets/types/index.html).

use std::ops::{BitAnd, BitOr};

/// 16-bit unsigned integer in big-endian order.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u16be(pub u16);

impl From<u16> for u16be {
    fn from(item: u16) -> Self {
        u16be(u16::to_be(item))
    }
}

impl From<u16be> for u16 {
    fn from(item: u16be) -> Self {
        u16::from_be(item.0)
    }
}

impl BitAnd for u16be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u16be(self.0 & rhs.0)
    }
}

impl BitOr for u16be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// -------------------------------------------------------

/// 32-bit unsigned integer in big-endian order.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u32be(pub u32);

impl From<u32> for u32be {
    fn from(item: u32) -> Self {
        u32be(u32::to_be(item))
    }
}

impl From<::std::net::Ipv4Addr> for u32be {
    fn from(item: ::std::net::Ipv4Addr) -> Self {
        u32be::from(u32::from(item))
    }
}

impl From<u32be> for u32 {
    fn from(item: u32be) -> Self {
        u32::from_be(item.0)
    }
}

impl BitAnd for u32be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u32be(self.0 & rhs.0)
    }
}

impl BitOr for u32be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// -------------------------------------------------------

/// 64-bit unsigned integer in big-endian order.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u64be(pub u64);

impl From<u64> for u64be {
    fn from(item: u64) -> Self {
        u64be(u64::to_be(item))
    }
}

impl From<u64be> for u64 {
    fn from(item: u64be) -> Self {
        u64::from_be(item.0)
    }
}

impl BitAnd for u64be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u64be(self.0 & rhs.0)
    }
}

impl BitOr for u64be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// -------------------------------------------------------

/// 128-bit unsigned integer in big-endian order.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u128be(pub u128);

impl From<u128> for u128be {
    fn from(item: u128) -> Self {
        u128be(u128::to_be(item))
    }
}

impl From<u128be> for u128 {
    fn from(item: u128be) -> Self {
        u128::from_be(item.0)
    }
}

impl BitAnd for u128be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u128be(self.0 & rhs.0)
    }
}

impl BitOr for u128be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
