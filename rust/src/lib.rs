//! Independent Rust verifier for Continuity Receipt bundles (0.1 + 0.2).
//!
//! This is a second implementation of `continuity_receipt/verify.py`; the
//! Python implementation in this repository remains the reference. Verdicts
//! follow the CTQ-aligned semantics of spec section 7:
//! `TRUSTED` | `PROVISIONAL` | `INSUFFICIENT_EVIDENCE` | `UNTRUSTED`.

pub mod canon;
pub mod didkey;
pub mod verify;

pub use verify::{verify_bundle, VerifyResult};
