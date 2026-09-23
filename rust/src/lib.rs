//! Independent Rust verifier for Continuity Receipt bundles (0.1–0.3) and
//! verification receipts (companion v1).
//!
//! This is a second implementation of `continuity_receipt/verify.py` and
//! `continuity_receipt/verification.py`; the Python implementation in this
//! repository remains the reference. Verdicts follow the CTQ-aligned
//! semantics of spec section 7:
//! `TRUSTED` | `PROVISIONAL` | `INSUFFICIENT_EVIDENCE` | `UNTRUSTED`.

pub mod anchor;
pub mod canon;
pub mod didkey;
pub mod disclose;
pub mod verification;
pub mod verify;

pub use verification::{verify_verification_receipt, VerificationReceiptResult};
pub use verify::{verify_bundle, VerifyResult};
