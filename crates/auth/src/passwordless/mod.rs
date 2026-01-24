//! Passwordless Authentication
//!
//! Provides multiple passwordless authentication methods:
//! - Magic links (email-based one-time links)
//! - OTP (TOTP/HOTP based on RFC 6238/4226)
//! - WebAuthn/FIDO2 (hardware keys, biometrics)
//! - Passkeys
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Passwordless Authentication                    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  Magic Link                                                       │
//! │  ┌──────────┐     ┌──────────────┐     ┌──────────────┐          │
//! │  │  Email   │────▶│  Verify      │────▶│  Session     │          │
//! │  │  Request │     │  Token       │     │  Created     │          │
//! │  └──────────┘     └──────────────┘     └──────────────┘          │
//! │                                                                   │
//! │  OTP (TOTP/HOTP)                                                  │
//! │  ┌──────────┐     ┌──────────────┐     ┌──────────────┐          │
//! │  │  Setup   │────▶│  Verify      │────▶│  Session     │          │
//! │  │  QR Code │     │  Code        │     │  Created     │          │
//! │  └──────────┘     └──────────────┘     └──────────────┘          │
//! │                                                                   │
//! │  WebAuthn                                                         │
//! │  ┌──────────┐     ┌──────────────┐     ┌──────────────┐          │
//! │  │ Register │────▶│  Challenge   │────▶│  Credential  │          │
//! │  │ Device   │     │  Response    │     │  Stored      │          │
//! │  └──────────┘     └──────────────┘     └──────────────┘          │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod magic_link;
pub mod otp;
pub mod webauthn;

pub use magic_link::{MagicLink, MagicLinkManager, MagicLinkRequest, MagicLinkVerification};
pub use otp::{OtpConfig, OtpManager, OtpSecret, OtpType, TotpValidator};
pub use webauthn::{
    WebAuthnChallenge, WebAuthnConfig, WebAuthnCredential, WebAuthnManager, WebAuthnRegistration,
    WebAuthnVerification,
};
