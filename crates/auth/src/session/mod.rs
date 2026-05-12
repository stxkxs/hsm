/// Session ID type (cryptographically secure)
pub type SessionId = String;

/// Template ID type
pub type TemplateId = String;

pub mod manager;
pub mod rate_limiter;
pub mod scope;
pub mod session_data;
pub mod token;

#[cfg(test)]
mod tests;

pub use manager::SessionManager;
pub use rate_limiter::RateLimiterState;
pub use scope::{SessionScope, SessionTemplate};
pub use session_data::{Session, SessionCreationResult};
pub use token::{HashedToken, SessionToken};
