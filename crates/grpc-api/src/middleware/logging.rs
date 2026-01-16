use std::time::Instant;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

pub struct RequestLogger;

impl RequestLogger {
    pub fn new() -> Self {
        Self
    }

    pub fn log_request<T>(&self, request: &Request<T>, method: &str) -> Instant {
        let remote_addr = request.remote_addr();

        info!(
            method = %method,
            remote_addr = ?remote_addr,
            "Incoming gRPC request"
        );

        Instant::now()
    }

    pub fn log_response<T>(
        &self,
        method: &str,
        result: &Result<Response<T>, Status>,
        start: Instant,
    ) {
        let duration = start.elapsed();

        match result {
            Ok(_) => {
                info!(
                    method = %method,
                    duration_ms = duration.as_millis(),
                    "Request completed successfully"
                );
            }
            Err(status) => {
                let code = status.code();
                let message = status.message();

                if code == tonic::Code::Internal || code == tonic::Code::Unknown {
                    error!(
                        method = %method,
                        code = ?code,
                        message = %message,
                        duration_ms = duration.as_millis(),
                        "Request failed with error"
                    );
                } else {
                    warn!(
                        method = %method,
                        code = ?code,
                        message = %message,
                        duration_ms = duration.as_millis(),
                        "Request failed"
                    );
                }
            }
        }
    }
}

impl Default for RequestLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = RequestLogger::new();
        assert!(std::mem::size_of_val(&logger) == 0);
    }

    #[test]
    fn test_default_logger() {
        let logger = RequestLogger::default();
        assert!(std::mem::size_of_val(&logger) == 0);
    }
}
