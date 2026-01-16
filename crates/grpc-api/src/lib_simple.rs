pub mod error;
pub mod middleware;
pub mod proto {
    pub mod hsm {
        tonic::include_proto!("hsm.v1");
    }
}

pub use error::{ApiError, Result};

// Simplified stubs for compilation
pub struct GrpcServer;

impl GrpcServer {
    pub async fn serve(self) -> Result<()> {
        Ok(())
    }
}

pub async fn start_server(_addr: std::net::SocketAddr) -> Result<()> {
    Ok(())
}
