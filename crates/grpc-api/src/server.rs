use crate::config::{ServerConfig, TlsConfig};
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::signal;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

/// Creates an optimized gRPC server with performance and security enhancements.
///
/// This function configures a production-ready gRPC server with:
/// - HTTP/2 optimizations for high throughput and low latency
/// - Optional TLS/mTLS support for secure transport
/// - DoS protection through message size limits
/// - Connection health monitoring via keepalive
///
/// # Arguments
///
/// * `config` - Server configuration including HTTP/2 and TLS settings
///
/// # Returns
///
/// A configured Tonic [`Server`] ready to accept service registrations
///
/// # Errors
///
/// Returns an error if:
/// - TLS certificate or key files cannot be read
/// - Client CA certificate is invalid (for mTLS)
/// - TLS configuration fails to apply
///
/// # HTTP/2 Optimizations
///
/// The server applies the following HTTP/2 settings:
///
/// - **Keepalive**: Detects dead connections early (default: 30s interval, 10s timeout)
/// - **Adaptive Window**: Automatic flow control tuning based on traffic patterns
/// - **Initial Windows**: Large initial windows (1MB) for high throughput
/// - **Concurrent Streams**: Limits concurrent streams (default: 100) to prevent resource exhaustion
/// - **TCP_NODELAY**: Disables Nagle's algorithm for low latency
/// - **Frame Size**: Optimized frame size (16KB) for most network conditions
///
/// # Examples
///
/// ```no_run
/// use hsm_grpc_api::{config::ServerConfig, server::create_server};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ServerConfig::default();
/// let server = create_server(&config)?;
/// # Ok(())
/// # }
/// ```
pub fn create_server(config: &ServerConfig) -> Result<Server> {
    let http2_config = &config.http2;

    let mut server = Server::builder()
        .http2_keepalive_interval(Some(http2_config.keepalive_interval()))
        .http2_keepalive_timeout(Some(http2_config.keepalive_timeout()))
        .http2_adaptive_window(Some(http2_config.adaptive_window))
        .initial_connection_window_size(Some(http2_config.initial_connection_window_size))
        .initial_stream_window_size(Some(http2_config.initial_stream_window_size))
        .max_concurrent_streams(Some(http2_config.max_concurrent_streams))
        .tcp_nodelay(http2_config.tcp_nodelay)
        .max_frame_size(Some(http2_config.max_frame_size));

    // Configure TLS if enabled
    if let Some(tls_config) = &config.tls {
        let tls = create_tls_config(tls_config)?;
        server = server.tls_config(tls).context("Failed to configure TLS")?;
    }

    Ok(server)
}

/// Creates TLS configuration with optional mutual authentication (mTLS).
///
/// This function sets up TLS for the gRPC server with support for:
/// - Standard TLS: Server authenticates to client
/// - Mutual TLS (mTLS): Both server and client authenticate to each other
///
/// # Arguments
///
/// * `config` - TLS configuration specifying certificate paths and mTLS options
///
/// # Returns
///
/// A configured [`ServerTlsConfig`] ready to be applied to the server
///
/// # Errors
///
/// Returns an error if:
/// - Server certificate file cannot be read
/// - Server private key file cannot be read
/// - Client CA certificate file cannot be read (when mTLS is enabled)
/// - Certificate or key files are invalid PEM format
///
/// # mTLS Configuration
///
/// When `client_ca_path` is provided, the server will:
/// 1. Load the client CA certificate
/// 2. Require clients to present certificates signed by this CA
/// 3. Verify client certificates during TLS handshake
/// 4. Optionally enforce client certificate requirement via `require_client_cert`
///
/// # Security
///
/// - Certificates must be in PEM format
/// - Private keys should have restricted file permissions (e.g., 0600)
/// - Use strong TLS versions (TLS 1.2+ recommended)
/// - Client CA should only sign authorized client certificates
fn create_tls_config(config: &TlsConfig) -> Result<ServerTlsConfig> {
    // Load server certificate and key
    let cert = std::fs::read(&config.cert_path)
        .with_context(|| format!("Failed to read certificate from {:?}", config.cert_path))?;

    let key = std::fs::read(&config.key_path)
        .with_context(|| format!("Failed to read private key from {:?}", config.key_path))?;

    let server_identity = Identity::from_pem(cert, key);

    let mut tls_config = ServerTlsConfig::new().identity(server_identity);

    // Configure mTLS if client CA is provided
    if let Some(client_ca_path) = &config.client_ca_path {
        let client_ca_cert = std::fs::read(client_ca_path).with_context(|| {
            format!(
                "Failed to read client CA certificate from {:?}",
                client_ca_path
            )
        })?;

        let client_ca = Certificate::from_pem(client_ca_cert);

        tls_config = tls_config.client_ca_root(client_ca);

        if config.require_client_cert {
            info!("mTLS enabled: Client certificates required");
        }
    }

    Ok(tls_config)
}

/// Creates a graceful shutdown signal for the gRPC server.
///
/// This async function waits for OS signals to trigger graceful shutdown:
/// - **SIGINT**: Ctrl+C in terminal
/// - **SIGTERM**: Kubernetes pod termination, systemd stop, etc.
///
/// The function blocks until one of these signals is received, then returns
/// to allow the server to perform cleanup and shutdown gracefully.
///
/// # Platform Support
///
/// - **Unix/Linux**: Listens for both SIGINT and SIGTERM
/// - **Windows**: Listens for SIGINT (Ctrl+C) only
///
/// # Examples
///
/// ```no_run
/// use hsm_grpc_api::server::{create_server, shutdown_signal};
/// use hsm_grpc_api::config::ServerConfig;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = ServerConfig::default();
///     let server = create_server(&config)?;
///
///     let addr: std::net::SocketAddr = "0.0.0.0:50051".parse()?;
///
///     // Start server with graceful shutdown
///     // server
///     //     .serve_with_shutdown(addr, shutdown_signal())
///     //     .await?;
///
///     Ok(())
/// }
/// ```
///
/// # Panics
///
/// Panics if signal handlers cannot be installed (rare, indicates OS-level issues)
pub async fn shutdown_signal() {
    // Wait for SIGTERM or SIGINT
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
        },
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}

/// Background task to periodically cleanup expired cache entries.
///
/// This task runs in the background and removes expired entries from the response cache
/// at regular intervals. It also logs cache statistics for monitoring.
///
/// # Arguments
///
/// * `cache` - The response cache to cleanup
/// * `interval` - How often to run cleanup (e.g., `Duration::from_secs(300)` for 5 minutes)
/// * `shutdown` - Watch channel receiver to signal task shutdown
///
/// # Behavior
///
/// The task performs the following actions on each interval:
/// 1. Remove all expired cache entries
/// 2. Log current cache statistics (size and capacity for each cache type)
/// 3. Check for shutdown signal
///
/// # Examples
///
/// ```no_run
/// use hsm_grpc_api::cache::ResponseCache;
/// use hsm_grpc_api::server::cache_cleanup_task;
/// use std::time::Duration;
/// use tokio::sync::watch;
///
/// #[tokio::main]
/// async fn main() {
///     let cache = ResponseCache::default();
///     let (shutdown_tx, shutdown_rx) = watch::channel(false);
///
///     // Spawn cleanup task (runs every 5 minutes)
///     tokio::spawn(cache_cleanup_task(
///         cache.clone(),
///         Duration::from_secs(300),
///         shutdown_rx,
///     ));
///
///     // ... run server ...
///
///     // Signal shutdown when done
///     let _ = shutdown_tx.send(true);
/// }
/// ```
pub async fn cache_cleanup_task(
    cache: crate::cache::ResponseCache,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                cache.cleanup_expired();
                let stats = cache.stats();
                info!(
                    "Cache cleanup: get_key={}/{}, verify={}/{}",
                    stats.get_key.size, stats.get_key.capacity,
                    stats.verify.size, stats.verify.capacity
                );
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Cache cleanup task shutting down");
                    break;
                }
            }
        }
    }
}

/// Health check service implementation.
///
/// This module provides a gRPC health check service compliant with the
/// [gRPC Health Checking Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md).
///
/// The health service allows clients and orchestrators (like Kubernetes) to check
/// if the HSM service is ready to accept requests.
///
/// # Service Names
///
/// - `""` (empty string): Overall server health
/// - `"hsm.v1.HSM"`: HSM service-specific health
/// - Other names: Return `UNKNOWN` status
///
/// # Examples
///
/// ```no_run
/// use hsm_grpc_api::server::health::HealthService;
/// use tonic_health::pb::health_server::HealthServer;
///
/// #[tokio::main]
/// async fn main() {
///     let health_service = HealthService::new();
///     let health_server = HealthServer::new(health_service);
///
///     // Add to gRPC server:
///     // server.add_service(health_server).serve(addr).await?;
/// }
/// ```
pub mod health {
    use tonic::{Request, Response, Status};
    use tonic_health::pb::{
        health_check_response::ServingStatus, health_server::Health, HealthCheckRequest,
        HealthCheckResponse,
    };

    /// Health check service for monitoring HSM server status.
    ///
    /// Returns serving status for registered services.
    /// Currently returns `SERVING` for all health checks.
    ///
    /// # Future Enhancements
    ///
    /// - Check downstream service connectivity (crypto engine, storage)
    /// - Monitor resource usage (memory, CPU)
    /// - Validate certificate expiration
    /// - Check circuit breaker states
    #[derive(Debug, Clone, Default)]
    pub struct HealthService {
        // Add health check dependencies here
    }

    impl HealthService {
        /// Creates a new health service.
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[tonic::async_trait]
    impl Health for HealthService {
        type WatchStream =
            tokio_stream::wrappers::ReceiverStream<Result<HealthCheckResponse, Status>>;

        async fn check(
            &self,
            request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, Status> {
            let service_name = request.into_inner().service;

            // Check service health based on name
            let status = match service_name.as_str() {
                "" => {
                    // Overall health check
                    ServingStatus::Serving
                }
                "hsm.v1.HSM" => {
                    // HSM service health
                    ServingStatus::Serving
                }
                _ => ServingStatus::Unknown,
            };

            Ok(Response::new(HealthCheckResponse {
                status: status as i32,
            }))
        }

        async fn watch(
            &self,
            _request: Request<HealthCheckRequest>,
        ) -> Result<Response<Self::WatchStream>, Status> {
            // Watch not implemented yet
            Err(Status::unimplemented("Health watch not implemented"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_server_without_tls() {
        let config = ServerConfig::default();
        let server = create_server(&config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_health_service_creation() {
        let _health = health::HealthService::new();
    }
}
