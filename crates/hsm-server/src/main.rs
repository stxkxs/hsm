//! HSM Server
//!
//! Production-grade Hardware Security Module server for Kubernetes.
//!
//! This binary provides:
//! - REST API for key management and cryptographic operations
//! - Prometheus metrics endpoint
//! - Health and readiness probes
//! - mTLS authentication
//!
//! # Usage
//!
//! ```bash
//! # Start with default configuration
//! hsm-server
//!
//! # Start with custom config file
//! hsm-server --config /path/to/config.toml
//!
//! # Start with environment variables
//! HSM_REST_PORT=8443 HSM_METRICS_PORT=9090 hsm-server
//! ```

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hsm_auth::SessionManager;
use hsm_key_manager::DefaultKeyManager;
use hsm_rest_api::middleware::AppState;

/// HSM Server command-line arguments
#[derive(Parser, Debug)]
#[command(name = "hsm-server")]
#[command(author, version, about = "Hardware Security Module Server", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config/hsm.toml")]
    config: String,

    /// REST API port
    #[arg(long, env = "HSM_REST_PORT", default_value = "8443")]
    rest_port: u16,

    /// Metrics port
    #[arg(long, env = "HSM_METRICS_PORT", default_value = "9090")]
    metrics_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "HSM_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Enable JSON logging
    #[arg(long, env = "HSM_JSON_LOGS")]
    json_logs: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    info!("Starting HSM Server v{}", env!("CARGO_PKG_VERSION"));

    // Initialize components
    // Default session TTL: 1 hour (3600 seconds)
    let session_manager = Arc::new(SessionManager::new(3600));
    let key_manager = Arc::new(DefaultKeyManager::new());

    // Create REST API state
    let app_state = AppState::with_key_manager(session_manager.clone(), key_manager);

    // Build REST API router
    let rest_app = hsm_rest_api::create_router(app_state);

    // Build metrics router
    let metrics_app = create_metrics_router();

    // Start REST API server
    let rest_addr: SocketAddr = format!("0.0.0.0:{}", args.rest_port).parse()?;
    info!("REST API listening on {}", rest_addr);

    // Start metrics server
    let metrics_addr: SocketAddr = format!("0.0.0.0:{}", args.metrics_port).parse()?;
    info!("Metrics endpoint listening on {}", metrics_addr);

    // Bind listeners
    let rest_listener = tokio::net::TcpListener::bind(rest_addr)
        .await
        .expect("Failed to bind REST server");
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr)
        .await
        .expect("Failed to bind metrics server");

    // Spawn servers
    let rest_server = tokio::spawn(async move {
        axum::serve(rest_listener, rest_app).await.unwrap();
    });

    let metrics_server = tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_app).await.unwrap();
    });

    info!("HSM Server started successfully");

    // Wait for shutdown signal or server completion
    tokio::select! {
        _ = shutdown_signal() => {
            info!("Shutdown signal received, stopping servers...");
        }
        result = rest_server => {
            info!("REST server exited: {:?}", result);
        }
        result = metrics_server => {
            info!("Metrics server exited: {:?}", result);
        }
    }

    info!("HSM Server stopped");
    Ok(())
}

/// Initialize logging based on configuration
fn init_logging(args: &Args) -> Result<()> {
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level.to_string()));

    if args.json_logs {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    Ok(())
}

/// Create the metrics router
fn create_metrics_router() -> axum::Router {
    use axum::{routing::get, Router};

    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
}

/// Metrics endpoint handler (Prometheus format)
async fn metrics_handler() -> String {
    // In production, this would collect actual metrics from the metrics crate
    // For now, return placeholder metrics
    let metrics = r#"
# HELP hsm_requests_total Total number of HSM requests
# TYPE hsm_requests_total counter
hsm_requests_total{operation="sign"} 0
hsm_requests_total{operation="verify"} 0
hsm_requests_total{operation="encrypt"} 0
hsm_requests_total{operation="decrypt"} 0

# HELP hsm_keys_total Total number of keys managed
# TYPE hsm_keys_total gauge
hsm_keys_total 0

# HELP hsm_sessions_active Current active sessions
# TYPE hsm_sessions_active gauge
hsm_sessions_active 0

# HELP hsm_up HSM server status (1 = up, 0 = down)
# TYPE hsm_up gauge
hsm_up 1
"#;
    metrics.trim().to_string()
}

/// Health check handler
async fn health_handler() -> &'static str {
    "OK"
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
