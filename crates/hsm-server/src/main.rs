#![deny(unsafe_code)]
//! HSM Server
//!
//! Production-grade Hardware Security Module server for Kubernetes.
//!
//! This binary provides:
//! - REST API for key management and cryptographic operations
//! - Prometheus metrics endpoint (real metrics from the metrics crate)
//! - Health and readiness probes with subsystem checks
//! - Optional TLS for REST API
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
//!
//! # Start with TLS
//! hsm-server --tls-cert server.crt --tls-key server.key
//! ```

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use clap::Parser;
use hsm_metrics::MetricsCollector;
use prometheus::TextEncoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hsm_auth::SessionManager;
use hsm_key_manager::{DefaultKeyManager, KeyFilter, KeyManager};
use hsm_rest_api::middleware::AppState;

/// Shared state for the metrics/health server
#[derive(Clone)]
struct ServerState {
    metrics: MetricsCollector,
    session_manager: Arc<SessionManager>,
    key_manager: Arc<DefaultKeyManager>,
}

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

    /// TLS certificate path (enables TLS for REST API)
    #[arg(long, env = "HSM_TLS_CERT")]
    tls_cert: Option<String>,

    /// TLS private key path (required when --tls-cert is set)
    #[arg(long, env = "HSM_TLS_KEY")]
    tls_key: Option<String>,

    /// TLS CA certificate for client authentication (enables mTLS)
    #[arg(long, env = "HSM_TLS_CA")]
    tls_ca: Option<String>,

    /// Session timeout in seconds
    #[arg(long, env = "HSM_SESSION_TIMEOUT", default_value = "3600")]
    session_timeout: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    info!("Starting HSM Server v{}", env!("CARGO_PKG_VERSION"));

    // Validate TLS args
    if args.tls_cert.is_some() != args.tls_key.is_some() {
        anyhow::bail!("Both --tls-cert and --tls-key must be provided together");
    }

    // Initialize metrics collector
    let metrics_collector =
        MetricsCollector::new().context("Failed to initialize metrics collector")?;

    // Initialize components
    let session_manager = Arc::new(SessionManager::new(args.session_timeout));
    let key_manager = Arc::new(DefaultKeyManager::new());

    // Create REST API state
    let app_state = AppState::with_key_manager(session_manager.clone(), key_manager.clone());

    // Build REST API router
    let rest_app = hsm_rest_api::create_router(app_state);

    // Build metrics/health router with real metrics
    let server_state = ServerState {
        metrics: metrics_collector,
        session_manager: session_manager.clone(),
        key_manager: key_manager.clone(),
    };
    let metrics_app = create_metrics_router(server_state);

    // Start REST API server
    let rest_addr: SocketAddr = format!("0.0.0.0:{}", args.rest_port).parse()?;

    // Start metrics server
    let metrics_addr: SocketAddr = format!("0.0.0.0:{}", args.metrics_port).parse()?;

    // Bind listeners
    let rest_listener = tokio::net::TcpListener::bind(rest_addr)
        .await
        .context("Failed to bind REST server")?;
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr)
        .await
        .context("Failed to bind metrics server")?;

    // Shutdown coordination
    let shutdown_token = CancellationToken::new();

    // Optionally configure TLS for REST API
    let rest_server = if let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) {
        info!("REST API listening on {} (TLS enabled)", rest_addr);
        let tls_config =
            build_tls_config(cert_path, key_path, args.tls_ca.as_deref())
                .context("Failed to configure TLS")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let token = shutdown_token.clone();
        tokio::spawn(serve_tls(rest_listener, rest_app, acceptor, token))
    } else {
        warn!(
            "REST API listening on {} (TLS disabled - NOT recommended for production)",
            rest_addr
        );
        let token = shutdown_token.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(rest_listener, rest_app)
                .with_graceful_shutdown(token.cancelled_owned())
                .await
            {
                error!("REST server error: {}", e);
            }
        })
    };

    info!("Metrics endpoint listening on {}", metrics_addr);
    let token = shutdown_token.clone();
    let metrics_server = tokio::spawn(async move {
        if let Err(e) = axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(token.cancelled_owned())
            .await
        {
            error!("Metrics server error: {}", e);
        }
    });

    info!("HSM Server started successfully");

    // Wait for shutdown signal or server completion
    tokio::select! {
        _ = shutdown_signal() => {
            info!("Shutdown signal received, stopping servers...");
            shutdown_token.cancel();
        }
        result = rest_server => {
            match result {
                Ok(()) => info!("REST server exited"),
                Err(e) => error!("REST server task failed: {}", e),
            }
        }
        result = metrics_server => {
            match result {
                Ok(()) => info!("Metrics server exited"),
                Err(e) => error!("Metrics server task failed: {}", e),
            }
        }
    }

    info!("HSM Server stopped");
    Ok(())
}

/// Build a rustls ServerConfig from cert and key files.
/// When `ca_path` is provided, client certificate verification is enforced (mTLS).
fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    ca_path: Option<&str>,
) -> Result<rustls::ServerConfig> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("Failed to read TLS certificate: {}", cert_path))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse TLS certificates")?;

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("Failed to read TLS key: {}", key_path))?;

    let config = if let Some(ca) = ca_path {
        info!("mTLS enabled — requiring client certificates");
        let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(ca)
            .with_context(|| format!("Failed to read CA certificate: {}", ca))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to parse CA certificates")?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).context("Failed to add CA certificate to root store")?;
        }

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("Failed to build client certificate verifier")?;

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("Failed to build mTLS config")?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to build TLS config")?
    };

    Ok(config)
}

/// Serve HTTP over TLS using tokio-rustls with graceful shutdown support
async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    acceptor: tokio_rustls::TlsAcceptor,
    shutdown: CancellationToken,
) {
    use hyper_util::rt::TokioIo;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("TLS server shutting down gracefully");
                break;
            }
            result = listener.accept() => {
                let (stream, addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("TLS handshake failed from {}: {}", addr, e);
                            return;
                        }
                    };

                    let io = TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);

                    if let Err(e) =
                        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(io, service)
                            .await
                    {
                        warn!("Connection error from {}: {}", addr, e);
                    }
                });
            }
        }
    }
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

/// Create the metrics/health router with real Prometheus metrics
fn create_metrics_router(state: ServerState) -> axum::Router {
    use axum::{routing::get, Router};

    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}

/// Metrics endpoint handler — exports real Prometheus metrics
async fn metrics_handler(State(state): State<ServerState>) -> Response {
    let encoder = TextEncoder::new();
    let metric_families = state.metrics.gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(encoded) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            encoded,
        )
            .into_response(),
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode metrics: {}", e),
            )
                .into_response()
        }
    }
}

/// Health check handler — checks subsystem status
async fn health_handler(State(state): State<ServerState>) -> Response {
    let mut status = "healthy";
    let mut components = serde_json::Map::new();

    // Check session manager
    let session_count = state.session_manager.active_session_count();
    components.insert(
        "session_manager".to_string(),
        serde_json::json!({ "status": "healthy", "active_sessions": session_count }),
    );

    // Check key manager
    let km: &dyn KeyManager = &*state.key_manager;
    match km.list_keys("default", KeyFilter::default()) {
        Ok(_) => {
            components.insert(
                "key_manager".to_string(),
                serde_json::json!({ "status": "healthy" }),
            );
        }
        Err(e) => {
            status = "degraded";
            let err_msg = e.to_string();
            components.insert(
                "key_manager".to_string(),
                serde_json::json!({ "status": "degraded", "error": err_msg }),
            );
        }
    }

    let body = serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "components": components,
    });

    let status_code = if status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, axum::Json(body)).into_response()
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to install Ctrl+C handler: {}", e);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
