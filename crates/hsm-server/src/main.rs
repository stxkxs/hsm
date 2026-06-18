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
use std::time::Duration;
use tokio::signal;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hsm_audit::{AsyncAuditConfig, AsyncAuditLogger, StorageConfig as AuditStorageConfig};
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

    /// Directory for tamper-evident audit logs.
    #[arg(long, env = "HSM_AUDIT_DIR", default_value = "/data/hsm/audit")]
    audit_dir: String,

    /// Maximum number of concurrent connections accepted by the TLS listener.
    ///
    /// Connections beyond this limit wait for a permit before the TLS
    /// handshake begins, bounding the number of in-flight pre-auth handshakes
    /// and the file descriptors they consume. Matches the spec's
    /// `server.max_connections`.
    #[arg(long, env = "HSM_MAX_CONNECTIONS", default_value = "1000")]
    max_connections: usize,

    /// TLS handshake timeout in seconds.
    ///
    /// A connected peer that withholds or trickles its ClientHello (a
    /// slowloris-on-TLS attack) is dropped once this deadline elapses, freeing
    /// the task, the file descriptor, and the connection permit.
    #[arg(long, env = "HSM_TLS_HANDSHAKE_TIMEOUT", default_value = "10")]
    tls_handshake_timeout: u64,
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

    // Initialize the tamper-evident audit logger. Every mutating/crypto REST
    // operation records an event fail-closed before responding, and the
    // /audit endpoint reads from this same logger.
    let audit_logger = Arc::new(
        AsyncAuditLogger::new(AsyncAuditConfig {
            storage: AuditStorageConfig {
                base_dir: args.audit_dir.clone().into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .context("Failed to initialize audit logger")?,
    );

    // Create REST API state, wiring the authorization managers (RBAC,
    // namespaces, ACLs are constructed inside AppState) and the audit logger.
    let app_state = AppState::with_key_manager(session_manager.clone(), key_manager.clone())
        .with_audit_logger(audit_logger.clone());

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
        let tls_config = build_tls_config(cert_path, key_path, args.tls_ca.as_deref())
            .context("Failed to configure TLS")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let token = shutdown_token.clone();
        let serve_cfg = ServeTlsConfig::new(args.max_connections, args.tls_handshake_timeout);
        tokio::spawn(serve_tls(
            rest_listener,
            rest_app,
            acceptor,
            token,
            serve_cfg,
        ))
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

    // Flush and stop the audit writer so no buffered events are lost on exit.
    audit_logger.shutdown().await;

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
            root_store
                .add(cert)
                .context("Failed to add CA certificate to root store")?;
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

/// Resource limits applied to the production TLS listener.
///
/// These bound the work an unauthenticated peer can force the server to hold:
/// a maximum number of concurrent connections (file descriptors + tasks) and a
/// hard deadline on the pre-auth TLS handshake.
#[derive(Clone)]
struct ServeTlsConfig {
    /// Bounds concurrent (in-flight) connections. A permit is acquired before
    /// the TLS handshake starts and released when the connection task ends.
    connection_limit: Arc<Semaphore>,
    /// Maximum duration allowed for the TLS handshake to complete.
    handshake_timeout: Duration,
}

impl ServeTlsConfig {
    /// Build a config from a maximum connection count and handshake timeout
    /// (in seconds).
    ///
    /// `max_connections` is clamped to at least 1 so the listener can always
    /// make forward progress even if misconfigured to 0. `handshake_timeout`
    /// is likewise clamped to a minimum of 1 second.
    fn new(max_connections: usize, handshake_timeout_secs: u64) -> Self {
        let max_connections = max_connections.max(1);
        let handshake_timeout_secs = handshake_timeout_secs.max(1);
        Self {
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            handshake_timeout: Duration::from_secs(handshake_timeout_secs),
        }
    }
}

/// Outcome of a timeout-bounded TLS handshake attempt.
enum HandshakeOutcome<S> {
    /// Handshake completed; the negotiated TLS stream is returned.
    Completed(S),
    /// The handshake itself failed (e.g. bad ClientHello, cert error).
    Failed(std::io::Error),
    /// The handshake deadline elapsed before completion (slowloris-on-TLS).
    TimedOut,
}

/// Perform a TLS handshake bounded by `timeout`.
///
/// A peer that connects but withholds or trickles its ClientHello cannot pin
/// the task indefinitely: once `timeout` elapses the in-progress handshake is
/// dropped and [`HandshakeOutcome::TimedOut`] is returned, releasing the
/// underlying socket.
async fn tls_handshake_with_timeout<IO>(
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: IO,
    timeout: Duration,
) -> HandshakeOutcome<tokio_rustls::server::TlsStream<IO>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => HandshakeOutcome::Completed(s),
        Ok(Err(e)) => HandshakeOutcome::Failed(e),
        Err(_elapsed) => HandshakeOutcome::TimedOut,
    }
}

/// Serve HTTP over TLS using tokio-rustls with graceful shutdown support.
///
/// Each accepted connection is gated behind a semaphore ([`ServeTlsConfig`])
/// bounding concurrency, and its TLS handshake is bounded by a timeout so a
/// slow or stalled peer cannot pin a task and file descriptor pre-auth.
async fn serve_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    acceptor: tokio_rustls::TlsAcceptor,
    shutdown: CancellationToken,
    config: ServeTlsConfig,
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

                // Acquire a connection permit BEFORE spawning work. This caps
                // the number of in-flight pre-auth handshakes; when the limit
                // is reached the accept loop pauses here, applying backpressure
                // rather than spawning unbounded tasks. The permit is held by
                // the spawned task and released (via Drop) when it completes.
                let permit = match Arc::clone(&config.connection_limit).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Semaphore closed — only happens on shutdown.
                        break;
                    }
                };

                let acceptor = acceptor.clone();
                let app = app.clone();
                let handshake_timeout = config.handshake_timeout;

                tokio::spawn(async move {
                    // The permit is moved into this task and dropped when the
                    // task returns, releasing the slot for the next connection.
                    let _permit = permit;

                    let tls_stream = match tls_handshake_with_timeout(
                        &acceptor,
                        stream,
                        handshake_timeout,
                    )
                    .await
                    {
                        HandshakeOutcome::Completed(s) => s,
                        HandshakeOutcome::Failed(e) => {
                            warn!("TLS handshake failed from {}: {}", addr, e);
                            return;
                        }
                        HandshakeOutcome::TimedOut => {
                            warn!(
                                "TLS handshake from {} timed out after {:?}; dropping connection",
                                addr, handshake_timeout
                            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// Install a rustls crypto provider for the process if one isn't already
    /// set. Both `ring` and `aws-lc-rs` are present transitively, so rustls
    /// cannot auto-select; the tests pin `ring` explicitly. Idempotent: a
    /// second call (already-installed) is ignored.
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // --- Connection-cap (semaphore) wiring ------------------------------------

    /// The semaphore must expose exactly `max_connections` permits, refuse to
    /// hand out more once exhausted, and free a slot when a permit is dropped.
    ///
    /// Pre-fix there was no semaphore at all, so an unbounded number of
    /// connections (and pre-auth handshake tasks) could be spawned. This test
    /// pins the cap-and-release contract the fix relies on.
    #[tokio::test]
    async fn serve_tls_config_caps_and_releases_permits() {
        let cfg = ServeTlsConfig::new(2, 10);

        // Two permits available, third must fail while both are held.
        let p1 = Arc::clone(&cfg.connection_limit)
            .try_acquire_owned()
            .expect("first permit should be available");
        let p2 = Arc::clone(&cfg.connection_limit)
            .try_acquire_owned()
            .expect("second permit should be available");
        assert_eq!(cfg.connection_limit.available_permits(), 0);
        assert!(
            Arc::clone(&cfg.connection_limit)
                .try_acquire_owned()
                .is_err(),
            "third concurrent connection must be refused once the cap is reached"
        );

        // Dropping a permit (connection task ends) releases exactly one slot.
        drop(p1);
        assert_eq!(cfg.connection_limit.available_permits(), 1);
        let p3 = Arc::clone(&cfg.connection_limit)
            .try_acquire_owned()
            .expect("a slot should be free after a permit is dropped");

        drop(p2);
        drop(p3);
        assert_eq!(cfg.connection_limit.available_permits(), 2);
    }

    /// A misconfigured `max_connections = 0` must not deadlock the listener:
    /// the cap is clamped to at least one permit, and the handshake timeout is
    /// clamped to at least one second.
    #[tokio::test]
    async fn serve_tls_config_clamps_zero_to_safe_minimums() {
        let cfg = ServeTlsConfig::new(0, 0);
        assert_eq!(
            cfg.connection_limit.available_permits(),
            1,
            "zero max_connections must clamp to one usable permit"
        );
        assert!(
            cfg.handshake_timeout >= Duration::from_secs(1),
            "zero handshake timeout must clamp to at least one second"
        );
    }

    // --- TLS handshake timeout (slowloris) ------------------------------------

    fn test_acceptor() -> tokio_rustls::TlsAcceptor {
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        ensure_crypto_provider();

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build server config");
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    /// Regression for HIGH #19: a peer that connects but never sends a
    /// ClientHello (slowloris-on-TLS) must NOT pin the handshake task forever.
    ///
    /// Pre-fix, `acceptor.accept(stream).await` had no deadline, so this future
    /// never resolves — the task and file descriptor leak. With the timeout
    /// wrapper, the handshake is abandoned once the deadline elapses.
    ///
    /// Uses `start_paused` so the (10s) timeout is exercised deterministically
    /// without real wall-clock waiting: tokio auto-advances time when the
    /// runtime is otherwise idle.
    #[tokio::test(start_paused = true)]
    async fn tls_handshake_with_timeout_fires_on_silent_peer() {
        let acceptor = test_acceptor();

        // A silent, in-memory peer: an in-process duplex stream held open but
        // never written to (no ClientHello is ever sent). Using an in-memory
        // stream rather than a real TCP socket keeps this test DETERMINISTIC
        // under `start_paused` — there is no real socket I/O to race the virtual
        // clock, so `acceptor.accept` stays pending and the 10s timeout fires
        // reliably. `_client_half` must stay in scope so the read side blocks
        // (pending) rather than observing EOF. (A prior version used a real
        // TcpStream and was flaky: the rustls read occasionally errored before
        // the virtual timeout elapsed, yielding Failed instead of TimedOut.)
        let (server_stream, _client_half) = tokio::io::duplex(1024);

        let timeout = Duration::from_secs(10);
        let outcome = tls_handshake_with_timeout(&acceptor, server_stream, timeout).await;

        match outcome {
            HandshakeOutcome::TimedOut => {}
            HandshakeOutcome::Completed(_) => {
                panic!("handshake unexpectedly completed against a silent peer")
            }
            HandshakeOutcome::Failed(e) => {
                panic!("expected a timeout, got handshake failure: {e}")
            }
        }
    }

    /// The timeout wrapper must not break the happy path: a genuine TLS client
    /// completing its handshake within the deadline yields a negotiated stream.
    /// This proves the slowloris fix doesn't reject legitimate connections.
    #[tokio::test]
    async fn tls_handshake_with_timeout_completes_real_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let acceptor = test_acceptor();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Client side: trust the self-signed cert via a custom verifier so the
        // handshake completes without a real CA.
        let client = tokio::spawn(async move {
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config_trust_all()));
            let tcp = tokio::net::TcpStream::connect(addr)
                .await
                .expect("client connect");
            let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .expect("client TLS handshake");
            // Exchange a byte to confirm the channel is live.
            tls.write_all(b"x").await.expect("client write");
            let mut buf = [0u8; 1];
            tls.read_exact(&mut buf).await.expect("client read");
            assert_eq!(&buf, b"y");
        });

        let (server_stream, _peer) = listener.accept().await.expect("accept");
        let timeout = Duration::from_secs(10);

        let outcome = tls_handshake_with_timeout(&acceptor, server_stream, timeout).await;
        let mut tls = match outcome {
            HandshakeOutcome::Completed(s) => s,
            HandshakeOutcome::TimedOut => panic!("legitimate handshake timed out"),
            HandshakeOutcome::Failed(e) => panic!("legitimate handshake failed: {e}"),
        };

        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"x");
        tls.write_all(b"y").await.expect("server write");

        client.await.expect("client task");
    }

    /// rustls client config that accepts any server certificate — for tests
    /// only, so a self-signed server cert handshakes successfully.
    fn client_config_trust_all() -> rustls::ClientConfig {
        ensure_crypto_provider();

        #[derive(Debug)]
        struct NoVerify;

        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls_pki_types::CertificateDer<'_>,
                _intermediates: &[rustls_pki_types::CertificateDer<'_>],
                _server_name: &rustls_pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls_pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls_pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls_pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                use rustls::SignatureScheme::*;
                vec![
                    ECDSA_NISTP256_SHA256,
                    ED25519,
                    RSA_PKCS1_SHA256,
                    RSA_PSS_SHA256,
                ]
            }
        }

        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    }
}
