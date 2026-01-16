//! Health check system for HSM monitoring
//!
//! This module provides comprehensive health checks for all HSM components,
//! including connectivity, performance, and resource usage checks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum HealthCheckError {
    #[error("Health check failed: {0}")]
    CheckFailed(String),
    #[error("Health check timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, HealthCheckError>;

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Health check result for a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    pub message: String,
    pub last_check: Option<u64>,
    pub metrics: HashMap<String, f64>,
}

impl ComponentHealth {
    pub fn healthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: message.into(),
            last_check: Some(current_timestamp()),
            metrics: HashMap::new(),
        }
    }

    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: message.into(),
            last_check: Some(current_timestamp()),
            metrics: HashMap::new(),
        }
    }

    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: message.into(),
            last_check: Some(current_timestamp()),
            metrics: HashMap::new(),
        }
    }

    pub fn with_metric(mut self, key: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(key.into(), value);
        self
    }
}

/// Complete health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub components: HashMap<String, ComponentHealth>,
    pub timestamp: u64,
}

impl HealthReport {
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            components: HashMap::new(),
            timestamp: current_timestamp(),
        }
    }

    pub fn add_component(&mut self, name: impl Into<String>, health: ComponentHealth) {
        let name = name.into();

        // Update overall status based on component status
        match health.status {
            HealthStatus::Unhealthy => self.status = HealthStatus::Unhealthy,
            HealthStatus::Degraded => {
                if self.status == HealthStatus::Healthy {
                    self.status = HealthStatus::Degraded;
                }
            }
            HealthStatus::Healthy => {}
        }

        self.components.insert(name, health);
    }

    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

impl Default for HealthReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check trait for components
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    async fn check(&self) -> Result<ComponentHealth>;
    fn name(&self) -> &str;
}

/// Health checker that runs periodic health checks
pub struct HealthChecker {
    checks: Arc<RwLock<Vec<Arc<dyn HealthCheck>>>>,
    last_report: Arc<RwLock<Option<HealthReport>>>,
    check_interval: Duration,
}

impl HealthChecker {
    pub fn new(check_interval: Duration) -> Self {
        Self {
            checks: Arc::new(RwLock::new(Vec::new())),
            last_report: Arc::new(RwLock::new(None)),
            check_interval,
        }
    }

    pub fn with_default_interval() -> Self {
        Self::new(Duration::from_secs(30))
    }

    pub async fn add_check(&self, check: Arc<dyn HealthCheck>) {
        self.checks.write().await.push(check);
    }

    pub async fn run_checks(&self) -> HealthReport {
        let mut report = HealthReport::new();
        let checks = self.checks.read().await;

        for check in checks.iter() {
            let health = match check.check().await {
                Ok(h) => h,
                Err(e) => ComponentHealth::unhealthy(format!("Check failed: {}", e)),
            };
            report.add_component(check.name(), health);
        }

        *self.last_report.write().await = Some(report.clone());
        report
    }

    pub async fn get_last_report(&self) -> Option<HealthReport> {
        self.last_report.read().await.clone()
    }

    pub async fn start_periodic_checks(self: Arc<Self>) {
        loop {
            self.run_checks().await;
            tokio::time::sleep(self.check_interval).await;
        }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let checker = Arc::new(self);
        tokio::spawn(async move {
            checker.start_periodic_checks().await;
        })
    }
}

/// Simple connectivity health check
pub struct ConnectivityCheck {
    name: String,
    check_fn: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl ConnectivityCheck {
    pub fn new(
        name: impl Into<String>,
        check_fn: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            check_fn: Arc::new(check_fn),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for ConnectivityCheck {
    async fn check(&self) -> Result<ComponentHealth> {
        if (self.check_fn)() {
            Ok(ComponentHealth::healthy("Connected"))
        } else {
            Ok(ComponentHealth::unhealthy("Not connected"))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Performance health check
pub struct PerformanceCheck {
    name: String,
    threshold_ms: u64,
    measure_fn: Arc<dyn Fn() -> Duration + Send + Sync>,
}

impl PerformanceCheck {
    pub fn new(
        name: impl Into<String>,
        threshold_ms: u64,
        measure_fn: impl Fn() -> Duration + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            threshold_ms,
            measure_fn: Arc::new(measure_fn),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for PerformanceCheck {
    async fn check(&self) -> Result<ComponentHealth> {
        let duration = (self.measure_fn)();
        let ms = duration.as_millis() as u64;

        let health = if ms <= self.threshold_ms {
            ComponentHealth::healthy(format!("Response time: {}ms", ms))
        } else if ms <= self.threshold_ms * 2 {
            ComponentHealth::degraded(format!("Response time: {}ms (above threshold)", ms))
        } else {
            ComponentHealth::unhealthy(format!("Response time: {}ms (critically slow)", ms))
        };

        Ok(health.with_metric("response_time_ms", ms as f64))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_health() {
        let health = ComponentHealth::healthy("All good")
            .with_metric("cpu", 50.0)
            .with_metric("memory", 75.0);

        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.metrics.len(), 2);
    }

    #[test]
    fn test_health_report() {
        let mut report = HealthReport::new();
        assert_eq!(report.status, HealthStatus::Healthy);

        report.add_component("db", ComponentHealth::healthy("Connected"));
        assert_eq!(report.status, HealthStatus::Healthy);

        report.add_component("cache", ComponentHealth::degraded("Slow"));
        assert_eq!(report.status, HealthStatus::Degraded);

        report.add_component("storage", ComponentHealth::unhealthy("Down"));
        assert_eq!(report.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_connectivity_check() {
        let check = ConnectivityCheck::new("test", || true);
        let result = check.check().await.unwrap();
        assert_eq!(result.status, HealthStatus::Healthy);

        let check = ConnectivityCheck::new("test", || false);
        let result = check.check().await.unwrap();
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_performance_check() {
        let check = PerformanceCheck::new("test", 100, || Duration::from_millis(50));
        let result = check.check().await.unwrap();
        assert_eq!(result.status, HealthStatus::Healthy);

        let check = PerformanceCheck::new("test", 100, || Duration::from_millis(150));
        let result = check.check().await.unwrap();
        assert_eq!(result.status, HealthStatus::Degraded);

        let check = PerformanceCheck::new("test", 100, || Duration::from_millis(300));
        let result = check.check().await.unwrap();
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_checker() {
        let checker = HealthChecker::with_default_interval();

        let check1 = Arc::new(ConnectivityCheck::new("test1", || true));
        let check2 = Arc::new(ConnectivityCheck::new("test2", || false));

        checker.add_check(check1).await;
        checker.add_check(check2).await;

        let report = checker.run_checks().await;
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert_eq!(report.components.len(), 2);
    }
}
