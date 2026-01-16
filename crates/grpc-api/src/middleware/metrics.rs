use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tonic::Code;

pub struct MetricsCollector {
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    total_duration_ms: Arc<AtomicU64>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_duration_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_request(&self) -> RequestMetrics {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        RequestMetrics {
            start: Instant::now(),
            collector: self.clone(),
        }
    }

    pub fn record_success(&self, duration_ms: u64) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
    }

    pub fn record_failure(&self, duration_ms: u64, _code: Code) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
        self.total_duration_ms
            .fetch_add(duration_ms, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> MetricsStats {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let total_duration = self.total_duration_ms.load(Ordering::Relaxed);

        let avg_duration_ms = if total > 0 { total_duration / total } else { 0 };

        MetricsStats {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            avg_duration_ms,
        }
    }

    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.successful_requests.store(0, Ordering::Relaxed);
        self.failed_requests.store(0, Ordering::Relaxed);
        self.total_duration_ms.store(0, Ordering::Relaxed);
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            total_requests: Arc::clone(&self.total_requests),
            successful_requests: Arc::clone(&self.successful_requests),
            failed_requests: Arc::clone(&self.failed_requests),
            total_duration_ms: Arc::clone(&self.total_duration_ms),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RequestMetrics {
    start: Instant,
    collector: MetricsCollector,
}

impl RequestMetrics {
    pub fn finish_success(self) {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        self.collector.record_success(duration_ms);
    }

    pub fn finish_error(self, code: Code) {
        let duration_ms = self.start.elapsed().as_millis() as u64;
        self.collector.record_failure(duration_ms, code);
    }
}

#[derive(Debug, Clone)]
pub struct MetricsStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        let stats = collector.get_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_requests, 0);
        assert_eq!(stats.failed_requests, 0);
        assert_eq!(stats.avg_duration_ms, 0);
    }

    #[test]
    fn test_record_request() {
        let collector = MetricsCollector::new();
        let metrics = collector.record_request();
        let stats = collector.get_stats();
        assert_eq!(stats.total_requests, 1);

        metrics.finish_success();
        let stats = collector.get_stats();
        assert_eq!(stats.successful_requests, 1);
    }

    #[test]
    fn test_record_failure() {
        let collector = MetricsCollector::new();
        let metrics = collector.record_request();
        metrics.finish_error(Code::Internal);

        let stats = collector.get_stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.successful_requests, 0);
    }

    #[test]
    fn test_reset() {
        let collector = MetricsCollector::new();
        let metrics = collector.record_request();
        metrics.finish_success();

        collector.reset();
        let stats = collector.get_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_requests, 0);
    }
}
