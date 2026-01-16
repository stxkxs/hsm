use crate::error::{ApiError, Result};
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::logging::RequestLogger;
use crate::middleware::metrics::MetricsCollector;
use crate::proto::hsm::*;
use hsm_auth::Permission;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{error, info};

pub struct AuditHandler {
    auth: Arc<AuthInterceptor>,
    logger: RequestLogger,
    metrics: MetricsCollector,
    audit_entries: Arc<tokio::sync::RwLock<Vec<AuditLogEntry>>>,
}

impl AuditHandler {
    pub fn new(auth: Arc<AuthInterceptor>, metrics: MetricsCollector) -> Self {
        Self {
            auth,
            logger: RequestLogger::new(),
            metrics,
            audit_entries: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    pub async fn add_audit_entry(
        &self,
        user_id: String,
        operation: String,
        resource_id: String,
        namespace: String,
        success: bool,
        error_message: Option<String>,
        metadata: HashMap<String, String>,
    ) {
        let entry = AuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            user_id,
            operation,
            resource_id,
            namespace,
            success,
            error_message: error_message.unwrap_or_default(),
            metadata,
        };

        let mut entries = self.audit_entries.write().await;
        entries.push(entry);
    }

    pub async fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> Result<Response<GetAuditLogResponse>, Status> {
        let method = "GetAuditLog";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let _user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Read)
            .await?;

        let entries = self.audit_entries.read().await;
        let filtered_entries: Vec<AuditLogEntry> = entries
            .iter()
            .filter(|e| {
                e.namespace == req.namespace
                    && (req.user_id.is_empty() || e.user_id == req.user_id)
                    && (req.operation.is_empty() || e.operation == req.operation)
                    && (req.start_time == 0 || e.timestamp >= req.start_time)
                    && (req.end_time == 0 || e.timestamp <= req.end_time)
            })
            .cloned()
            .collect();

        info!(
            namespace = %req.namespace,
            count = filtered_entries.len(),
            "Retrieved audit log entries"
        );

        let response = GetAuditLogResponse {
            entries: filtered_entries.clone(),
            next_page_token: String::new(),
            total_count: filtered_entries.len() as i32,
        };

        let response = Ok(Response::new(response));
        self.logger.log_response(method, &response, start);
        _metrics.finish_success();
        response
    }

    pub async fn stream_audit_log(
        &self,
        request: Request<StreamAuditLogRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<AuditLogEntry, Status>> + Send>>>, Status> {
        let method = "StreamAuditLog";
        let _start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let _user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Read)
            .await?;

        let entries = self.audit_entries.read().await;
        let filtered_entries: Vec<AuditLogEntry> = entries
            .iter()
            .filter(|e| {
                e.namespace == req.namespace
                    && (req.user_id.is_empty() || e.user_id == req.user_id)
                    && (req.operation.is_empty() || e.operation == req.operation)
                    && (req.start_time == 0 || e.timestamp >= req.start_time)
            })
            .cloned()
            .collect();

        let (tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            for entry in filtered_entries {
                if tx.send(Ok(entry)).await.is_err() {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Pin<Box<dyn Stream<Item = Result<AuditLogEntry, Status>> + Send>>))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_auth::AuthManager;

    #[tokio::test]
    async fn test_add_audit_entry() {
        let auth_manager = Arc::new(AuthManager::new());
        let auth = Arc::new(AuthInterceptor::new(auth_manager));
        let metrics = MetricsCollector::new();
        let handler = AuditHandler::new(auth, metrics);

        handler
            .add_audit_entry(
                "user1".to_string(),
                "GenerateKey".to_string(),
                "key1".to_string(),
                "ns1".to_string(),
                true,
                None,
                HashMap::new(),
            )
            .await;

        let entries = handler.audit_entries.read().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user_id, "user1");
        assert_eq!(entries[0].operation, "GenerateKey");
    }
}
