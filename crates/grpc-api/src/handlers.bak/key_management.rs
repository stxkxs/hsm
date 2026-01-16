use crate::error::{ApiError, Result};
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::logging::RequestLogger;
use crate::middleware::metrics::MetricsCollector;
use crate::proto::hsm::*;
use hsm_auth::Permission;
use hsm_key_manager::{KeyManager, KeyType as KmKeyType, KeyUsagePolicy as KmPolicy};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{error, info};

pub struct KeyManagementHandler {
    key_manager: Arc<KeyManager>,
    auth: Arc<AuthInterceptor>,
    logger: RequestLogger,
    metrics: MetricsCollector,
}

impl KeyManagementHandler {
    pub fn new(
        key_manager: Arc<KeyManager>,
        auth: Arc<AuthInterceptor>,
        metrics: MetricsCollector,
    ) -> Self {
        Self {
            key_manager,
            auth,
            logger: RequestLogger::new(),
            metrics,
        }
    }

    pub async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let method = "GenerateKey";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let key_type = self.convert_key_type(req.key_type)?;
        let policy = self.convert_policy(req.policy.as_ref())?;

        let result = self
            .key_manager
            .generate_key(&req.namespace, key_type, policy)
            .await;

        match result {
            Ok(key_info) => {
                info!(
                    user_id = %user_id,
                    key_id = %key_info.id,
                    namespace = %req.namespace,
                    "Key generated successfully"
                );

                let response = GenerateKeyResponse {
                    key_id: key_info.id.clone(),
                    public_key: key_info.public_key.unwrap_or_default(),
                    metadata: Some(self.convert_key_metadata(&key_info)),
                };

                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                error!(error = %e, "Failed to generate key");
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<GetKeyResponse>, Status> {
        let method = "GetKey";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let _user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Read)
            .await?;

        let result = self.key_manager.get_key(&req.key_id, &req.namespace).await;

        match result {
            Ok(key_info) => {
                let response = GetKeyResponse {
                    metadata: Some(self.convert_key_metadata(&key_info)),
                    public_key: key_info.public_key.unwrap_or_default(),
                };

                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn list_keys(
        &self,
        request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let method = "ListKeys";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let _user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Read)
            .await?;

        let result = self.key_manager.list_keys(&req.namespace).await;

        match result {
            Ok(keys) => {
                let response = ListKeysResponse {
                    keys: keys.iter().map(|k| self.convert_key_metadata(k)).collect(),
                    next_page_token: String::new(),
                    total_count: keys.len() as i32,
                };

                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let method = "DeleteKey";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let result = self.key_manager.delete_key(&req.key_id, &req.namespace).await;

        match result {
            Ok(_) => {
                info!(
                    user_id = %user_id,
                    key_id = %req.key_id,
                    namespace = %req.namespace,
                    "Key deleted successfully"
                );

                let response = DeleteKeyResponse { success: true };
                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let method = "RotateKey";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let result = self
            .key_manager
            .rotate_key(&req.key_id, &req.namespace)
            .await;

        match result {
            Ok(new_key) => {
                info!(
                    user_id = %user_id,
                    old_key_id = %req.key_id,
                    new_key_id = %new_key.id,
                    namespace = %req.namespace,
                    "Key rotated successfully"
                );

                let response = RotateKeyResponse {
                    new_key_id: new_key.id.clone(),
                    metadata: Some(self.convert_key_metadata(&new_key)),
                };

                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    fn convert_key_type(&self, key_type: i32) -> Result<KmKeyType> {
        match KeyType::try_from(key_type) {
            Ok(KeyType::KeyTypeRsa2048) => Ok(KmKeyType::Rsa2048),
            Ok(KeyType::KeyTypeRsa4096) => Ok(KmKeyType::Rsa4096),
            Ok(KeyType::KeyTypeEcdsaP256) => Ok(KmKeyType::EcdsaP256),
            Ok(KeyType::KeyTypeEcdsaP384) => Ok(KmKeyType::EcdsaP384),
            Ok(KeyType::KeyTypeEd25519) => Ok(KmKeyType::Ed25519),
            Ok(KeyType::KeyTypeAes256) => Ok(KmKeyType::Aes256),
            _ => Err(ApiError::InvalidKeyType(format!("Unknown key type: {}", key_type))),
        }
    }

    fn convert_policy(&self, policy: Option<&KeyUsagePolicy>) -> Result<KmPolicy> {
        let policy = policy.ok_or_else(|| ApiError::InvalidRequest("Missing key usage policy".to_string()))?;

        Ok(KmPolicy {
            exportable: policy.exportable,
            max_uses: if policy.max_uses > 0 { Some(policy.max_uses as u64) } else { None },
            expiry_time: if policy.expiry_time > 0 { Some(policy.expiry_time as u64) } else { None },
        })
    }

    fn convert_key_metadata(&self, key_info: &hsm_key_manager::KeyInfo) -> KeyMetadata {
        KeyMetadata {
            key_id: key_info.id.clone(),
            namespace: key_info.namespace.clone(),
            key_type: self.convert_km_key_type(&key_info.key_type),
            state: KeyState::KeyStateActive as i32,
            policy: Some(KeyUsagePolicy {
                allowed_usages: vec![],
                exportable: key_info.policy.exportable,
                max_uses: key_info.policy.max_uses.unwrap_or(0) as i64,
                expiry_time: key_info.policy.expiry_time.unwrap_or(0) as i64,
                allowed_namespaces: vec![key_info.namespace.clone()],
            }),
            created_at: key_info.created_at as i64,
            updated_at: key_info.updated_at as i64,
            version: key_info.version.to_string(),
        }
    }

    fn convert_km_key_type(&self, key_type: &KmKeyType) -> i32 {
        match key_type {
            KmKeyType::Rsa2048 => KeyType::KeyTypeRsa2048 as i32,
            KmKeyType::Rsa4096 => KeyType::KeyTypeRsa4096 as i32,
            KmKeyType::EcdsaP256 => KeyType::KeyTypeEcdsaP256 as i32,
            KmKeyType::EcdsaP384 => KeyType::KeyTypeEcdsaP384 as i32,
            KmKeyType::Ed25519 => KeyType::KeyTypeEd25519 as i32,
            KmKeyType::Aes256 => KeyType::KeyTypeAes256 as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_auth::AuthManager;

    #[tokio::test]
    async fn test_convert_key_type() {
        let auth_manager = Arc::new(AuthManager::new());
        let auth = Arc::new(AuthInterceptor::new(auth_manager));
        let key_manager = Arc::new(KeyManager::new().await.unwrap());
        let metrics = MetricsCollector::new();
        let handler = KeyManagementHandler::new(key_manager, auth, metrics);

        let result = handler.convert_key_type(KeyType::KeyTypeRsa2048 as i32);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), KmKeyType::Rsa2048));
    }
}
