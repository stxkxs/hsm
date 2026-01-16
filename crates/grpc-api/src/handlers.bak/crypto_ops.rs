use crate::error::{ApiError, Result};
use crate::middleware::auth::AuthInterceptor;
use crate::middleware::logging::RequestLogger;
use crate::middleware::metrics::MetricsCollector;
use crate::proto::hsm::*;
use hsm_auth::Permission;
use hsm_crypto_engine::CryptoEngine;
use hsm_key_manager::KeyManager;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{error, info};

pub struct CryptoOpsHandler {
    crypto_engine: Arc<CryptoEngine>,
    key_manager: Arc<KeyManager>,
    auth: Arc<AuthInterceptor>,
    logger: RequestLogger,
    metrics: MetricsCollector,
}

impl CryptoOpsHandler {
    pub fn new(
        crypto_engine: Arc<CryptoEngine>,
        key_manager: Arc<KeyManager>,
        auth: Arc<AuthInterceptor>,
        metrics: MetricsCollector,
    ) -> Self {
        Self {
            crypto_engine,
            key_manager,
            auth,
            logger: RequestLogger::new(),
            metrics,
        }
    }

    pub async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let method = "Sign";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let key_info = self
            .key_manager
            .get_key(&req.key_id, &req.namespace)
            .await
            .map_err(ApiError::from)?;

        let result = self
            .crypto_engine
            .sign(&key_info.private_key, &req.data)
            .await;

        match result {
            Ok(signature) => {
                info!(
                    user_id = %user_id,
                    key_id = %req.key_id,
                    data_len = req.data.len(),
                    "Data signed successfully"
                );

                let response = SignResponse {
                    signature,
                    algorithm: req.algorithm.clone(),
                };

                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                error!(error = %e, "Failed to sign data");
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let method = "Verify";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let _user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Read)
            .await?;

        let key_info = self
            .key_manager
            .get_key(&req.key_id, &req.namespace)
            .await
            .map_err(ApiError::from)?;

        let public_key = key_info
            .public_key
            .ok_or_else(|| ApiError::InvalidRequest("Public key not available".to_string()))?;

        let result = self
            .crypto_engine
            .verify(&public_key, &req.data, &req.signature)
            .await;

        match result {
            Ok(valid) => {
                let response = VerifyResponse { valid };
                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                error!(error = %e, "Failed to verify signature");
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let method = "Encrypt";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let key_info = self
            .key_manager
            .get_key(&req.key_id, &req.namespace)
            .await
            .map_err(ApiError::from)?;

        let result = self
            .crypto_engine
            .encrypt(&key_info.private_key, &req.plaintext, &req.associated_data)
            .await;

        match result {
            Ok((ciphertext, nonce)) => {
                info!(
                    user_id = %user_id,
                    key_id = %req.key_id,
                    plaintext_len = req.plaintext.len(),
                    "Data encrypted successfully"
                );

                let response = EncryptResponse { ciphertext, nonce };
                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                error!(error = %e, "Failed to encrypt data");
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }

    pub async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let method = "Decrypt";
        let start = self.logger.log_request(&request, method);
        let _metrics = self.metrics.record_request();

        let req = request.get_ref();
        let user_id = self
            .auth
            .authenticate_and_authorize(&request, &req.namespace, Permission::Write)
            .await?;

        let key_info = self
            .key_manager
            .get_key(&req.key_id, &req.namespace)
            .await
            .map_err(ApiError::from)?;

        let result = self
            .crypto_engine
            .decrypt(
                &key_info.private_key,
                &req.ciphertext,
                &req.nonce,
                &req.associated_data,
            )
            .await;

        match result {
            Ok(plaintext) => {
                info!(
                    user_id = %user_id,
                    key_id = %req.key_id,
                    ciphertext_len = req.ciphertext.len(),
                    "Data decrypted successfully"
                );

                let response = DecryptResponse { plaintext };
                let response = Ok(Response::new(response));
                self.logger.log_response(method, &response, start);
                _metrics.finish_success();
                response
            }
            Err(e) => {
                error!(error = %e, "Failed to decrypt data");
                let status = Status::from(ApiError::from(e));
                self.logger.log_response(method, &Err(status.clone()), start);
                _metrics.finish_error(status.code());
                Err(status)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_auth::AuthManager;

    #[tokio::test]
    async fn test_crypto_ops_handler_creation() {
        let auth_manager = Arc::new(AuthManager::new());
        let auth = Arc::new(AuthInterceptor::new(auth_manager));
        let crypto_engine = Arc::new(CryptoEngine::new());
        let key_manager = Arc::new(KeyManager::new().await.unwrap());
        let metrics = MetricsCollector::new();

        let _handler = CryptoOpsHandler::new(crypto_engine, key_manager, auth, metrics);
    }
}
