use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Namespace configuration
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub name: String,
    pub max_keys: usize,
    pub allowed_key_types: Vec<crate::KeyType>,
}

/// Namespace manager for multi-tenancy
pub struct NamespaceManager {
    configs: Arc<RwLock<HashMap<String, NamespaceConfig>>>,
}

impl NamespaceManager {
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_namespace(&self, config: NamespaceConfig) -> Result<(), crate::Error> {
        let mut configs = self.configs.write();

        if configs.contains_key(&config.name) {
            return Err(crate::Error::NamespaceNotFound(format!(
                "Namespace already exists: {}",
                config.name
            )));
        }

        configs.insert(config.name.clone(), config);
        Ok(())
    }

    pub fn get_config(&self, namespace: &str) -> Result<NamespaceConfig, crate::Error> {
        let configs = self.configs.read();
        configs
            .get(namespace)
            .cloned()
            .ok_or_else(|| crate::Error::NamespaceNotFound(namespace.to_string()))
    }

    pub fn validate_key_type(
        &self,
        namespace: &str,
        key_type: crate::KeyType,
    ) -> Result<(), crate::Error> {
        let config = self.get_config(namespace)?;

        if !config.allowed_key_types.contains(&key_type) {
            return Err(crate::Error::UnsupportedKeyType(key_type));
        }

        Ok(())
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}
