use crate::env;
use crate::error::{FnoxError, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;

const PROVIDER_NAME: &str = "Secret Server";
const PROVIDER_URL: &str = "https://fnox.jdx.dev/providers/secretserver";

pub fn env_dependencies() -> &'static [&'static str] {
    &["FNOX_SECRETSERVER_TOKEN", "SECRETSERVER_TOKEN"]
}

fn secretserver_token() -> Option<String> {
    env::var("FNOX_SECRETSERVER_TOKEN")
        .or_else(|_| env::var("SECRETSERVER_TOKEN"))
        .ok()
}

pub struct SecretServerProvider {
    base_url: String,
    token: Option<String>,
}

impl SecretServerProvider {
    pub fn new(base_url: String, token: Option<String>) -> Result<Self> {
        let base_url = secretserver_base_url()
            .or(Some(base_url))
            .map(|v| v.trim_end_matches('/').to_string())
            .ok_or_else(|| FnoxError::ProviderAuthFailed {
                provider: PROVIDER_NAME.to_string(),
                details: "token not configured".to_string(),
                hint: "Set FNOX_SECRETSERVER_TOKEN or pass token in config".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        match token {
            Some(t) => Ok(Self {
                base_url,
                token: Some(t),
            }),
            None => Self::from_env(base_url),
        }
    }

    fn from_env(base_url: String) -> Result<Self> {
        let ss_token = secretserver_token().ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "token not configured".to_string(),
            hint: "Set FNOX_SECRETSERVER_TOKEN or pass token in config".to_string(),
            url: PROVIDER_URL.to_string(),
        })?;
        Ok(Self {
            base_url,
            token: Some(ss_token),
        })
    }

    fn create_client() -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .build()
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to create HTTP client: {}", e),
                hint: "Check your network configuration".to_string(),
                url: PROVIDER_URL.to_string(),
            })
    }

    async fn get_auth_token(&self) -> Result<Option<String>> {
        Ok(self.token.clone())
    }

    fn ensure_token(&self, token: Option<String>) -> Result<String> {
        token.ok_or_else(|| FnoxError::ProviderAuthFailed {
            provider: PROVIDER_NAME.to_string(),
            details: "token not configured".to_string(),
            hint: "Set FNOX_SECRETSERVER_TOKEN or pass token in config".to_string(),
            url: PROVIDER_URL.to_string(),
        })
    }

    async fn get_bearer_token(&self) -> Result<String> {
        self.ensure_token(self.get_auth_token().await?)
    }

    fn parse_reference(&self, value: &str) -> Result<(i32, String)> {
        let parts: Vec<&str> = value.split('/').collect();

        match parts.len() {
            2 => Ok((
                str::parse::<i32>(parts[0]).map_err(|i| FnoxError::ProviderSecretNameInvalid {
                    provider: "secretserver".into(),
                    secret: value.into(),
                    hint: format!("secret name must be of the form [integer ID]/[field-slug], found {} for the integer ID", i)
                })?,
                parts[1].to_lowercase(),
            )),
            _ => Err(FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Invalid reference format: '{}'", value),
                hint: "Expected 'name' or 'name/field'".to_string(),
                url: PROVIDER_URL.to_string(),
            }),
        }
    }

    async fn get_field_value(&self, secret_id: i32, field_slug: &str) -> Result<String> {
        let client = Self::create_client()?;

        let url = format!(
            "{}/api/v1/secrets/{}/fields/{}",
            self.base_url, secret_id, field_slug
        );

        tracing::debug!("Fetching field '{}' for secret {}", field_slug, secret_id);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.get_bearer_token().await?))
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("HTTP request failed: {}", e),
                hint: "Check network connectivity to Secret Server".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: format!("HTTP {}: {}", status, body),
                    hint: "Check your token and permissions".to_string(),
                    url: PROVIDER_URL.to_string(),
                });
            }
            if status.as_u16() == 404 {
                return Err(FnoxError::ProviderSecretNotFound {
                    provider: PROVIDER_NAME.to_string(),
                    secret: format!("secret {} field {}", secret_id, field_slug),
                    hint: "Check that the secret and field exist".to_string(),
                    url: PROVIDER_URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("HTTP {}: {}", status, body),
                hint: "Check your Secret Server configuration".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        let field_response: SecretFieldResponse = response
            .json::<String>()
            .await
            .map(|s| SecretFieldResponse { value: Some(s) })
            .map_err(|e| FnoxError::ProviderInvalidResponse {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to parse field response: {}", e),
                hint: "The Secret Server API returned an unexpected response format".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        Ok(field_response.value.unwrap_or_default())
    }
}

fn secretserver_base_url() -> Option<String> {
    env::var("FNOX_SECRETSERVER_BASE_URL")
        .or_else(|_| env::var("SECRETSERVER_BASE_URL"))
        .ok()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SecretFieldResponse {
    value: Option<String>,
}

#[async_trait]
impl crate::providers::Provider for SecretServerProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![
            crate::providers::ProviderCapability::RemoteRead,
            crate::providers::ProviderCapability::RemoteStorage,
        ]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        tracing::debug!("Getting secret '{}' from Secret Server", value);

        let (id, field) = self.parse_reference(value)?;

        self.get_field_value(id, &field).await
    }

    async fn get_secrets_batch(
        &self,
        secrets: &[(String, String)],
    ) -> HashMap<String, Result<String>> {
        use futures::stream::{self, StreamExt};

        let secrets_vec: Vec<_> = secrets.to_vec();

        let results: Vec<_> = stream::iter(secrets_vec)
            .map(|(key, value)| async move {
                let result = self.get_secret(&value).await;
                (key, result)
            })
            .buffer_unordered(10)
            .collect()
            .await;

        results.into_iter().collect()
    }

    async fn test_connection(&self) -> Result<()> {
        let client = Self::create_client()?;

        let url = format!("{}/api/v1/secrets/lookup", self.base_url);

        tracing::debug!("Testing Secret Server connection: {}", url);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.get_bearer_token().await?))
            .send()
            .await
            .map_err(|e| FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Failed to connect to '{}': {}", self.base_url, e),
                hint: "Check network connectivity to Secret Server".to_string(),
                url: PROVIDER_URL.to_string(),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(FnoxError::ProviderAuthFailed {
                    provider: PROVIDER_NAME.to_string(),
                    details: format!("Connection test failed: HTTP {}", status),
                    hint: "Check your token".to_string(),
                    url: PROVIDER_URL.to_string(),
                });
            }
            return Err(FnoxError::ProviderApiError {
                provider: PROVIDER_NAME.to_string(),
                details: format!("Connection test failed: HTTP {}", status),
                hint: "Check your Secret Server configuration".to_string(),
                url: PROVIDER_URL.to_string(),
            });
        }

        tracing::debug!("Secret Server connection test successful");

        Ok(())
    }
}
