use reqwest::Client;
use std::net::IpAddr;

#[derive(Debug)]
pub enum DohError {
    NetworkError(String),
    EncodingError(String),
    DecodingError(String),
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DohError::NetworkError(e) => write!(f, "Network error: {}", e),
            DohError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            DohError::DecodingError(e) => write!(f, "Decoding error: {}", e),
        }
    }
}

impl std::error::Error for DohError {}

pub struct DohClient {
    resolver_url: String,
    client: Client,
}

impl DohClient {
    pub fn new(resolver_url: String) -> Self {
        Self {
            resolver_url,
            client: Client::new(),
        }
    }

    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DohError> {
        // Build a simple DNS-over-HTTPS GET request (RFC 8484 wire format).
        // For now we use the JSON API (RFC 8484 / application/dns-json) as a
        // practical interim that does not require base64-encoded wire-format
        // messages.  The JSON wire format is supported by Cloudflare, Google,
        // and most public DoH resolvers.
        let url = format!("{}?name={}&type=A", self.resolver_url, domain);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| DohError::NetworkError(e.to_string()))?;

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| DohError::DecodingError(e.to_string()))?;

        let answers = body
            .get("Answer")
            .and_then(|a| a.as_array())
            .ok_or_else(|| DohError::DecodingError("Missing Answer section".to_string()))?;

        let mut ips = Vec::new();
        for answer in answers {
            if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                if let Ok(ip) = data.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
        }

        Ok(ips)
    }

    /// Returns the resolver URL this client is configured to use.
    pub fn resolver_url(&self) -> &str {
        &self.resolver_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_client_creation() {
        let client = DohClient::new("https://1.1.1.1/dns-query".to_string());
        assert_eq!(client.resolver_url(), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_doh_error_display() {
        let err = DohError::NetworkError("connection refused".to_string());
        assert_eq!(format!("{}", err), "Network error: connection refused");

        let err = DohError::EncodingError("bad input".to_string());
        assert_eq!(format!("{}", err), "Encoding error: bad input");

        let err = DohError::DecodingError("invalid json".to_string());
        assert_eq!(format!("{}", err), "Decoding error: invalid json");
    }

    #[test]
    fn test_doh_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(DohError::NetworkError("test".to_string()));
        assert!(err.to_string().contains("Network error"));
    }
}
