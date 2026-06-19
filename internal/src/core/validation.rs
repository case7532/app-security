use regex::Regex;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid MAC address format: {0}")]
    InvalidMac(String),
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Invalid interface name: {0}")]
    InvalidInterface(String),
}

pub struct InputValidator;

impl InputValidator {
    pub fn validate_mac(mac: &str) -> Result<(), ValidationError> {
        let mac_regex = Regex::new(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
            .map_err(|e| ValidationError::InvalidMac(e.to_string()))?;

        if !mac_regex.is_match(mac) {
            return Err(ValidationError::InvalidMac(mac.to_string()));
        }

        let first_octet = u8::from_str_radix(&mac[0..2], 16)
            .map_err(|_| ValidationError::InvalidMac(mac.to_string()))?;

        if first_octet & 0x01 != 0 {
            return Err(ValidationError::InvalidMac(format!(
                "MAC has multicast bit set: {}",
                mac
            )));
        }

        Ok(())
    }

    pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
        if hostname.is_empty() {
            return Err(ValidationError::InvalidHostname("empty".to_string()));
        }

        if hostname.len() > 253 {
            return Err(ValidationError::InvalidHostname("too long".to_string()));
        }

        let hostname_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
            .map_err(|e| ValidationError::InvalidHostname(e.to_string()))?;

        if !hostname_regex.is_match(hostname) {
            return Err(ValidationError::InvalidHostname(hostname.to_string()));
        }

        Ok(())
    }

    pub fn validate_ip(ip: &str) -> Result<(), ValidationError> {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| ValidationError::InvalidIp(ip.to_string()))?;
        Ok(())
    }
}
