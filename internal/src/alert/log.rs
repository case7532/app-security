use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::types::{Alert, AlertConfig};

/// Alert logger that writes alerts to a JSON log file.
pub struct AlertLogger {
    /// Path to the log file.
    log_path: Option<String>,
    /// Whether logging is enabled.
    enabled: bool,
    /// File handle for writing.
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl AlertLogger {
    /// Create a new AlertLogger from configuration.
    pub fn from_config(config: &AlertConfig) -> Self {
        let log_path = config.log_file_path.clone().or_else(|| {
            dirs::data_local_dir().map(|d| {
                let path = d.join("app-security").join("alerts.json");
                std::fs::create_dir_all(path.parent().unwrap()).ok();
                path.to_string_lossy().to_string()
            })
        });

        Self {
            log_path,
            enabled: config.log_to_file,
            file: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a logger with a specific path.
    pub fn new(log_path: String) -> Self {
        Self {
            log_path: Some(log_path),
            enabled: true,
            file: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize the log file.
    pub async fn initialize(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if let Some(ref path) = self.log_path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("Failed to open log file: {}", e))?;

            let mut file_lock = self.file.lock().await;
            *file_lock = Some(file);
        }

        Ok(())
    }

    /// Write an alert to the log file.
    pub async fn log_alert(&self, alert: &Alert) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let json = serde_json::to_string(alert)
            .map_err(|e| format!("Failed to serialize alert: {}", e))?;

        let mut file_lock = self.file.lock().await;
        if let Some(ref mut file) = *file_lock {
            writeln!(file, "{}", json)
                .map_err(|e| format!("Failed to write alert: {}", e))?;
            file.flush()
                .map_err(|e| format!("Failed to flush log: {}", e))?;
        }

        Ok(())
    }

    /// Get the log file path.
    pub fn log_path(&self) -> Option<&str> {
        self.log_path.as_deref()
    }

    /// Read alerts from the log file.
    pub async fn read_alerts(&self) -> Result<Vec<Alert>, String> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let path = match &self.log_path {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };

        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read log file: {}", e))?;

        let mut alerts = Vec::new();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            if let Ok(alert) = serde_json::from_str::<Alert>(line) {
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    /// Clear the log file.
    pub async fn clear_log(&self) -> Result<(), String> {
        if let Some(ref path) = self.log_path {
            std::fs::write(path, "")
                .map_err(|e| format!("Failed to clear log file: {}", e))?;
        }
        Ok(())
    }
}

impl Default for AlertLogger {
    fn default() -> Self {
        Self {
            log_path: None,
            enabled: false,
            file: Arc::new(Mutex::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::AlertSeverity;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_logger_creates_file() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        let logger = AlertLogger::new(path.clone());

        logger.initialize().await.unwrap();
        assert!(Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_logger_writes_alert() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        let logger = AlertLogger::new(path.clone());

        logger.initialize().await.unwrap();

        let alert = Alert::new(
            AlertSeverity::High,
            "Test".to_string(),
            "Message".to_string(),
        );
        logger.log_alert(&alert).await.unwrap();

        let alerts = logger.read_alerts().await.unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Test");
    }

    #[tokio::test]
    async fn test_logger_writes_multiple() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        let logger = AlertLogger::new(path.clone());

        logger.initialize().await.unwrap();

        for i in 0..3 {
            let alert = Alert::new(
                AlertSeverity::Info,
                format!("Alert {}", i),
                "msg".to_string(),
            );
            logger.log_alert(&alert).await.unwrap();
        }

        let alerts = logger.read_alerts().await.unwrap();
        assert_eq!(alerts.len(), 3);
    }

    #[tokio::test]
    async fn test_logger_clear() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        let logger = AlertLogger::new(path.clone());

        logger.initialize().await.unwrap();

        let alert = Alert::new(
            AlertSeverity::Info,
            "Test".to_string(),
            "msg".to_string(),
        );
        logger.log_alert(&alert).await.unwrap();
        assert_eq!(logger.read_alerts().await.unwrap().len(), 1);

        logger.clear_log().await.unwrap();
        assert_eq!(logger.read_alerts().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_logger_disabled() {
        let logger = AlertLogger::default();
        assert!(logger.read_alerts().await.unwrap().is_empty());

        let alert = Alert::new(
            AlertSeverity::Info,
            "Test".to_string(),
            "msg".to_string(),
        );
        // Should not error when disabled
        logger.log_alert(&alert).await.unwrap();
    }
}
