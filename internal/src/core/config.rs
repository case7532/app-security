use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::mod_trait::ModuleConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub modules: HashMap<String, ModuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub check_updates: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut modules = HashMap::new();
        modules.insert("vpn".to_string(), ModuleConfig::default());
        modules.insert("killswitch".to_string(), ModuleConfig::default());
        modules.insert("arp_detector".to_string(), ModuleConfig::default());

        Self {
            general: GeneralConfig {
                auto_start: true,
                minimize_to_tray: false,
                check_updates: true,
            },
            modules,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&content).map_err(|e| e.to_string())
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, content).map_err(|e| e.to_string())
    }
}
