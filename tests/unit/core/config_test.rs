use app_security::core::config::AppConfig;

#[test]
fn test_default_config() {
    let config = AppConfig::default();
    assert!(config.general.auto_start);
    assert!(!config.general.minimize_to_tray);
    assert!(config.general.check_updates);
}

#[test]
fn test_config_serialization() {
    let config = AppConfig::default();
    let toml = toml::to_string_pretty(&config).unwrap();
    let deserialized: AppConfig = toml::from_str(&toml).unwrap();

    assert_eq!(config.general.auto_start, deserialized.general.auto_start);
    assert_eq!(
        config.general.minimize_to_tray,
        deserialized.general.minimize_to_tray
    );
    assert_eq!(
        config.general.check_updates,
        deserialized.general.check_updates
    );
}

#[test]
fn test_config_modules_populated() {
    let config = AppConfig::default();
    assert!(config.modules.contains_key("vpn"));
    assert!(config.modules.contains_key("killswitch"));
    assert!(config.modules.contains_key("arp_detector"));
    assert_eq!(config.modules.len(), 3);
}

#[test]
fn test_config_load_and_save_roundtrip() {
    let config = AppConfig::default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_config.toml");

    config.save(path.to_str().unwrap()).unwrap();
    let loaded = AppConfig::load(path.to_str().unwrap()).unwrap();

    assert_eq!(config.general.auto_start, loaded.general.auto_start);
    assert_eq!(
        config.general.minimize_to_tray,
        loaded.general.minimize_to_tray
    );
    assert_eq!(
        config.general.check_updates,
        loaded.general.check_updates
    );
    assert_eq!(config.modules.len(), loaded.modules.len());
}

#[test]
fn test_config_load_nonexistent_file() {
    let result = AppConfig::load("/nonexistent/path/config.toml");
    assert!(result.is_err());
}

#[test]
fn test_config_from_toml_string() {
    let toml_str = r#"
[general]
auto_start = false
minimize_to_tray = true
check_updates = false

[modules.vpn]
enabled = true
auto_start = true
settings = {}

[modules.killswitch]
enabled = false
auto_start = false
settings = {}
"#;
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.general.auto_start);
    assert!(config.general.minimize_to_tray);
    assert!(!config.general.check_updates);
    assert!(config.modules["vpn"].enabled);
    assert!(!config.modules["killswitch"].enabled);
}

#[test]
fn test_config_module_settings_json() {
    let toml_str = r#"
[general]
auto_start = true
minimize_to_tray = false
check_updates = true

[modules.vpn]
enabled = true
auto_start = true

[modules.vpn.settings]
server = "us-east-1"
port = 1194
"#;
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    let vpn_settings = &config.modules["vpn"].settings;
    assert_eq!(vpn_settings["server"], "us-east-1");
    assert_eq!(vpn_settings["port"], 1194);
}
