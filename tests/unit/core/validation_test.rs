use app_security::core::validation::InputValidator;

#[test]
fn test_valid_mac() {
    assert!(InputValidator::validate_mac("AA:BB:CC:DD:EE:FF").is_ok());
    assert!(InputValidator::validate_mac("00:11:22:33:44:55").is_ok());
}

#[test]
fn test_invalid_mac_format() {
    assert!(InputValidator::validate_mac("not-a-mac").is_err());
    assert!(InputValidator::validate_mac("AA:BB:CC:DD:EE").is_err());
    assert!(InputValidator::validate_mac("").is_err());
}

#[test]
fn test_multicast_mac() {
    assert!(InputValidator::validate_mac("01:00:00:00:00:00").is_err());
    assert!(InputValidator::validate_mac("FF:FF:FF:FF:FF:FF").is_err());
}

#[test]
fn test_valid_hostname() {
    assert!(InputValidator::validate_hostname("mycomputer").is_ok());
    assert!(InputValidator::validate_hostname("my-computer.local").is_ok());
}

#[test]
fn test_invalid_hostname() {
    assert!(InputValidator::validate_hostname("").is_err());
    assert!(InputValidator::validate_hostname("-invalid").is_err());
    assert!(InputValidator::validate_hostname("a".repeat(300).as_str()).is_err());
}

#[test]
fn test_valid_ip() {
    assert!(InputValidator::validate_ip("192.168.1.1").is_ok());
    assert!(InputValidator::validate_ip("::1").is_ok());
}

#[test]
fn test_invalid_ip() {
    assert!(InputValidator::validate_ip("not-an-ip").is_err());
    assert!(InputValidator::validate_ip("256.256.256.256").is_err());
}
