use serde::{Deserialize, Serialize};

pub const HOSTNAME: &str = "drukarka";
pub const DOMAIN: &str = "drukarka.local";
pub const STATIC_IP: &str = "192.168.18.129";
pub const ADMIN_USER: &str = "admin";
pub const PRINTER_NAME: &str = "HP_LaserJet_P1005";
pub const PRINTER_DEVICE_URI: &str = "hp:/usb/HP_LaserJet_P1005?serial=*";

pub const OPT_ROOT: &str = "/opt/drukarka";
pub const CURRENT_LINK: &str = "/opt/drukarka/current";
pub const PREVIOUS_LINK: &str = "/opt/drukarka/previous";
pub const RELEASES_DIR: &str = "/opt/drukarka/releases";
pub const STATE_DB: &str = "/var/lib/drukarka/state.db";
pub const CA_DIR: &str = "/etc/drukarka-ca";
pub const CUPS_LOCAL_PORT: u16 = 8631;
pub const IPP_LISTEN_PORT: u16 = 631;
pub const HTTPS_PORT: u16 = 443;
pub const HTTP_PORT: u16 = 80;
pub const APP_BIND: &str = "127.0.0.1:9090";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseMeta {
    pub id: String,
    pub built_at: String,
    pub git_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetHost {
    pub host: String,
    pub user: String,
    pub port: u16,
}

impl Default for TargetHost {
    fn default() -> Self {
        Self {
            // Prefer mDNS; DHCP IP may change (reservation is optional).
            host: DOMAIN.to_string(),
            user: ADMIN_USER.to_string(),
            port: 22,
        }
    }
}
