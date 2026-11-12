#[cfg(feature = "acme")]
mod acme;
mod carrier;
pub mod cli;
mod config;
#[cfg_attr(not(any(target_os = "windows", target_os = "macos")), allow(dead_code))]
mod craft;
mod dgram;
mod dns;
mod doctor;
mod engine;
mod entry;
mod exit;
mod fleet;
mod l3;
mod limits;
mod links;
#[cfg(target_os = "macos")]
mod mac_raw;
mod noise;
mod openvpn;
mod proxy;
mod ramaquic;
#[cfg(target_os = "linux")]
mod raw;
#[cfg(not(target_os = "linux"))]
#[path = "raw_stub.rs"]
mod raw;
mod resume;
mod route;
mod session;
mod stats;
mod status;
#[cfg(target_os = "windows")]
mod win_raw;
mod wire;
mod xui;
pub use shabdiz;
