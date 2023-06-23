const VERSION: &str = env!("CARGO_PKG_VERSION");
const TAG: Option<&str> = option_env!("TAG");

/// Current version of Trustification
pub const fn version() -> &'static str {
    if let Some(tag) = TAG {
        tag
    } else {
        VERSION
    }
}
