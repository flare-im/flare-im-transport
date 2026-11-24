//! 证书模块
//!
//! 提供证书的解析和转换功能，支持从文件或字符串加载证书
//! 支持 DER 和 PEM 格式，可用于 QUIC 和 WebSocket (TLS)

pub mod converter;
pub mod loader;
pub mod pinning;
pub mod server;

pub use converter::*;
pub use loader::*;
pub use pinning::*;
pub use server::*;

/// 错误类型跨了好几层库，只能看文字。不看最外层：reqwest 的外层错误带 URL，主机名里可能恰好有这些词。
#[cfg(not(target_arch = "wasm32"))]
const TLS_FAILURE_MARKERS: &[&str] = &[
    "certificate",
    "pin mismatch",
    "handshake failure",
    "tls handshake",
    "fatal alert",
    "peer is incompatible",
];

/// 连接阶段的失败是不是 TLS 失败（证书、钉扎、握手）。
#[cfg(not(target_arch = "wasm32"))]
pub fn is_tls_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = error.source();
    while let Some(error) = current {
        let text = error.to_string().to_ascii_lowercase();
        if TLS_FAILURE_MARKERS
            .iter()
            .any(|marker| text.contains(marker))
        {
            return true;
        }
        current = error.source();
    }
    false
}
