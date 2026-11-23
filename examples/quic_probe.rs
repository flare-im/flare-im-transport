//! 非交互 QUIC 连通性探测：`cargo run --example quic_probe -- quic://host:port [ca-cert-file]`
//!
//! 只做建连（TLS 握手 + 协商），用来区分三种失败：
//! UDP 不通（超时）、证书不被信任（invalid peer certificate）、服务端拒绝。
//! 已启用鉴权的网关可通过 FLARE_QUIC_PROBE_TOKEN 和 FLARE_QUIC_PROBE_DEVICE_ID
//! 提供测试账号的 IM 连接令牌及签发时使用的设备 ID。
use flare_core::client::HybridClient;
use flare_core::client::{Client, ClientConfig};
use flare_core::common::config_types::TlsConfig;
use flare_core::common::device::{DeviceInfo, DevicePlatform};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "quic://127.0.0.1:60052".to_string());
    let ca = args.next();
    let mut config = ClientConfig::new(url.clone()).quic();
    if let Some(token) = std::env::var_os("FLARE_QUIC_PROBE_TOKEN") {
        let token = token
            .into_string()
            .map_err(|_| "invalid probe token encoding")?;
        let device = std::env::var("FLARE_QUIC_PROBE_DEVICE_ID")?;
        if token.is_empty() || device.is_empty() {
            return Err("probe token and device id must be nonempty".into());
        }
        config = config
            .with_token(token)
            .with_device_info(DeviceInfo::new(device, DevicePlatform::PC));
    }
    if let Some(ca) = ca {
        config.tls = TlsConfig::none().with_ca_cert(PathBuf::from(ca));
    }
    let started = std::time::Instant::now();
    match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        HybridClient::connect_with_race(config),
    )
    .await
    {
        Ok(Ok(mut client)) => {
            println!(
                "QUIC_PROBE ok url={url} elapsed_ms={}",
                started.elapsed().as_millis()
            );
            let _ = client.disconnect().await;
        }
        Ok(Err(e)) => {
            println!(
                "QUIC_PROBE error url={url} elapsed_ms={} err={e}",
                started.elapsed().as_millis()
            );
            std::process::exit(2);
        }
        Err(_) => {
            println!("QUIC_PROBE timeout url={url} (UDP 很可能不通)");
            std::process::exit(3);
        }
    }
    Ok(())
}
