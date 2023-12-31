use gtp_ddos::{bootstrap::Config, crypto::hmac::Blake3Hasher, guide::Guide};

#[tokio::main]
async fn main() {
    let config_path = std::env::var("CONFIG").expect("config path should present");
    let guide_address = std::env::var("ADDRESS").expect("address should present");
    let bind_address = std::env::var("BIND_ADDRESS").expect("bind address should present");
    let config = Config::from_file(&config_path);
    let (handle, _) = Guide::from_config(&config, guide_address)
        .serve::<Blake3Hasher>(bind_address)
        .await;
    handle.await.unwrap();
}
