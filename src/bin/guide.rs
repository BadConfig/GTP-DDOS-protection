use gtp_ddos::{bootstrap::Config, crypto::hmac::Blake3Hasher, guide::Guide};

#[tokio::main]
async fn main() {
    let config_path = std::env::var("CONFIG").expect("config path should present");
    let guide_address = std::env::var("ADDRESS").expect("address should present");
    let config = Config::from_file(&config_path);
    let (_, _) = Guide::from_config(&config, guide_address.into())
        .serve::<Blake3Hasher>()
        .await;
    loop {}
}
