use gtp_ddos::{bootstrap::Config, crypto::hmac::Blake3Hasher, server::QuoteServer};

#[tokio::main]
async fn main() {
    let config_path = std::env::var("CONFIG").expect("config path should present");
    let server_address = std::env::var("ADDRESS").expect("address should present");
    let bind_address = std::env::var("BIND_ADDRESS").expect("bind address should present");
    let config = Config::from_file(&config_path);
    let (_, _) = QuoteServer::from_config(&config, server_address.into(), 1000000000000000000)
        .serve::<Blake3Hasher>(bind_address)
        .await;
    loop {}
}
