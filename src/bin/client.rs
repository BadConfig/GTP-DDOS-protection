use std::time::Duration;

use gtp_ddos::{client, crypto::hmac::Blake3Hasher};

#[tokio::main]
async fn main() {
    let address = std::env::var("SERVER_ADDRESS").expect("server address should be set");
    loop {
        let result = client::make_request::<Blake3Hasher>(address.clone()).await;
        println!("poll result: {}", result.unwrap_or("error".into()));
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}
