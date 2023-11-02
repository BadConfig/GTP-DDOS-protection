use std::time::Duration;

use tokio::task::yield_now;

use crate::{
    bootstrap::Config,
    client,
    crypto::{hmac::Blake3Hasher, GtpCrypto},
    guide::Guide,
    server::QuoteServer,
};

#[test]
fn gen_secret() {
    let s = serde_json::to_string(&GtpCrypto::gen_secret()).unwrap();
    println!("{}", s);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn services_happy_path() {
    let config = Config::from_file("./config.json");
    let (_, server_shutdown) =
        QuoteServer::from_config(&config, "0.0.0.0:8000".into(), 1000000000000000000)
            .serve::<Blake3Hasher>()
            .await;
    let (_, guide1_shutdown) = Guide::from_config(&config, "0.0.0.0:4001".into())
        .serve::<Blake3Hasher>()
        .await;
    let (_, guide2_shutdown) = Guide::from_config(&config, "0.0.0.0:4002".into())
        .serve::<Blake3Hasher>()
        .await;
    let (_, guide3_shutdown) = Guide::from_config(&config, "0.0.0.0:4003".into())
        .serve::<Blake3Hasher>()
        .await;

    let _ = client::make_request::<Blake3Hasher>("0.0.0.0:8000".into())
        .await
        .is_some();
    let _ = client::make_request::<Blake3Hasher>("0.0.0.0:8000".into())
        .await
        .is_some();
    let _ = client::make_request::<Blake3Hasher>("0.0.0.0:8000".into())
        .await
        .is_some();
    let _ = client::make_request::<Blake3Hasher>("0.0.0.0:8000".into())
        .await
        .is_some();
    server_shutdown.send(()).unwrap();
    guide1_shutdown.send(()).unwrap();
    guide2_shutdown.send(()).unwrap();
    guide3_shutdown.send(()).unwrap();
}
