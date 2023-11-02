use crate::crypto::{Address, GtpGuideTcpRequest, SecretsStorage};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::error::Error;

pub struct Guide {
    secrets: SecretsStorage,
    address: Address,
    server_address: Address,
}

impl Guide {
    async fn serve(&mut self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(&self.address).await?;
        println!("Listening on: {}", self.address);

        loop {
            let (mut socket, user_address) = listener.accept().await?;

            tokio::spawn(async move {
                let mut buf = Vec::new();

                loop {
                    let n = socket
                        .read_to_end(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    if n == 0 {
                        return;
                    }

                    socket
                        .write(&buf[0..n])
                        .await
                        .expect("failed to write data to socket");
                }
            });
        }
    }
}
