use serde::{Deserialize, Serialize};

use crate::crypto::{Address, SecretsStorage};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub secrets: HashMap<Address, SecretsStorage>,
    pub server_address: Address,
}

impl Config {
    pub fn from_file(path: &str) -> Self {
        let row_file = fs::read_to_string(path).expect("Should've been able to read config file");
        let config: Config =
            serde_json::from_str(&row_file).expect("Should parse config correctly");
        config
    }
}
