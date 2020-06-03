use chrono::prelude::*;
use hmac::{Hmac, Mac};
use rand::prelude::*;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Deserialize)]
struct SampleService {
    id: String,
    key: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Conf {
    #[serde(rename = "sampleService")]
    sample_service: SampleService,
}

fn main() {
    println!("OWT Authorization");
    println!("------------------");

    let config = "owt-authorization.toml";
    let mut file = match File::open(config) {
        Ok(f) => f,
        Err(e) => panic!("Failed to open config: {} {}", config, e),
    };

    let mut str_val = String::new();
    match file.read_to_string(&mut str_val) {
        Ok(s) => s,
        Err(e) => panic!("Failed to read file: {}", e),
    };

    let conf: Conf = toml::from_str(&str_val).expect("Failded to parse toml");
    let sample_service_id = conf.sample_service.id;
    let sample_service_key = conf.sample_service.key;

    println!("sampleServiceId: {}", sample_service_id);
    println!("sampleServiceKey: {}", sample_service_key);
    println!("------------------");

    let random_data: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(8)
        .collect();
    let cnounce = hex::encode(&random_data);
    let timestamp = Local::now().timestamp_millis().to_string();
    let mut to_sign = String::new();

    to_sign.push_str(&timestamp);
    to_sign.push(',');
    to_sign.push_str(&cnounce);

    let mut header =
        String::from("MAuth realm=http://marte3.dit.upm.es,mauth_signature_method=HMAC_SHA256");
    header += ",mauth_serviceid=";
    header += &sample_service_id;
    header += ",mauth_cnonce=";
    header += &cnounce;
    header += ",mauth_timestamp=";
    header += &timestamp;
    header += ",mauth_signature=";
    header += calculate_signature(&to_sign, &sample_service_key).as_ref();

    println!("Authorization:\n{}\n", header);
}

fn calculate_signature(to_sign: &String, key: &String) -> String {
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_varkey(key.as_ref()).expect("wtf");
    mac.input(to_sign.as_ref());

    let result = mac.result();

    return base64::encode(hex::encode(result.code()));
}
