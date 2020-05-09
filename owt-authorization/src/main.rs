use rand::prelude::*;
use chrono::prelude::*;
use hmac::{Hmac, Mac};

fn main() {
    println!("OWT Authorization");
    println!("------------------");

    let sample_service_id = "5e72ca9eda3a9a154d25e6b3";
    let sample_service_key = "mW7r59SHlVo5VtK+ZZpqY+SAkf1U3YeuZwQbIT2yNcvPpi15tAKjEehl2TZPteSmK4wx90NRgvFZKyMcML8TgIGVKcWhz/cGtAj/C4L190lPTqjT+G5IH2QMJxL/ojyB0PWS1gzhxaBl49wMgDfrKy/dZoz2XEHfJqQKUJYzBME=";
    let random_data: Vec<u8>= rand::thread_rng().sample_iter(rand::distributions::Standard).take(8).collect();
    let cnounce = hex::encode(&random_data);
    let timestamp = Local::now().timestamp_millis().to_string();
    let mut to_sign = String::new();

    to_sign.push_str(&timestamp);
    to_sign.push(',');
    to_sign.push_str(&cnounce);

    let mut header = String::from("MAuth realm=http://marte3.dit.upm.es,mauth_signature_method=HMAC_SHA256");
    header += ",mauth_serviceid=";
    header += sample_service_id;
    header += ",mauth_cnonce=";
    header += &cnounce;
    header += ",mauth_timestamp=";
    header += &timestamp;
    header += ",mauth_signature=";
    header += calculate_signature(&to_sign, sample_service_key).as_ref();

    println!("Authorization:\n{}\n", header);
}

fn calculate_signature(to_sign: &String, key: &str) -> String{
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_varkey(key.as_ref()).expect("wtf");
    mac.input(to_sign.as_ref());

    let result = mac.result();

    return base64::encode(hex::encode(result.code()));
}
