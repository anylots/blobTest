use std::{env::var, str::FromStr};

use serde_json::{json, Value};

pub async fn query_blob_tx(hash: &str) -> Option<Value> {
    let params: serde_json::Value = json!([hash]);

    let rt = tokio::task::spawn_blocking(move || {
        query_execution_node(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": params,
            "id": 1,
        }))
    })
    .await
    .unwrap();

    match rt {
        Some(info) => {
            match serde_json::from_str::<Value>(&info) {
                Ok(parsed) => return Some(parsed),
                Err(_) => {
                    log::error!("deserialize query_transaction failed, hash= {:?}", hash);
                    return None;
                }
            };
            // log::info!(
            //     "blobVersionedHashes: {:#?}",
            //     transaction["result"]["blobVersionedHashes"]
            // );
        }
        None => {
            log::error!("query ransaction failed");
            return None;
        }
    }
}

pub async fn query_block(hash: &str) -> Option<Value> {
    let params: serde_json::Value = json!([hash,true]);

    let rt = tokio::task::spawn_blocking(move || {
        query_execution_node(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": params,
            "id": 1,
        }))
    })
    .await
    .unwrap();

    match rt {
        Some(info) => {
            match serde_json::from_str::<Value>(&info) {
                Ok(parsed) => return Some(parsed),
                Err(_) => {
                    log::error!("deserialize query_transaction failed, hash= {:?}", hash);
                    return None;
                }
            };
            // log::info!(
            //     "blobVersionedHashes: {:#?}",
            //     block["result"]["blobVersionedHashes"]
            // );
        }
        None => {
            log::error!("query ransaction failed");
            return None;
        }
    }
}

pub async fn query_side_car(slot: u128, indexes: Vec<u64>) -> Option<Value> {
    let rt = tokio::task::spawn_blocking(move || query_beacon_node(slot, indexes))
        .await
        .unwrap();

    match rt {
        Some(info) => {
            match serde_json::from_str::<Value>(&info) {
                Ok(parsed) => return Some(parsed),
                Err(_) => {
                    log::error!("deserialize query_transaction failed, slot= {:?}", slot);
                    return None;
                }
            };
            // log::info!(
            //     "blobVersionedHashes: {:#?}",
            //     block["result"]["blobVersionedHashes"]
            // );
        }
        None => {
            log::error!("query_side_car failed");
            return None;
        }
    }
}

pub fn query_execution_node(param: &serde_json::Value) -> Option<String> {
    let l1_rpc = var("GAS_ORACLE_L1_RPC").expect("Cannot detect GAS_ORACLE_L1_RPC env var");

    let client = reqwest::blocking::Client::new();
    let url = l1_rpc.to_owned();
    let response = client
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        )
        .json(param)
        .send();
    let rt: Result<String, reqwest::Error> = match response {
        Ok(x) => x.text(),
        Err(e) => {
            log::error!("call prover error, param =  {:#?}, error = {:#?}", param, e);
            return None;
        }
    };

    let rt_text = match rt {
        Ok(x) => x,
        Err(e) => {
            log::error!(
                "fetch prover res_txt error, param =  {:#?}, error = {:#?}",
                param,
                e
            );
            return None;
        }
    };

    Some(rt_text)
}

pub fn query_beacon_node(slot: u128, indexes: Vec<u64>) -> Option<String> {
    let l1_beacon_rpc =
        var("GAS_ORACLE_L1_BEACON_RPC").expect("Cannot detect GAS_ORACLE_L1_RPC env var");

    let client = reqwest::blocking::Client::new();
    let mut url = l1_beacon_rpc.to_owned() + slot.to_string().as_str() + "?";
    for index in indexes {
        url = url + "indices=" + index.to_string().as_str() + "&";
    }
    let response = client
        .get(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        )
        .send();
    let rt: Result<String, reqwest::Error> = match response {
        Ok(x) => x.text(),
        Err(e) => {
            log::error!("call prover error, slot =  {:#?}, error = {:#?}", slot, e);
            return None;
        }
    };

    let rt_text = match rt {
        Ok(x) => x,
        Err(e) => {
            log::error!(
                "fetch prover res_txt error, slot =  {:#?}, error = {:#?}",
                slot,
                e
            );
            return None;
        }
    };

    Some(rt_text)
}

pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}

#[tokio::test]
async fn test_query_execution_node() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    dotenv::dotenv().ok();

    let params: serde_json::Value =
        json!(["0x541cee01d959a9c8ea9f6607763a1e048327dcaf312f1d435fddfbc4a1e78dc7"]);

    let rt = tokio::task::spawn_blocking(move || {
        query_execution_node(
            (&json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByHash",
                "params": params,
                "id": 1,
            })),
        )
    })
    .await
    .unwrap();

    match rt {
        Some(info) => {
            log::info!("query result: {:#?}", info);
            let transaction = match serde_json::from_str::<Value>(&info) {
                Ok(parsed) => parsed,
                Err(_) => {
                    log::error!("deserialize rollup_batch failed, batch index");
                    return;
                }
            };
            log::info!(
                "blobVersionedHashes: {:#?}",
                transaction["result"]["blobVersionedHashes"]
            );
        }
        None => {
            log::error!("submitt prove task failed");
        }
    }
}

#[tokio::test]
async fn test_query_beacon_node() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    dotenv::dotenv().ok();

    let rt = tokio::task::spawn_blocking(move || query_beacon_node(4481517, vec![0]))
        .await
        .unwrap();

    match rt {
        Some(info) => {
            log::info!("query result: {:#?}", info);
            let transaction = match serde_json::from_str::<Value>(&info) {
                Ok(parsed) => parsed,
                Err(_) => {
                    log::error!("deserialize rollup_batch failed, batch index");
                    return;
                }
            };
            log::info!(
                "blobVersionedHashes: {:#?}",
                transaction["data"][0]["kzg_commitment"]
            );
        }
        None => {
            log::error!("submitt prove task failed");
        }
    }
}
