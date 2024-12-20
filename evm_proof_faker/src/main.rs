use eth_trie_proofs::EthTrieError;
use evm_proof_faker::{Instance, ProofFaker};


#[tokio::main]
async fn main() -> Result<(), EthTrieError> {
    let url: String = "https://mainnet.infura.io/v3/66dda5ed7d56432a82c8da4ac54fde8e".to_string();
    let address: String = "Ca14007Eff0dB1f8135f4C25B34De49AB0d42766".to_string();
    let storage_slot: String =
        "4d13244817f246930fdc27dd358d16eb57bb7af945c5c4daddbee79636769dc8".to_string();
    let block_number: String = "1466AB0".to_string();
    let new_value: String = "00".to_string();
    let instance = Instance::new(url.to_string());
    let proof = instance
        .fake_storage_slot(address, storage_slot, block_number, new_value)
        .await?;

    println!("proof: {:?}", proof);

    Ok(())
}
