use alloy_primitives::{hex, Address, U256};
use eth_trie_proofs::error::EthTrieError;
use eth_trie_proofs::storage::StorageMptHandler;
use ethereum_types::H256;
use url::Url;

pub struct Instance {
    handler: StorageMptHandler,
}
pub trait ProofFaker {
    fn new(url: String) -> Self;
    async fn fake_storage_slot(
        &self,
        address: String,
        storage_slot: String,
        block_number: String,
        new_value: String,
    ) -> Result<String, EthTrieError>;
}

impl ProofFaker for Instance {
    fn new(url: String) -> Self {
        let url = Url::parse(&url).unwrap();
        Self {
            handler: StorageMptHandler::new(url).unwrap(),
        }
    }

    async fn fake_storage_slot(
        &self,
        address: String,
        storage_slot: String,
        block_number: String,
        new_value: String,
    ) -> Result<String, EthTrieError> {
        let address = address.parse::<Address>().unwrap();
        println!("Address: {:?}", address);
        let storage_slot = H256::from_slice(hex::decode(storage_slot).unwrap().as_slice());
        println!("storage slot: {:?}", storage_slot);
        let block_number = u64::from_str_radix(&block_number, 16).unwrap();
        println!("block number: {:?}", block_number);
        let new_value = U256::from_be_slice(hex::decode(new_value).unwrap().as_slice());
        println!("new value: {:?}", new_value);
        let root = self
            .handler
            .fake_storage(address, storage_slot, block_number, new_value)
            .await
            .unwrap();
        Ok(root)
    }
}
