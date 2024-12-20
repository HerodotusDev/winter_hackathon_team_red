use alloy_primitives::{hex, Address, U256};
use eth_trie_proofs::error::EthTrieError;
use eth_trie_proofs::storage::StorageMptHandler;
use ethereum_types::H256;
use url::Url;

struct Instance {
    handler: StorageMptHandler,
}
trait ProofFaker<T> {
    fn new(url: String) -> Self;
    async fn fake_storage_slot(
        &self,
        address: String,
        storage_slot: String,
        block_number: String,
        new_value: String,
    ) -> Result<String, EthTrieError>;
}

impl ProofFaker<StorageMptHandler> for Instance {
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

#[tokio::main]
async fn main() -> Result<(), EthTrieError> {
    let url: String = "https://mainnet.infura.io/v3/66dda5ed7d56432a82c8da4ac54fde8e".to_string();
    let address: String = "Ca14007Eff0dB1f8135f4C25B34De49AB0d42766".to_string();
    let storage_slot: String =
        "4d13244817f246930fdc27dd358d16eb57bb7af945c5c4daddbee79636769dc8".to_string();
    let block_number: String = "1466AB0".to_string();
    let new_value: String = "00".to_string();
    let instance = Instance::new(url.to_string());
    let root = instance
        .fake_storage_slot(address, storage_slot, block_number, new_value)
        .await?;

    println!("root: {:?}", root);

    Ok(())
}

//  let url = Url::parse("https://mainnet.infura.io/v3/66dda5ed7d56432a82c8da4ac54fde8e").unwrap();
//     // println!("{}", address!("CAf4C8e7516b3A008A8D25111f2ba9AC8ede21AE"));
//     // handler.fake_account_balance(address!("CAf4C8e7516b3A008A8D25111f2ba9AC8ede21AE"), 21392048).await.unwrap();
//     handler
//         .fake_storage_slot(
//             address!("Ca14007Eff0dB1f8135f4C25B34De49AB0d42766"),
//             H256::from_slice(
//                 hex::decode("4d13244817f246930fdc27dd358d16eb57bb7af945c5c4daddbee79636769dc8")
//                     .unwrap()
//                     .as_slice(),
//             ),
//             21392048,
//             U256::from_be_slice(hex::decode("00").unwrap().as_slice()),
//         )
//         .await
//         .unwrap();
