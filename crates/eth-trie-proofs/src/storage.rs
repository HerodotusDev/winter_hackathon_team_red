use std::sync::Arc;

use alloy::consensus::Account;
use alloy::hex;
use alloy::network::eip2718::Encodable2718;
use alloy::primitives::{B256, U256};
use eth_trie::{EthTrie, MemoryDB, Trie as _};
use alloy_rlp::{Decodable, Encodable, encode, decode_exact, RlpEncodable, RlpDecodable};
use ethereum_types::{H256, Address};
use url::Url;
use crate::rpc::RpcProvider;
use crate::error::EthTrieError;
use tiny_keccak::Keccak;
use tiny_keccak::Hasher;
use rlp;
use eth_trie::DB;

pub struct StorageMptHandler {
    provider: RpcProvider,
}


#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
struct PayloadNode(Vec<Vec<u8>>);

#[derive(Debug, Clone)]
pub struct AccountProof {
    root: H256,
    proof: Vec<Vec<u8>>,
    key: H256,
}

#[derive(Debug, Clone)]
pub struct StorageProof {
    storage_hash: H256,
    storage_proof: Vec<Vec<u8>>,
    storage_key: H256,
}

impl StorageMptHandler {
    pub fn new(url: Url) -> Result<Self, EthTrieError> {
        let provider = RpcProvider::new(url);
        Ok(Self { provider })
    }

    pub async fn fake_account_balance(&self, address: alloy::primitives::Address, block_number: u64) -> Result<AccountProof, EthTrieError> {
        let real_proof = self.get_account_proof(address, block_number).await?;
        let payload = self.verify_account_proof(real_proof.clone())?;
        println!("real_state_root: {:?}", hex::encode(real_proof.root.as_bytes()));
        println!("old payload: {:?}", hex::encode(payload.clone()));
        let faked_account_payload = self.update_account_balance(payload.clone(), U256::from(1000))?;
        let new_proof = self.update_proof_auto(real_proof, faked_account_payload)?;
        println!("______________________________________________________");
        let new_payload = self.verify_account_proof(new_proof.clone())?;
        println!("new_state_root: {:?}", hex::encode(new_proof.root.as_bytes()));
        println!("new_payload: {:?}", hex::encode(new_payload.clone()));
        Ok(new_proof)
    }

    pub async fn fake_storage_slot(&self, address: alloy::primitives::Address, storage_key: H256, block_number: u64) -> Result<(), EthTrieError> {
        let key = B256::from_slice(self.storage_key_to_key(storage_key).as_bytes());
        let proof = self.provider.get_proof(address, vec![key], block_number.into()).await.map_err(EthTrieError::from)?;
        println!("proof: {:#?}", proof);
        let storage_proof = StorageProof {
            storage_hash: H256::from_slice(proof.storage_hash.as_slice()),
            storage_proof: proof.storage_proof[0].proof.iter().map(|p| p.to_vec()).collect::<Vec<Vec<u8>>>(),
            storage_key: storage_key,
        };
        println!("proof: {:?}", storage_proof);
        let res = self.verify_storage_proof(storage_proof)?;
        println!("res: {:?}", hex::encode(res.clone()));
        Ok(())
    }

    pub async fn get_account_proof(&self, address: alloy::primitives::Address, block_number: u64) -> Result<AccountProof, EthTrieError> {
        let proof = self.provider.get_proof(address, vec![], block_number.into()).await.map_err(EthTrieError::from)?;
        let proof_bytes = proof.account_proof.iter().map(|p| p.to_vec()).collect::<Vec<Vec<u8>>>();

        let key = self.address_to_key(address);
            
        let block = self.provider.get_block(block_number).await?;
        let root = block.header.state_root;

        let account_proof = AccountProof {
            root: H256::from_slice(&root.as_slice()),
            proof: proof_bytes,
            key: key,
        };
        Ok(account_proof)
    }

    pub fn verify_account_proof(&self, proof: AccountProof) -> Result<Vec<u8>, EthTrieError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        let result = trie.verify_proof(proof.root, proof.key.as_bytes(), proof.proof).unwrap().unwrap();
        Ok(result)
    }

    pub fn verify_storage_proof(&self, proof: StorageProof) -> Result<Vec<u8>, EthTrieError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);


        let result = trie.verify_proof(proof.storage_hash, proof.storage_key.as_bytes(), proof.storage_proof).unwrap().unwrap();
        Ok(result)
    }

    fn update_account_balance(&self, account_rlp: Vec<u8>, new_balance: U256) -> Result<Vec<u8>, EthTrieError> {
        let mut account = Account::decode(&mut account_rlp.as_slice()).unwrap();
        account.balance = new_balance;
        let encoded = encode(&account);
        Ok(encoded)
    }
    const HASHED_LENGTH: usize = 32;

    fn update_proof_auto(&self, proof: AccountProof, new_payload: Vec<u8>) -> Result<AccountProof, EthTrieError> {
        let proof_db = Arc::new(MemoryDB::new(true));
        let root_hash = H256::from_slice(proof.root.as_bytes());
        for node_encoded in proof.proof.into_iter() {
            let mut sha3 = Keccak::v256();
            let mut output = [0u8; 32];
            sha3.update(&node_encoded.to_vec());
            sha3.finalize(&mut output);
            let hash = H256::from_slice(&output.as_slice());

            if root_hash.eq(&hash) || node_encoded.len() >= Self::HASHED_LENGTH {
                proof_db.insert(hash.as_bytes(), node_encoded).unwrap();
            }
        }
        let mut trie = EthTrie::new(proof_db).at_root(root_hash);
        trie.insert(proof.key.as_bytes(), &new_payload).unwrap();
        let new_root_hash = trie.root_hash().unwrap();

        let new_proof = trie.get_proof(proof.key.as_bytes()).unwrap();
        Ok(AccountProof {
            root: new_root_hash,
            proof: new_proof,
            key: proof.key,
        })
    }

    fn address_to_key(&self, address: alloy::primitives::Address) -> H256 {
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(&address.to_vec());
        keccak.finalize(&mut output);
        H256::from_slice(&output.as_slice())
    }

    fn storage_key_to_key(&self, storage_key: H256) -> H256 {
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(&storage_key.as_bytes());
        keccak.finalize(&mut output);
        H256::from_slice(&output.as_slice())
    }
}


// trait StorageFaker {
//     fn new(url: Url) -> Self;
//     fn fake_storage_slot(&self, address: Address, storage_key: H256, new_value: U256, block_number: u64) -> Result<StorageProof, EthTrieError>;
//     fn fake_account_balance(&self, address: Address, new_balance: U256, block_number: u64) -> Result<AccountProof, EthTrieError>;
// }
