use std::sync::Arc;

use crate::error::EthTrieError;
use crate::rpc::RpcProvider;
use alloy::consensus::Account;
use alloy::hex;
use alloy::primitives::{B256, U256};
use alloy::rpc::types::EIP1186AccountProofResponse;
use alloy_rlp::{decode_exact, encode, Decodable, Encodable, RlpDecodable, RlpEncodable};
use eth_trie::DB;
use eth_trie::{EthTrie, MemoryDB, Trie as _};
use ethereum_types::H256;
use rlp;
use tiny_keccak::Hasher;
use tiny_keccak::Keccak;
use url::Url;

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
    storage_slot: H256,
}

#[derive(Debug, Clone)]
pub struct MptProof {
    root: H256,
    proof: Vec<Vec<u8>>,
    key: H256,
}

impl StorageMptHandler {
    pub fn new(url: Url) -> Result<Self, EthTrieError> {
        let provider = RpcProvider::new(url);
        Ok(Self { provider })
    }

    pub async fn fake_account_balance(
        &self,
        address: alloy::primitives::Address,
        block_number: u64,
    ) -> Result<AccountProof, EthTrieError> {
        let real_proof = self.get_account_proof(address, block_number).await?;
        let payload = self.verify_account_proof(real_proof.clone())?;
        println!(
            "real_state_root: {:?}",
            hex::encode(real_proof.root.as_bytes())
        );
        println!("old payload: {:?}", hex::encode(payload.clone()));
        let faked_account_payload =
            self.update_account_balance(payload.clone(), U256::from(1000))?;
        let new_proof = self.update_proof_auto(real_proof.into(), faked_account_payload)?;
        println!("______________________________________________________");
        let new_payload = self.verify_account_proof(new_proof.clone().into())?;
        println!(
            "new_state_root: {:?}",
            hex::encode(new_proof.root.as_bytes())
        );
        println!("new_payload: {:?}", hex::encode(new_payload.clone()));
        Ok(new_proof.into())
    }

    pub async fn fake_storage_slot(
        &self,
        address: alloy::primitives::Address,
        storage_slot: H256,
        block_number: u64,
        new_value: U256,
    ) -> Result<(), EthTrieError> {
        let key = B256::from_slice(storage_slot.as_bytes());
        let proof = self
            .provider
            .get_proof(address, vec![key], block_number.into())
            .await
            .map_err(EthTrieError::from)?;
        let storage_proof = StorageProof {
            storage_hash: H256::from_slice(proof.storage_hash.as_slice()),
            storage_proof: proof.storage_proof[0]
                .proof
                .iter()
                .map(|p| p.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            storage_slot: self.storage_slot_to_key(storage_slot),
        };

        let account_proof = self
            .parse_account_proof(address, block_number, proof)
            .await?;
        let account_payload = self.verify_account_proof(account_proof.clone())?;

        let res = self.verify_storage_proof(storage_proof.clone())?;
        println!(
            "old_storage_hash: {:?}",
            hex::encode(storage_proof.storage_hash.as_bytes())
        );
        println!("old_value: {:?}", hex::encode(res.clone()));
        println!("______________________________________________________");
        let new_slot = self.update_storage_slot(res, new_value)?;
        let new_storage_proof = self.update_proof_auto(storage_proof.into(), new_slot)?;
        let new_res = self.verify_storage_proof(new_storage_proof.clone().into())?;
        println!(
            "new_storage_hash: {:?}",
            hex::encode(new_storage_proof.root.as_bytes())
        );
        println!("new_value: {:?}", hex::encode(new_res.clone()));
        println!("______________________________________________________");

        println!(
            "old_state_root: {:?}",
            hex::encode(account_proof.root.as_bytes())
        );
        println!(
            "old_account_payload: {:?}",
            hex::encode(account_payload.clone())
        );
        println!("______________________________________________________");

        let new_account_payload =
            self.update_account_storage_root(account_payload, new_storage_proof.root)?;
        let new_account_proof =
            self.update_proof_auto(account_proof.into(), new_account_payload)?;
        let new_account_res = self.verify_account_proof(new_account_proof.clone().into())?;
        println!(
            "new_state_root: {:?}",
            hex::encode(new_account_proof.root.as_bytes())
        );
        println!(
            "new_account_payload: {:?}",
            hex::encode(new_account_res.clone())
        );

        Ok(())
    }

    pub async fn get_account_proof(
        &self,
        address: alloy::primitives::Address,
        block_number: u64,
    ) -> Result<AccountProof, EthTrieError> {
        let proof = self
            .provider
            .get_proof(address, vec![], block_number.into())
            .await
            .map_err(EthTrieError::from)?;
        self.parse_account_proof(address, block_number, proof).await
    }

    async fn parse_account_proof(
        &self,
        address: alloy::primitives::Address,
        block_number: u64,
        proof: EIP1186AccountProofResponse,
    ) -> Result<AccountProof, EthTrieError> {
        let proof_bytes = proof
            .account_proof
            .iter()
            .map(|p| p.to_vec())
            .collect::<Vec<Vec<u8>>>();

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

        let result = trie
            .verify_proof(proof.root, proof.key.as_bytes(), proof.proof)
            .unwrap()
            .unwrap();
        Ok(result)
    }

    pub fn verify_storage_proof(&self, proof: StorageProof) -> Result<Vec<u8>, EthTrieError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let trie = EthTrie::new(memdb);

        let result = trie
            .verify_proof(
                proof.storage_hash,
                proof.storage_slot.as_bytes(),
                proof.storage_proof,
            )
            .unwrap()
            .unwrap();
        Ok(result)
    }

    fn update_account_balance(
        &self,
        account_rlp: Vec<u8>,
        new_balance: U256,
    ) -> Result<Vec<u8>, EthTrieError> {
        let mut account = Account::decode(&mut account_rlp.as_slice()).unwrap();
        account.balance = new_balance;
        let encoded = encode(&account);
        Ok(encoded)
    }

    fn update_account_storage_root(
        &self,
        account_rlp: Vec<u8>,
        new_storage_hash: H256,
    ) -> Result<Vec<u8>, EthTrieError> {
        let mut account = Account::decode(&mut account_rlp.as_slice()).unwrap();
        account.storage_root = B256::from_slice(new_storage_hash.as_bytes());
        let encoded = encode(&account);
        Ok(encoded)
    }

    fn update_storage_slot(
        &self,
        storage_rlp: Vec<u8>,
        new_value: U256,
    ) -> Result<Vec<u8>, EthTrieError> {
        let storage = rlp::decode::<Vec<u8>>(&storage_rlp).unwrap();
        let encoded = encode(new_value);
        Ok(encoded)
    }
    const HASHED_LENGTH: usize = 32;

    fn update_proof_auto(
        &self,
        proof: MptProof,
        new_leaf: Vec<u8>,
    ) -> Result<MptProof, EthTrieError> {
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
        trie.insert(proof.key.as_bytes(), &new_leaf).unwrap();
        let new_root_hash = trie.root_hash().unwrap();

        let new_proof = trie.get_proof(proof.key.as_bytes()).unwrap();
        Ok(MptProof {
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

    fn storage_slot_to_key(&self, storage_key: H256) -> H256 {
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

impl From<AccountProof> for MptProof {
    fn from(proof: AccountProof) -> Self {
        MptProof {
            root: proof.root,
            proof: proof.proof,
            key: proof.key,
        }
    }
}

impl From<StorageProof> for MptProof {
    fn from(proof: StorageProof) -> Self {
        MptProof {
            root: proof.storage_hash,
            proof: proof.storage_proof,
            key: proof.storage_slot,
        }
    }
}

impl From<MptProof> for AccountProof {
    fn from(proof: MptProof) -> Self {
        AccountProof {
            root: proof.root,
            proof: proof.proof,
            key: proof.key,
        }
    }
}

impl From<MptProof> for StorageProof {
    fn from(proof: MptProof) -> Self {
        StorageProof {
            storage_hash: proof.root,
            storage_proof: proof.proof,
            storage_slot: proof.key,
        }
    }
}
