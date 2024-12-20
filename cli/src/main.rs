// cli.rs
use alloy_primitives::hex::{self, FromHex};
use alloy_primitives::{B256, Address, address, U256};
use clap::{Parser, Subcommand};
use eth_trie_proofs::tx_trie::TxsMptHandler;
use eth_trie_proofs::storage::StorageMptHandler;
use serde::Serialize;
use serde_with::serde_as;
use ethereum_types::{H256};

use eth_trie_proofs::tx_receipt_trie::TxReceiptsMptHandler;
use eth_trie_proofs::EthTrieError;
use url::Url;
#[derive(Debug, Parser)]
#[command(name = "eth-trie-proof")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Generate a MPT proof for a transaction")]
    Tx {
        /// Target transaction hash
        tx_hash: String,
        /// Ethereum node RPC URL
        rpc_url: Option<String>,
    },
    #[command(about = "Generate a MPT proof for a transaction receipt")]
    Receipt {
        /// Receipt transaction hash
        tx_hash: String,
        /// Ethereum node RPC URL
        rpc_url: Option<String>,
    },
}

#[serde_with::serde_as]
#[derive(Debug, Serialize)]
struct MptProof {
    root: B256,
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    proof: Vec<Vec<u8>>,
    index: u64,
}

#[tokio::main]
async fn main() {
    let url = Url::parse("https://mainnet.infura.io/v3/66dda5ed7d56432a82c8da4ac54fde8e").unwrap();
    let handler = StorageMptHandler::new(url).unwrap();
    // println!("{}", address!("CAf4C8e7516b3A008A8D25111f2ba9AC8ede21AE"));
    // handler.fake_account_balance(address!("CAf4C8e7516b3A008A8D25111f2ba9AC8ede21AE"), 21392048).await.unwrap();
    handler.fake_storage_slot(
        address!("Ca14007Eff0dB1f8135f4C25B34De49AB0d42766"), 
        H256::from_slice(hex::decode("4d13244817f246930fdc27dd358d16eb57bb7af945c5c4daddbee79636769dc8").unwrap().as_slice()), 
        21392048,
        U256::from_be_slice(hex::decode("00").unwrap().as_slice())
    ).await.unwrap();
}
// async fn main() -> Result<(), EthTrieError> {
//     let cli = Cli::parse();
//     match cli.command {
//         Commands::Tx { tx_hash, rpc_url } => {
//             generate_tx_proof(
//                 &tx_hash,
//                 rpc_url
//                     .unwrap_or("https://ethereum-rpc.publicnode.com".parse().unwrap())
//                     .as_str(),
//             )
//             .await?;
//         }
//         Commands::Receipt { tx_hash, rpc_url } => {
//             generate_receipt_proof(
//                 &tx_hash,
//                 rpc_url
//                     .unwrap_or("https://ethereum-rpc.publicnode.com".parse().unwrap())
//                     .as_str(),
//             )
//             .await?;
//         }
//     }

//     Ok(())
// }

async fn generate_tx_proof(tx_hash: &str, rpc_url: &str) -> Result<(), EthTrieError> {
    let rpc_url = url::Url::parse(rpc_url).expect("Invalid URL");
    let mut txs_mpt_handler = TxsMptHandler::new(rpc_url)?;
    let tx_hash = B256::from_hex(tx_hash).unwrap();
    txs_mpt_handler.build_tx_tree_from_tx_hash(tx_hash).await?;
    let index = txs_mpt_handler.tx_hash_to_tx_index(tx_hash)?;
    let proof = txs_mpt_handler.get_proof(index)?;
    let root = txs_mpt_handler.get_root()?;

    let mpt_proof = MptProof { root, proof, index };
    print!("{}", serde_json::to_string(&mpt_proof).unwrap());
    Ok(())
}

async fn generate_receipt_proof(tx_hash: &str, rpc_url: &str) -> Result<(), EthTrieError> {
    let rpc_url = url::Url::parse(rpc_url).expect("Invalid URL");
    let mut tx_receipts_mpt_handler = TxReceiptsMptHandler::new(rpc_url)?;
    let tx_hash = B256::from_hex(tx_hash).unwrap();
    tx_receipts_mpt_handler
        .build_tx_receipt_tree_from_tx_hash(tx_hash)
        .await?;
    let index = tx_receipts_mpt_handler.tx_hash_to_tx_index(tx_hash).await?;
    let proof = tx_receipts_mpt_handler.get_proof(index)?;
    let root = tx_receipts_mpt_handler.get_root()?;

    let mpt_proof = MptProof { root, proof, index };
    print!("{}", serde_json::to_string(&mpt_proof).unwrap());
    Ok(())
}
