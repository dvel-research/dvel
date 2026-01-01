use crate::bft::types::{node_id_from_pubkey, ValidatorInfo};
use crate::event::PublicKey;
use hex::FromHex;

#[cfg(feature = "bft")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub validators: Vec<ValidatorConfig>,
    #[cfg_attr(feature = "bft", serde(default))]
    pub consensus: ConsensusConfig,
    #[cfg_attr(feature = "bft", serde(default))]
    pub client: ClientConfig,
    #[cfg_attr(feature = "bft", serde(default))]
    pub transport: TransportConfig,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct ValidatorConfig {
    pub pubkey_hex: String,
    pub address: String,
    #[cfg_attr(feature = "bft", serde(default))]
    pub power: u64,
    #[cfg_attr(feature = "bft", serde(default))]
    pub tls_cert_hex: Option<String>,
    #[cfg_attr(feature = "bft", serde(default = "default_stake"))]
    pub stake: u64,
}

fn default_stake() -> u64 {
    1_000_000
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub max_block_bytes: u64,
    pub max_events: u64,
    pub target_block_ms: u64,
    pub propose_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub timeout_backoff_num: u64,
    pub timeout_backoff_den: u64,
    pub timeout_cap_ms: u64,
    #[cfg_attr(feature = "bft", serde(default))]
    pub slashing: SlashingConfig,
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct SlashingConfig {
    #[cfg_attr(feature = "bft", serde(default = "default_slash_enabled"))]
    pub enabled: bool,
    #[cfg_attr(feature = "bft", serde(default = "default_double_sign_slash"))]
    pub double_sign_percent: u64,
    #[cfg_attr(feature = "bft", serde(default = "default_invalid_proposal_slash"))]
    pub invalid_proposal_percent: u64,
    #[cfg_attr(feature = "bft", serde(default = "default_jail_duration"))]
    pub jail_duration_blocks: u64,
}

fn default_slash_enabled() -> bool {
    true
}

fn default_double_sign_slash() -> u64 {
    5 // 5% of stake
}

fn default_invalid_proposal_slash() -> u64 {
    1 // 1% of stake
}

fn default_jail_duration() -> u64 {
    1000 // blocks
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            enabled: default_slash_enabled(),
            double_sign_percent: default_double_sign_slash(),
            invalid_proposal_percent: default_invalid_proposal_slash(),
            jail_duration_blocks: default_jail_duration(),
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            max_block_bytes: 1_048_576,
            max_events: 5_000,
            target_block_ms: 2_000,
            propose_timeout_ms: 800,
            prevote_timeout_ms: 600,
            precommit_timeout_ms: 600,
            timeout_backoff_num: 3,
            timeout_backoff_den: 2,
            timeout_cap_ms: 10_000,
            slashing: SlashingConfig::default(),
        }
    }
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct ClientConfig {
    #[cfg_attr(feature = "bft", serde(default))]
    pub listen_addr: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:7000".to_string(),
        }
    }
}

#[cfg_attr(feature = "bft", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct TransportConfig {
    #[cfg_attr(feature = "bft", serde(default))]
    pub tls_enabled: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { tls_enabled: false }
    }
}

impl GenesisConfig {
    pub fn validator_infos(&self) -> Result<Vec<ValidatorInfo>, String> {
        let mut out = Vec::with_capacity(self.validators.len());
        for v in &self.validators {
            let pubkey = parse_pubkey(&v.pubkey_hex)?;
            let node_id = node_id_from_pubkey(&pubkey);
            let power = if v.power == 0 { 1 } else { v.power };
            let stake = if v.stake == 0 { default_stake() } else { v.stake };
            let tls_cert = match &v.tls_cert_hex {
                Some(hex) => Some(parse_tls_cert(hex)?),
                None => None,
            };
            if self.transport.tls_enabled && tls_cert.is_none() {
                return Err("tls enabled but validator missing tls_cert_hex".into());
            }
            out.push(ValidatorInfo {
                pubkey,
                node_id,
                address: v.address.clone(),
                power,
                stake,
                tls_cert,
            });
        }
        Ok(out)
    }
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey, String> {
    let bytes = <[u8; 32]>::from_hex(hex_str)
        .map_err(|_| "invalid pubkey hex (expected 32 bytes)".to_string())?;
    Ok(bytes)
}

fn parse_tls_cert(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|_| "invalid tls_cert_hex".to_string())
}
