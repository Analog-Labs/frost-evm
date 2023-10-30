use anyhow::Result;
use frost_evm::{Signature, VerifyingKey};
use rosetta_client::Wallet;

pub async fn deploy_verifier(wallet: &Wallet) -> Result<String> {
    let bytes = hex::decode(include_str!("../sol/Schnorr.bin").trim())?;
    let hash = wallet.eth_deploy_contract(bytes).await?;
    let receipt = wallet.eth_transaction_receipt(&hash).await?;
    let contract_address = receipt["contractAddress"].as_str().unwrap().to_owned();
    Ok(contract_address)
}

pub async fn verify_sig(
    wallet: &Wallet,
    contract_address: &str,
    public_key: VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    let (pubkey_x, pubkey_y_parity) = public_key.to_px_parity();
    let message_hash = VerifyingKey::message_hash(message);
    let response = wallet
        .eth_view_call(
            contract_address,
            "function verify(uint8,uint256,uint256,uint256,uint256) returns (bool)",
            &[
                pubkey_y_parity.to_string(),
                hex::encode(pubkey_x),
                hex::encode(message_hash),
                hex::encode(signature.e.to_bytes()),
                hex::encode(signature.z.to_bytes()),
            ],
            None,
        )
        .await?;
    let result: Vec<String> = serde_json::from_value(response)?;
    anyhow::ensure!(result[0] == "true");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rosetta_client::BlockchainConfig;
    use rosetta_docker::Env;
    use rosetta_server_ethereum::MaybeWsEthereumClient;
    use std::collections::{BTreeMap, HashMap};

    fn frost_sign(message: &[u8]) -> Result<(VerifyingKey, Signature)> {
        let mut rng = thread_rng();
        let max_signers = 5;
        let min_signers = 3;
        let (shares, pubkeys) = frost_evm::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost_evm::keys::IdentifierList::Default,
            &mut rng,
        )?;

        // Verifies the secret shares from the dealer and store them in a HashMap.
        // In practice, the KeyPackages must be sent to its respective participants
        // through a confidential and authenticated channel.
        let mut key_packages: HashMap<_, _> = HashMap::new();

        for (k, v) in shares {
            let key_package = frost_evm::keys::KeyPackage::try_from(v)?;
            key_packages.insert(k, key_package);
        }

        let mut nonces = HashMap::new();
        let mut commitments = BTreeMap::new();

        ////////////////////////////////////////////////////////////////////////////
        // Round 1: generating nonces and signing commitments for each participant
        ////////////////////////////////////////////////////////////////////////////

        // In practice, each iteration of this loop will be executed by its respective participant.
        for participant_index in 1..(min_signers + 1) {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            // Generate one (1) nonce and one SigningCommitments instance for each
            // participant, up to _threshold_.
            let (nonce, commitment) = frost_evm::round1::commit(
                key_packages
                    .get(&participant_identifier)
                    .unwrap()
                    .signing_share(),
                &mut rng,
            );
            // In practice, the nonces and commitment must be sent to the coordinator
            // (or to every other participant if there is no coordinator) using
            // an authenticated channel.
            nonces.insert(participant_identifier, nonce);
            commitments.insert(participant_identifier, commitment);
        }

        // This is what the signature aggregator / coordinator needs to do:
        // - decide what message to sign
        // - take one (unused) commitment per signing participant
        let mut signature_shares = HashMap::new();
        // In practice, the SigningPackage must be sent to all participants
        // involved in the current signing (at least min_signers participants),
        // using an authenticate channel (and confidential if the message is secret).
        let signing_package = frost_evm::SigningPackage::new(commitments, message);

        ////////////////////////////////////////////////////////////////////////////
        // Round 2: each participant generates their signature share
        ////////////////////////////////////////////////////////////////////////////

        // In practice, each iteration of this loop will be executed by its respective participant.
        for participant_identifier in nonces.keys() {
            let key_package = key_packages.get(participant_identifier).unwrap();

            let nonces_to_use = &nonces.get(participant_identifier).unwrap();

            // Each participant generates their signature share.
            let signature_share =
                frost_evm::round2::sign(&signing_package, nonces_to_use, key_package)?;

            // In practice, the signature share must be sent to the Coordinator
            // using an authenticated channel.
            signature_shares.insert(*key_package.identifier(), signature_share);
        }

        ////////////////////////////////////////////////////////////////////////////
        // Aggregation: collects the signing shares from all participants,
        // generates the final signature.
        ////////////////////////////////////////////////////////////////////////////

        // Aggregate (also verifies the signature shares)
        let group_signature = frost_evm::aggregate(&signing_package, &signature_shares, &pubkeys)?;
        let group_public = frost_evm::VerifyingKey::new(pubkeys.verifying_key().to_element());

        // Check that the threshold signature can be verified by the group public
        // key (the verification key).
        assert!(group_public.verify(message, &group_signature).is_ok());

        Ok((group_public, group_signature))
    }

    pub async fn client_from_config(config: BlockchainConfig) -> Result<MaybeWsEthereumClient> {
        let url = config.node_uri.to_string();
        MaybeWsEthereumClient::from_config(config, url.as_str()).await
    }

    #[tokio::test]
    async fn test_frost() -> Result<()> {
        let message = b"message to sign";
        let (public_key, signature) = frost_sign(message)?;

        let config = rosetta_config_ethereum::config("dev")?;

        let env = Env::new("verify-sig", config.clone(), client_from_config).await?;
        let faucet = 100 * u128::pow(10, config.currency_decimals);
        let wallet = env.ephemeral_wallet().await?;
        wallet.faucet(faucet).await?;

        let contract_address = deploy_verifier(&wallet).await?;
        verify_sig(&wallet, &contract_address, public_key, message, &signature).await?;
        Ok(())
    }
}
