use anyhow::Result;
use frost_evm::{Signature, VerifyingKey};
use rosetta_client::{EthereumExt, Wallet};

pub async fn deploy_verifier(wallet: &Wallet) -> Result<String> {
    let bytes = hex::decode(include_str!("../sol/Schnorr.bin").trim())?;
    let response = wallet.eth_deploy_contract(bytes).await?;
    let receipt = wallet.eth_transaction_receipt(&response.hash).await?;
    let contract_address = receipt.result["contractAddress"]
        .as_str()
        .unwrap()
        .to_owned();
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
    let message_hash = public_key.message_hash(message);
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
        )
        .await?;
    let result: Vec<String> = serde_json::from_value(response.result)?;
    anyhow::ensure!(result[0] == "true");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rosetta_docker::Env;
    use std::collections::HashMap;

    fn frost_sign(message: &[u8]) -> Result<(VerifyingKey, Signature)> {
        let mut rng = thread_rng();
        let max_signers = 5;
        let min_signers = 3;
        let (shares, pubkeys) =
            frost_evm::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)?;

        // Verifies the secret shares from the dealer and store them in a HashMap.
        // In practice, the KeyPackages must be sent to its respective participants
        // through a confidential and authenticated channel.
        let mut key_packages: HashMap<_, _> = HashMap::new();

        for (k, v) in shares {
            let key_package = frost_evm::keys::KeyPackage::try_from(v)?;
            key_packages.insert(k, key_package);
        }

        let mut nonces = HashMap::new();
        let mut commitments = HashMap::new();

        ////////////////////////////////////////////////////////////////////////////
        // Round 1: generating nonces and signing commitments for each participant
        ////////////////////////////////////////////////////////////////////////////

        // In practice, each iteration of this loop will be executed by its respective participant.
        for participant_index in 1..(min_signers + 1) {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            // Generate one (1) nonce and one SigningCommitments instance for each
            // participant, up to _threshold_.
            let (nonce, commitment) = frost_evm::round1::commit(
                participant_identifier,
                key_packages[&participant_identifier].secret_share(),
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
        let mut signature_shares = Vec::new();
        let comms = commitments.clone().into_values().collect();
        // In practice, the SigningPackage must be sent to all participants
        // involved in the current signing (at least min_signers participants),
        // using an authenticate channel (and confidential if the message is secret).
        let signing_package = frost_evm::SigningPackage::new(comms, message.to_vec());

        ////////////////////////////////////////////////////////////////////////////
        // Round 2: each participant generates their signature share
        ////////////////////////////////////////////////////////////////////////////

        // In practice, each iteration of this loop will be executed by its respective participant.
        for participant_identifier in nonces.keys() {
            let key_package = &key_packages[participant_identifier];

            let nonces_to_use = &nonces[participant_identifier];

            // Each participant generates their signature share.
            let signature_share =
                frost_evm::round2::sign(&signing_package, nonces_to_use, key_package)?;

            // In practice, the signature share must be sent to the Coordinator
            // using an authenticated channel.
            signature_shares.push(signature_share);
        }

        ////////////////////////////////////////////////////////////////////////////
        // Aggregation: collects the signing shares from all participants,
        // generates the final signature.
        ////////////////////////////////////////////////////////////////////////////

        // Aggregate (also verifies the signature shares)
        let group_signature =
            frost_evm::aggregate(&signing_package, &signature_shares[..], &pubkeys)?;
        let group_public = frost_evm::VerifyingKey::new(pubkeys.group_public);

        // Check that the threshold signature can be verified by the group public
        // key (the verification key).
        assert!(group_public.verify(message, &group_signature).is_ok());

        Ok((group_public, group_signature))
    }

    #[tokio::test]
    async fn test_frost() -> Result<()> {
        let message = b"message to sign";
        let (public_key, signature) = frost_sign(message)?;

        let config = rosetta_config_ethereum::config("dev")?;

        let env = Env::new("verify-sig", config.clone()).await?;
        let faucet = 100 * u128::pow(10, config.currency_decimals);
        let wallet = env.ephemeral_wallet()?;
        wallet.faucet(faucet).await?;

        let contract_address = deploy_verifier(&wallet).await?;
        verify_sig(&wallet, &contract_address, public_key, message, &signature).await?;
        Ok(())
    }
}
