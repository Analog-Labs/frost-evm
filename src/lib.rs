#[cfg(test)]
mod tests {
    use anyhow::Result;
    use hex_literal::hex;
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{AffinePoint, NonZeroScalar, PublicKey, SecretKey};
    use rosetta_client::EthereumExt;
    use rosetta_docker::Env;
    use sha3::Digest;

    const SECRET_KEY: [u8; 32] =
        hex!("5d18fc9fb6494384932af3bda6fe8102c0fa7a26774e22af3993a69e2ca79565");
    const PUBLIC_KEY: [[u8; 32]; 2] = [
        hex!("6e071bbc2060bce7bae894019d30bdf606bdc8ddc99d5023c4c73185827aeb01"),
        hex!("9ed10348aa5cb37be35802226259ec776119bbea355597db176c66a0f94aa183"),
    ];
    const MESSAGE_HASH: [u8; 32] =
        hex!("18f224412c876d8efb2a3fa670837b5ad1347120363c2b310653f610d382729b");
    const K: [u8; 32] = hex!("d51e13c68bf56155a83e50fd9bc840e2a1847fb9b49cd206a577ecd1cd15e285");

    fn to_address(pubkey: PublicKey) -> [u8; 20] {
        let uncompressed = pubkey.as_affine().to_encoded_point(false);
        let digest = sha3::Keccak256::digest(&uncompressed.as_bytes()[1..]);
        digest[12..].try_into().unwrap()
    }

    async fn verify_sig(
        i: u8,
        pubkey_x: [u8; 32],
        pubkey_y_parity: u8,
        signature: [u8; 32],
        message_hash: [u8; 32],
        nonce_times_generator_address: [u8; 20],
    ) -> Result<bool> {
        let config = rosetta_config_ethereum::config("dev")?;

        let label = format!("verify-sig-{}", i);
        let env = Env::new(&label, config.clone()).await?;
        let faucet = 100 * u128::pow(10, config.currency_decimals);
        let wallet = env.ephemeral_wallet()?;
        wallet.faucet(faucet).await?;

        let bytes = hex::decode(include_str!("../sol/SchnorrSECP256K1.bin").trim())?;
        let response = wallet.eth_deploy_contract(bytes).await?;
        let receipt = wallet.eth_transaction_receipt(&response.hash).await?;
        let contract_address = receipt.result["contractAddress"].as_str().unwrap();

        let response = wallet
            .eth_view_call(
                contract_address,
                "function verifySignature(uint256,uint8,uint256,uint256,address) returns (bool)",
                &[
                    hex::encode(pubkey_x),
                    hex::encode([pubkey_y_parity]),
                    hex::encode(signature),
                    hex::encode(message_hash),
                    hex::encode(nonce_times_generator_address),
                ],
            )
            .await?;
        let result: Vec<String> = serde_json::from_value(response.result)?;
        Ok(result[0] == "true")
    }

    #[tokio::test]
    async fn test_verify_sig() -> Result<()> {
        let secret_key = SecretKey::from_bytes(&SECRET_KEY.into())?;
        let public_key = secret_key.public_key();
        let pubkey_x: [u8; 32] = public_key.as_affine().x().into();
        assert_eq!(pubkey_x, PUBLIC_KEY[0]);
        let pubkey_y_parity = public_key.as_affine().y_is_odd().unwrap_u8();
        let k = NonZeroScalar::from_repr(K.into()).unwrap();
        let k_times_g = AffinePoint::from(AffinePoint::GENERATOR * *k);
        let address = to_address(PublicKey::from_affine(k_times_g)?);
        let mut e_hasher = sha3::Keccak256::new();
        e_hasher.update(pubkey_x);
        e_hasher.update([pubkey_y_parity]);
        e_hasher.update(MESSAGE_HASH);
        e_hasher.update(address);
        let e = NonZeroScalar::from_repr(e_hasher.finalize()).unwrap();
        let s = k.sub(&e.mul(&secret_key.to_nonzero_scalar())).to_bytes();
        let result = verify_sig(
            0,
            pubkey_x,
            pubkey_y_parity,
            s.into(),
            MESSAGE_HASH,
            address,
        )
        .await?;
        assert!(result);
        Ok(())
    }
}
