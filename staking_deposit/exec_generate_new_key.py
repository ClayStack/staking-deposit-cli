from staking_deposit.cli.generate_new_keystore import generate_keys

if __name__ == "__main__":
    generate_keys(mnemonic_password='12345678', validator_start_index=0, num_validators=1, chain='goerli',
                  keystore_password='1234567890', eth1_withdrawal_address='0x80a1e599327f341d89075bD502ED0b6EbBD84ae2')
