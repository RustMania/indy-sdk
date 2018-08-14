#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate named_type_derive;


#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde_json;



extern crate byteorder;
extern crate indy;
extern crate indy_crypto;
extern crate uuid;
extern crate named_type;
extern crate rmp_serde;
extern crate rust_base58;
extern crate time;
extern crate serde;

// Workaround to share some utils code based on indy sdk types between tests and indy sdk
use indy::api as api;

#[macro_use]
mod utils;

use utils::wallet::WalletUtils;
use utils::anoncreds::AnoncredsUtils;
//use utils::blob_storage::BlobStorageUtils;
use utils::anoncreds::{COMMON_MASTER_SECRET, CREDENTIAL1_ID, CREDENTIAL2_ID, CREDENTIAL3_ID, ANONCREDS_WALLET_CONFIG};
use utils::test::TestUtils;

//use indy::api::ErrorCode;
//use utils::inmem_wallet::InmemWallet;
use utils::constants::*;

use utils::domain::anoncreds::schema::Schema;
use utils::domain::anoncreds::credential_definition::CredentialDefinition;
use utils::domain::anoncreds::revocation_registry_definition::RevocationRegistryDefinition;
use utils::domain::anoncreds::credential::CredentialInfo;
//use utils::domain::anoncreds::credential_for_proof_request::{CredentialsForProofRequest, RequestedCredential};
use utils::domain::anoncreds::proof::Proof;
use utils::domain::anoncreds::revocation_state::RevocationState;
use utils::domain::anoncreds::revocation_registry::RevocationRegistry;

//use std::collections::HashSet;


mod demos {


    use super::*;


    #[cfg(feature = "revocation_tests")]
    #[test]
    fn anoncreds_works_for_revocation_proof_for_issuance_and_proving_three_credential() {
        TestUtils::cleanup_storage();

        // Issuer creates wallet, gets wallet handle
        let issuer_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

        // Prover1 creates wallet, gets wallet handle
        let prover1_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

        // Prover2 creates wallet, gets wallet handle
        let prover2_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

        // Prover3 creates wallet, gets wallet handle
        let prover3_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

        //3 Issuer creates Schema, Credential Definition and Revocation Registry
        let (schema_id, schema_json,
            cred_def_id, cred_def_json,
            rev_reg_id, revoc_reg_def_json, _,
            blob_storage_reader_handle) = AnoncredsUtils::multi_steps_issuer_revocation_preparation(issuer_wallet_handle,
                                                                                                    ISSUER_DID,
                                                                                                    GVT_SCHEMA_NAME,
                                                                                                    GVT_SCHEMA_ATTRIBUTES,
                                                                                                    r#"{"max_cred_num":5, "issuance_type":"ISSUANCE_ON_DEMAND"}"#);

        // ISSUANCE CREDENTIAL FOR PROVER1

        // Prover1 creates Master Secret
        let prover1_master_secret_id = "prover1_master_secret";
        AnoncredsUtils::prover_create_master_secret(prover1_wallet_handle, prover1_master_secret_id).unwrap();

        let (prover1_cred_rev_id, revoc_reg_delta1_json) = AnoncredsUtils::multi_steps_create_revocation_credential(
            prover1_master_secret_id,
            prover1_wallet_handle,
            issuer_wallet_handle,
            CREDENTIAL1_ID,
            &AnoncredsUtils::gvt_credential_values_json(),
            &cred_def_id,
            &cred_def_json,
            &rev_reg_id,
            &revoc_reg_def_json,
            blob_storage_reader_handle,
        );
        let revoc_reg_delta1_json = revoc_reg_delta1_json.unwrap();
        println!("revoc_reg_delta1_json {}",revoc_reg_delta1_json);

        // ISSUANCE CREDENTIAL FOR PROVER2
        // Prover2 creates Master Secret
        let prover2_master_secret_id = "prover2_master_secret";
        AnoncredsUtils::prover_create_master_secret(prover2_wallet_handle, prover2_master_secret_id).unwrap();

        let (prover2_cred_rev_id, revoc_reg_delta2_json) = AnoncredsUtils::multi_steps_create_revocation_credential(
            prover2_master_secret_id,
            prover2_wallet_handle,
            issuer_wallet_handle,
            CREDENTIAL2_ID,
            &AnoncredsUtils::gvt2_credential_values_json(),
            &cred_def_id,
            &cred_def_json,
            &rev_reg_id,
            &revoc_reg_def_json,
            blob_storage_reader_handle,
        );
        let revoc_reg_delta2_json = revoc_reg_delta2_json.unwrap();

        println!("revoc_reg_delta2_json {}",revoc_reg_delta2_json);

        // Issuer merge Revocation Registry Deltas
        let revoc_reg_delta_json = AnoncredsUtils::issuer_merge_revocation_registry_deltas(&revoc_reg_delta1_json,
                                                                                           &revoc_reg_delta2_json).unwrap();
        println!("revoc_reg_delta_json {}",revoc_reg_delta_json);

        //ISSUANCE CREDENTIAL FOR PROVER3
        // Prover3 creates Master Secret
        let prover3_master_secret_id = "prover3_master_secret";
        AnoncredsUtils::prover_create_master_secret(prover3_wallet_handle, prover3_master_secret_id).unwrap();

        let (prover3_cred_rev_id, revoc_reg_delta3_json) = AnoncredsUtils::multi_steps_create_revocation_credential(
            prover3_master_secret_id,
            prover3_wallet_handle,
            issuer_wallet_handle,
            CREDENTIAL3_ID,
            &AnoncredsUtils::gvt3_credential_values_json(),
            &cred_def_id,
            &cred_def_json,
            &rev_reg_id,
            &revoc_reg_def_json,
            blob_storage_reader_handle,
        );
        let revoc_reg_delta3_json = revoc_reg_delta3_json.unwrap();

        // Issuer merge Revocation Registry Deltas
        let revoc_reg_delta_json = AnoncredsUtils::issuer_merge_revocation_registry_deltas(&revoc_reg_delta_json, &revoc_reg_delta3_json).unwrap();

        //PROVER1 PROVING REQUEST
        let proof_request = json!({
           "nonce":"123432421212",
           "name":"proof_req_1",
           "version":"0.1",
           "requested_attributes": json!({
               "attr1_referent": json!({
                   "name":"name"
               })
           }),
           "requested_predicates": json!({
               "predicate1_referent": json!({ "name":"age", "p_type":">=", "p_value":18 })
           }),
           "non_revoked": json!({ "from":80, "to":100 })
        }).to_string();

        // Prover1 gets Credentials for Proof Request
        let prover1_credentials_json = AnoncredsUtils::prover_get_credentials_for_proof_req(prover1_wallet_handle, &proof_request).unwrap();
        let prover1_credential = AnoncredsUtils::get_credential_for_attr_referent(&prover1_credentials_json, "attr1_referent");

        // Prover1 creates RevocationState
        let timestamp = 80;
        let prover1_rev_state_json = AnoncredsUtils::create_revocation_state(blob_storage_reader_handle,
                                                                             &revoc_reg_def_json,
                                                                             &revoc_reg_delta_json,
                                                                             timestamp,
                                                                             &prover1_cred_rev_id).unwrap();

        println!("rev_delta {}\nrev_state {}",revoc_reg_delta_json,prover1_rev_state_json);

        // Prover1 creates Proof
        let requested_credentials_json = json!({
             "self_attested_attributes": json!({}),
             "requested_attributes": json!({
                "attr1_referent": json!({ "cred_id": prover1_credential.referent, "timestamp": timestamp, "revealed":true })
             }),
             "requested_predicates": json!({
                "predicate1_referent": json!({ "cred_id": prover1_credential.referent, "timestamp": timestamp })
             })
        }).to_string();

        let schemas_json = json!({
            schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()
        }).to_string();

        let credential_defs_json = json!({
            cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()
        }).to_string();

        let rev_states_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationState>(&prover1_rev_state_json).unwrap()
            })
        }).to_string();

        let proof1_json = AnoncredsUtils::prover_create_proof(prover1_wallet_handle,
                                                              &proof_request,
                                                              &requested_credentials_json,
                                                              prover1_master_secret_id,
                                                              &schemas_json,
                                                              &credential_defs_json,
                                                              &rev_states_json).unwrap();

        // Verifier verifies proof from Prover1
        let proof: Proof = serde_json::from_str(&proof1_json).unwrap();
        assert_eq!("Alex", proof.requested_proof.revealed_attrs.get("attr1_referent").unwrap().raw);

        let rev_reg_defs_json = json!({
            rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
        }).to_string();

        let rev_regs_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta_json).unwrap()
            })
        }).to_string();



        let valid = AnoncredsUtils::verifier_verify_proof(&proof_request,
                                                          &proof1_json,
                                                          &schemas_json,
                                                          &credential_defs_json,
                                                          &rev_reg_defs_json,
                                                          &rev_regs_json).unwrap();
        assert!(valid);
        println!("prover1 verified");

        // Issuer revokes the credential issued for Prover2
        let revoc_reg_delta4_json = AnoncredsUtils::issuer_revoke_credential(issuer_wallet_handle,
                                                                            blob_storage_reader_handle,
                                                                            &rev_reg_id,
                                                                            &prover2_cred_rev_id).unwrap();
        println!("revoc_reg_delta4_json {}",revoc_reg_delta4_json);

        // Issuer merge Revocation Registry Deltas
        let revoc_reg_delta_json = AnoncredsUtils::issuer_merge_revocation_registry_deltas(&revoc_reg_delta_json, &revoc_reg_delta4_json).unwrap();
        println!("revoc_reg_delta_json {}",revoc_reg_delta_json);

        //PROVER2 PROVING REQUEST, and this is supposed to fail

        // Prover2 gets Credentials for Proof Request
        let prover2_credentials_json = AnoncredsUtils::prover_get_credentials_for_proof_req(prover2_wallet_handle, &proof_request).unwrap();
        let prover2_credential = AnoncredsUtils::get_credential_for_attr_referent(&prover2_credentials_json, "attr1_referent");

        // Prover2 creates RevocationState
        let timestamp = 90;
        let prover2_rev_state_json = AnoncredsUtils::create_revocation_state(blob_storage_reader_handle,
                                                                             &revoc_reg_def_json,
                                                                             &revoc_reg_delta_json,
                                                                             timestamp,
                                                                             &prover2_cred_rev_id).unwrap();

        // Prover2 creates Proof
        let requested_credentials_json = json!({
             "self_attested_attributes": json!({}),
             "requested_attributes": json!({
                "attr1_referent": json!({ "cred_id": prover2_credential.referent, "timestamp": timestamp, "revealed":true })
             }),
             "requested_predicates": json!({
                "predicate1_referent": json!({ "cred_id": prover2_credential.referent, "timestamp": timestamp })
             })
        }).to_string();

        let schemas_json = json!({
            schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()
        }).to_string();

        let credential_defs_json = json!({
            cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()
        }).to_string();

        let rev_states_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationState>(&prover2_rev_state_json).unwrap()
            })
        }).to_string();

        let proof2_json = AnoncredsUtils::prover_create_proof(prover2_wallet_handle,
                                                              &proof_request,
                                                              &requested_credentials_json,
                                                              prover2_master_secret_id,
                                                              &schemas_json,
                                                              &credential_defs_json,
                                                              &rev_states_json).unwrap();

        // Verifier verifies proof from Prover2
        let proof: Proof = serde_json::from_str(&proof2_json).unwrap();
        assert_eq!("Alexander", proof.requested_proof.revealed_attrs.get("attr1_referent").unwrap().raw);

        let rev_reg_defs_json = json!({
            rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
        }).to_string();

        let rev_regs_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta_json).unwrap()
            })
        }).to_string();

        let valid = AnoncredsUtils::verifier_verify_proof(&proof_request,
                                                          &proof2_json,
                                                          &schemas_json,
                                                          &credential_defs_json,
                                                          &rev_reg_defs_json,
                                                          &rev_regs_json).unwrap();
        assert!(!valid);
        println!("prover2 denied");



        // PROVING REQUEST

        // Prover3 gets Credentials for Proof Request
        let prover3_credentials_json = AnoncredsUtils::prover_get_credentials_for_proof_req(prover3_wallet_handle, &proof_request).unwrap();
        let prover3_credential = AnoncredsUtils::get_credential_for_attr_referent(&prover3_credentials_json, "attr1_referent");

        // Prover3 creates RevocationState
        let timestamp = 100;
        let prover3_rev_state_json = AnoncredsUtils::create_revocation_state(blob_storage_reader_handle,
                                                                             &revoc_reg_def_json,
                                                                             &revoc_reg_delta_json,
                                                                             timestamp,
                                                                             &prover3_cred_rev_id).unwrap();

        println!("rev_delta {}\nrev_state {}",revoc_reg_delta_json,prover3_rev_state_json);


        // Prover3 creates Proof
        let requested_credentials_json = json!({
             "self_attested_attributes": json!({}),
             "requested_attributes": json!({
                "attr1_referent": json!({ "cred_id": prover3_credential.referent, "timestamp": timestamp, "revealed":true })
             }),
             "requested_predicates": json!({
                "predicate1_referent": json!({ "cred_id": prover3_credential.referent, "timestamp": timestamp })
             })
        }).to_string();

        let schemas_json = json!({
            schema_id.clone(): serde_json::from_str::<Schema>(&schema_json).unwrap()
        }).to_string();

        let credential_defs_json = json!({
            cred_def_id.clone(): serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()
        }).to_string();

        let rev_states_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationState>(&prover3_rev_state_json).unwrap()
            })
        }).to_string();

        let proof3_json = AnoncredsUtils::prover_create_proof(prover3_wallet_handle,
                                                              &proof_request,
                                                              &requested_credentials_json,
                                                              prover3_master_secret_id,
                                                              &schemas_json,
                                                              &credential_defs_json,
                                                              &rev_states_json).unwrap();

        // Verifier verifies proof from Prover2
        let proof: Proof = serde_json::from_str(&proof3_json).unwrap();
        assert_eq!("Artem", proof.requested_proof.revealed_attrs.get("attr1_referent").unwrap().raw);

        let rev_reg_defs_json = json!({
            rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
        }).to_string();

        let rev_regs_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta_json).unwrap()
            })
        }).to_string();

        let valid = AnoncredsUtils::verifier_verify_proof(&proof_request,
                                                          &proof3_json,
                                                          &schemas_json,
                                                          &credential_defs_json,
                                                          &rev_reg_defs_json,
                                                          &rev_regs_json).unwrap();
        assert!(valid);
        println!("prover3 verified");

        WalletUtils::close_wallet(issuer_wallet_handle).unwrap();
        WalletUtils::close_wallet(prover1_wallet_handle).unwrap();
        WalletUtils::close_wallet(prover2_wallet_handle).unwrap();
        WalletUtils::close_wallet(prover3_wallet_handle).unwrap();

        TestUtils::cleanup_storage();
    }

#[cfg(feature = "disabled")]
#[test]
fn anoncreds_works_for_issuance_by_default_revocation_strategy_revoke_credential() {


    TestUtils::cleanup_storage();

    //1. Issuer creates wallet, gets wallet handle
    let issuer_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

    //2. Prover creates wallet, gets wallet handle
    let prover_wallet_handle = WalletUtils::create_and_open_default_wallet().unwrap();

    //3 Issuer creates Schema, Credential Definition and Revocation Registry
    let (schema_id, schema_json,
        cred_def_id, cred_def_json,
        rev_reg_id, revoc_reg_def_json, rev_reg_entry_json,
        blob_storage_reader_handle) = AnoncredsUtils::multi_steps_issuer_revocation_preparation(issuer_wallet_handle,
                                                                                                ISSUER_DID,
                                                                                                GVT_SCHEMA_NAME,
                                                                                                GVT_SCHEMA_ATTRIBUTES,
                                                                                                &AnoncredsUtils::issuance_by_default_rev_reg_config());
    //4. Prover creates Master Secret
    AnoncredsUtils::prover_create_master_secret(prover_wallet_handle, COMMON_MASTER_SECRET).unwrap();

    //5. Issuance Credential for Prover
    let (cred_rev_id, _) = AnoncredsUtils::multi_steps_create_revocation_credential(
        COMMON_MASTER_SECRET,
        prover_wallet_handle,
        issuer_wallet_handle,
        CREDENTIAL1_ID,
        &AnoncredsUtils::gvt_credential_values_json(),
        &cred_def_id,
        &cred_def_json,
        &rev_reg_id,
        &revoc_reg_def_json,
        blob_storage_reader_handle,
    );

    println!("rev_reg_id {}\nrevoc_reg_def_json {}\nrev_reg_entry_json {}",rev_reg_id,revoc_reg_def_json,rev_reg_entry_json);


    let stored_credential =
        AnoncredsUtils::prover_get_credential(prover_wallet_handle,CREDENTIAL1_ID);

    let v: CredentialInfo = serde_json::from_str(stored_credential.unwrap().as_str()).unwrap();

    println!("rev_reg_id {}",v.rev_reg_id.unwrap());

    //6. Prover gets Credentials for Proof Request
    let proof_request = json!({
           "nonce":"123432421212",
           "name":"proof_req_1",
           "version":"0.1",
           "requested_attributes": json!({
               "attr1_referent": json!({
                   "name":"name"
               })
           }),
           "requested_predicates": json!({
               "predicate1_referent": json!({ "name":"age", "p_type":">=", "p_value":18 })
           }),
           "non_revoked": json!({ "from":80, "to":100 })
        }).to_string();

    let credentials_json = AnoncredsUtils::prover_get_credentials_for_proof_req(prover_wallet_handle, &proof_request).unwrap();
    let credential = AnoncredsUtils::get_credential_for_attr_referent(&credentials_json, "attr1_referent");


    println!("credential found {:?}",credential);

    //7. Prover creates RevocationState
    let timestamp = 100;
    let rev_state_json = AnoncredsUtils::create_revocation_state(blob_storage_reader_handle,
                                                                 &revoc_reg_def_json,
                                                                 &rev_reg_entry_json,
                                                                 timestamp,
                                                                 &cred_rev_id).unwrap();

    println!("revocation state before the revocation {}",rev_state_json);

    //8. Prover creates Proof
    let requested_credentials_json = json!({
             "self_attested_attributes": json!({}),
             "requested_attributes": json!({
                "attr1_referent": json!({ "cred_id": credential.referent, "timestamp":timestamp, "revealed":true })
             }),
             "requested_predicates": json!({
                "predicate1_referent": json!({ "cred_id": credential.referent, "timestamp":timestamp })
             })
        }).to_string();

    let schemas_json = json!({
            schema_id: serde_json::from_str::<Schema>(&schema_json).unwrap()
        }).to_string();

    let credential_defs_json = json!({
            cred_def_id: serde_json::from_str::<CredentialDefinition>(&cred_def_json).unwrap()
        }).to_string();

    let rev_states_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationState>(&rev_state_json).unwrap()
            })
        }).to_string();

    let proof_json = AnoncredsUtils::prover_create_proof(prover_wallet_handle,
                                                         &proof_request,
                                                         &requested_credentials_json,
                                                         COMMON_MASTER_SECRET,
                                                         &schemas_json,
                                                         &credential_defs_json,
                                                         &rev_states_json).unwrap();
    println!("Proof {}", proof_json);


    //9. Verifier verifies proof before it will be revoked
    let rev_reg_defs_json = json!({
            rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
        }).to_string();

    let rev_regs_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationRegistry>(&rev_reg_entry_json).unwrap()
            })
        }).to_string();

    let valid = AnoncredsUtils::verifier_verify_proof(&proof_request,
                                                      &proof_json,
                                                      &schemas_json,
                                                      &credential_defs_json,
                                                      &rev_reg_defs_json,
                                                      &rev_regs_json).unwrap();
    assert!(valid);

    //10. Issuer revokes credential
    let revoc_reg_delta_json = AnoncredsUtils::issuer_revoke_credential(issuer_wallet_handle,
                                                                        blob_storage_reader_handle,
                                                                        &rev_reg_id,
                                                                        &cred_rev_id).unwrap();



    println!("revocation reg delta {}",rev_reg_delta_json);

    //11. Prover creates RevocationState after the revocation
    let timestamp = 200;
    let new_rev_state_json = AnoncredsUtils::create_revocation_state(blob_storage_reader_handle,
                                                                 &revoc_reg_def_json,
                                                                 &revoc_reg_delta_json,
                                                                 timestamp,
                                                                 &cred_rev_id).unwrap();

    println!("revocation state after the revocation {}",new_rev_state_json);
    println!("revocation state is same {}",new_rev_state_json == rev_state_json);

    //12, Prover creates new revocation state based on updated revocation state
    let new_rev_states_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationState>(&new_rev_state_json).unwrap()
            })
        }).to_string();

    let proof_after_revocation_json = AnoncredsUtils::prover_create_proof(prover_wallet_handle,
                                                                          &proof_request,
                                                                          &requested_credentials_json,
                                                                          COMMON_MASTER_SECRET,
                                                                          &schemas_json,
                                                                          &credential_defs_json,
                                                                          &new_rev_states_json).unwrap();


    println!("Proof after revocation {}", proof_after_revocation_json);
    println!("proof is same {}",proof_after_revocation_json == proof_json);

    let rev_reg_defs_json = json!({
            rev_reg_id.clone(): serde_json::from_str::<RevocationRegistryDefinition>(&revoc_reg_def_json).unwrap()
        }).to_string();

    let rev_regs_json = json!({
            rev_reg_id.clone(): json!({
                timestamp.to_string(): serde_json::from_str::<RevocationRegistry>(&revoc_reg_delta_json).unwrap()
            })
        }).to_string();



    //11. Verifier verifies proof after that was revoked
    let valid = AnoncredsUtils::verifier_verify_proof(&proof_request,
                                                      &proof_after_revocation_json,
                                                      &schemas_json,
                                                      &credential_defs_json,
                                                      &rev_reg_defs_json,
                                                      &rev_regs_json).unwrap();
    assert!(!valid);

    WalletUtils::close_wallet(issuer_wallet_handle).unwrap();
    WalletUtils::close_wallet(prover_wallet_handle).unwrap();

    TestUtils::cleanup_storage();
}


}