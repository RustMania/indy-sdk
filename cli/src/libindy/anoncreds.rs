use super::IndyHandle;


use indy::future::Future;
use indy::anoncreds;
use indy::ErrorCode;


pub struct Anoncreds {}



impl Anoncreds {

    pub fn create_schema(issuer_did: &str, schema_name : &str, schema_version: &str, schema_attrs: &str) -> Result<(String,String),ErrorCode>
    {
        anoncreds::issuer_create_schema(issuer_did, schema_name, schema_version, schema_attrs).wait()
    }


    pub fn create_credential_def(wallet: IndyHandle, issuer_did: &str, schema_json: &str,tag: &str, signature_type: &str, config_json : &str) ->  Result<(String,String),ErrorCode>
    {
        anoncreds::issuer_create_and_store_credential_def( wallet, issuer_did,schema_json, tag, Some(signature_type), config_json).wait()
    }

    pub fn create_credential_offer(wallet: IndyHandle, cred_def_id : &str) -> Result<String, ErrorCode>
    {
        anoncreds::issuer_create_credential_offer(wallet,cred_def_id).wait()
    }

    pub fn create_master_secret(wallet: IndyHandle, master_secret_id : &str) -> Result<String, ErrorCode>
    {
        anoncreds::prover_create_master_secret(wallet,Some(master_secret_id)).wait()
    }


    pub fn create_credential_request(wallet: IndyHandle, prover_did: &str, cred_offer: &str, cred_def: &str, master_secret_id: &str) -> Result<(String,String),ErrorCode>
    {
        anoncreds::prover_create_credential_req(wallet,prover_did,cred_offer,cred_def,master_secret_id).wait()
    }


    pub fn create_credential(wallet: IndyHandle, cred_offer: &str, cred_req: &str, cred_values: &str) -> Result<(String,Option<String>,Option<String>), ErrorCode>
    {
        anoncreds::issuer_create_credential(wallet, cred_offer,cred_req,cred_values,None,0i32).wait()
    }


    pub fn create_and_store_revoc_reg(wallet: IndyHandle, issuer_did: &str, revoc_def_type: &str, tag: &str, cred_def_id: &str,
                                      tails_config: &str,tails_writer_handle: i32) -> Result<(String,String,String), ErrorCode>
    {
        anoncreds::issuer_create_and_store_revoc_reg(wallet, issuer_did,Some(revoc_def_type), tag, cred_def_id, tails_config, tails_writer_handle).wait()
    }
}

