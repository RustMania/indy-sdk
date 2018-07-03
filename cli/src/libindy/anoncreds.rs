use super::{ErrorCode,IndyHandle};


use libc::c_char;
use std::ffi::CString;


pub struct Anoncreds {}



impl Anoncreds {

    pub fn create_schema(issuer_did: &str, schema_name : &str, schema_version: &str, schema_attrs: &str) -> Result<(String,String),ErrorCode>
    {
        let (receiver, command_handle, cb) = super::callbacks::_closure_to_cb_ec_string_string();

        let did = CString::new(issuer_did).unwrap();
        let name = CString::new(schema_name).unwrap();
        let version = CString::new(schema_version).unwrap();
        let attrs = CString::new(schema_attrs).unwrap();

        let err = unsafe {
            indy_issuer_create_schema(command_handle, did.as_ptr(), name.as_ptr(), version.as_ptr(), attrs.as_ptr(), cb)
        };
        super::results::result_to_string_string(err, receiver)
    }


    pub fn create_credential_def(wallet: IndyHandle, issuer_did: &str, schema_json: &str,
                                tag: &str, signature_type: &str, config_json : &str) ->  Result<(String,String),ErrorCode>
    {
        let (receiver, command_handle, cb) = super::callbacks::_closure_to_cb_ec_string_string();

        let did = CString::new(issuer_did).unwrap();
        let schema = CString::new(schema_json).unwrap();
        let tag = CString::new(tag).unwrap();
        let signature_t = CString::new(signature_type).unwrap();
        let config = CString::new(config_json).unwrap();

        let err = unsafe {
            indy_issuer_create_and_store_credential_def(command_handle, wallet, did.as_ptr(),
                                                        schema.as_ptr(), tag.as_ptr(), signature_t.as_ptr(),config.as_ptr(),cb)
        };

        super::results::result_to_string_string(err, receiver)
    }

    pub fn create_credential_offer(wallet: IndyHandle, cred_def_id : &str) -> Result<String, ErrorCode>
    {

        let (receiver, command_handle, cb ) = super::callbacks::_closure_to_cb_ec_string();

        let cred_def_id = CString::new(cred_def_id).unwrap();

        let err = unsafe {
            indy_issuer_create_credential_offer(command_handle,wallet,cred_def_id.as_ptr(),cb)
        };

        super::results::result_to_string(err, receiver)
    }

    pub fn create_master_secret(wallet: IndyHandle, master_secret_id : &str) -> Result<String, ErrorCode>
    {

        let (receiver, command_handle, cb ) = super::callbacks::_closure_to_cb_ec_string();

        let ms_id = CString::new(master_secret_id).unwrap();

        let err = unsafe {
            indy_prover_create_master_secret(command_handle,wallet,ms_id.as_ptr(),cb)
        };

        super::results::result_to_string(err, receiver)
    }


    pub fn create_credential_request(wallet: IndyHandle, prover_did: &str, cred_offer: &str, cred_def: &str, master_secret_id: &str) -> Result<(String,String),ErrorCode>
    {
        let (receiver, command_handle, cb) = super::callbacks::_closure_to_cb_ec_string_string();


        let prover_did = CString::new(prover_did).unwrap();
        let cred_offer = CString::new(cred_offer).unwrap();
        let cred_def = CString::new(cred_def).unwrap();
        let master_secret_id = CString::new(master_secret_id).unwrap();


        let err = unsafe {
            indy_prover_create_credential_req(command_handle,wallet,prover_did.as_ptr(),cred_offer.as_ptr(),
                                              cred_def.as_ptr(),master_secret_id.as_ptr(),cb)
        };

        super::results::result_to_string_string(err,receiver)

    }


    pub fn create_credential(wallet: IndyHandle, cred_offer: &str, cred_req: &str, cred_values: &str) -> Result<(String,String,String), ErrorCode>
    {
        let (receiver, command_handle, cb )
            = super::callbacks::_closure_to_cb_ec_string_string_string();

        let offer = CString::new(cred_offer).unwrap();
        let request = CString::new(cred_req).unwrap();
        let values = CString::new(cred_values).unwrap();

        let err = unsafe {
            indy_issuer_create_credential(command_handle,wallet, offer.as_ptr(),request.as_ptr(),values.as_ptr(),
            0 as *const i8,0i32,cb)
        };

        super::results::result_to_string_string_string(err,receiver)
    }
}



extern {
    #[no_mangle]
    pub fn indy_issuer_create_schema(command_handle: i32,
                                     issuer_did: *const c_char,
                                     name: *const c_char,
                                     version: *const c_char,
                                     attrs: *const c_char,
                                     cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                          schema_id: *const c_char, schema_json: *const c_char)>) -> ErrorCode;


    #[no_mangle]
    pub fn indy_issuer_create_and_store_credential_def(command_handle: i32,
                                                              wallet_handle: i32,
                                                              issuer_did: *const c_char,
                                                              schema_json: *const c_char,
                                                              tag: *const c_char,
                                                              signature_type: *const c_char,
                                                              config_json: *const c_char,
                                                              cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                                                   cred_def_id: *const c_char,
                                                                                   cred_def_json: *const c_char)>) -> ErrorCode;


    #[no_mangle]
    pub fn indy_issuer_create_credential_offer(command_handle: i32,
                                               wallet_handle: i32,
                                               cred_def_id: *const c_char,
                                               cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                                    cred_offer_json: *const c_char)>) -> ErrorCode;


    #[no_mangle]
    pub fn indy_prover_create_master_secret(command_handle: i32,
                                                   wallet_handle: i32,
                                                   master_secret_id: *const c_char,
                                                   cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                                        out_master_secret_id: *const c_char)>) -> ErrorCode;



    #[no_mangle]
    pub fn indy_prover_create_credential_req(command_handle: i32,
                                                    wallet_handle: i32,
                                                    prover_did: *const c_char,
                                                    cred_offer_json: *const c_char,
                                                    cred_def_json: *const c_char,
                                                    master_secret_id: *const c_char,
                                                    cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                                         cred_req_json: *const c_char,
                                                                         cred_req_metadata_json: *const c_char)>) -> ErrorCode;


    #[no_mangle]
    pub fn indy_issuer_create_credential(command_handle: i32,
                                                wallet_handle: i32,
                                                cred_offer_json: *const c_char,
                                                cred_req_json: *const c_char,
                                                cred_values_json: *const c_char,
                                                rev_reg_id: *const c_char,
                                                blob_storage_reader_handle: i32,
                                                cb: Option<extern fn(xcommand_handle: i32, err: ErrorCode,
                                                                     cred_json: *const c_char,
                                                                     cred_revoc_id: *const c_char,
                                                                     revoc_reg_delta_json: *const c_char)>) -> ErrorCode;



}