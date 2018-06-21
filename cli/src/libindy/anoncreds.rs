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
}