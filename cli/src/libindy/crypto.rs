use super::IndyHandle;


use indy::ErrorCode;
use indy::future::Future;
use indy::crypto;
use indy::did;

use base64;




pub struct Crypto {}


impl Crypto {

    pub fn encrypt(their_key: &str, msg: &str) -> Result<String, ErrorCode>
    {
        //pub fn anon_crypt(recipient_vk: &str, message: &[u8]) -> Box<Future<Item=Vec<u8>, Error=ErrorCode>>
        match crypto::anon_crypt(their_key,msg.as_bytes()).wait()
            {
                Ok(ciphertext) => Ok(base64::encode(&ciphertext)),
                Err(code) => Err(code)
            }
    }


    pub fn decrypt(wallet_handle: IndyHandle, my_key: &str, base64msg: &str) ->Result<String, ErrorCode>
    {
        let vec = base64::decode(base64msg).unwrap();

        //pub fn anon_decrypt(wallet_handle: IndyHandle, recipient_vk: &str, encrypted_message: &[u8]) -> Box<Future<Item=Vec<u8>, Error=ErrorCode>> {
        match crypto::anon_decrypt(wallet_handle, my_key,&vec).wait()
            {
                Ok(cleartext) => unsafe { Ok(String::from_utf8_unchecked(cleartext)) },
                Err(code) => Err(code)
            }

    }

    pub fn encrypt_dh(wallet_handle : IndyHandle, my_key: &str, their_key: &str , msg: &str) ->Result<String,ErrorCode>
    {
        // auth_crypt(wallet_handle: IndyHandle, sender_vk: &str, recipient_vk: &str, message: &[u8]) -> Box<Future<Item=Vec<u8>, Error=ErrorCode>>
        match crypto::auth_crypt(wallet_handle, my_key, their_key, msg.as_bytes()).wait()
            {
                Ok(ciphertext) =>Ok(base64::encode(&ciphertext)),
                Err(code) => Err(code)
            }

    }

    pub fn decrypt_dh(wallet_handle: IndyHandle, my_key: &str, base64msg: &str) ->Result<(String,String), ErrorCode>
    {
        let vec = base64::decode(base64msg).unwrap();

        //fn auth_decrypt(wallet_handle: IndyHandle, recipient_vk: &str, encrypted_message: &[u8]) -> Box<Future<Item=(String, Vec<u8>), Error=ErrorCode>>

        match crypto::auth_decrypt(wallet_handle, my_key,&vec).wait()
            {
                Ok((did,cleartext)) => unsafe {  Ok( (did,String::from_utf8_unchecked(cleartext))  ) },
                Err(code) => Err(code)
            }

    }

    pub fn get_key_for_did(pool_handle: IndyHandle, wallet_handle: IndyHandle, did: &str ) -> Result<String,ErrorCode>
    {

        //fn key_for_did(pool_handle: IndyHandle, wallet_handle: IndyHandle, did: &str) -> Box<Future<Item=String, Error=ErrorCode>> {
        did::key_for_did(pool_handle,wallet_handle,did).wait()

    }

}
