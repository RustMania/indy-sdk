use command_executor::{ Command, CommandMetadata, CommandContext,  CommandParams, CommandGroup, CommandGroupMetadata};
use commands::*;

use libindy::crypto::Crypto;
use libindy::anoncreds::Anoncreds;

pub mod group {
    use super::*;

    command_group!(CommandGroupMetadata::new("crypto", "Crypto management commands"));
}

pub mod compose_key{

    use rust_base58::{ToBase58, FromBase58};

    use super::*;

    command!(CommandMetadata::build("comp", "compose the key from its two base58 parts")
                .add_required_param("did", "First part")
                .add_required_param("ver", "Second part")
                .add_example("crypto comp did=Th7MpTaRZVRYnPiabds81Y  ver=~7TYfekw4GUagBnBVCqPjiC")
                .finalize()
    );

    fn execute (_ctx: &CommandContext, params: &CommandParams) -> Result<(), ()>
    {
        let did58 = get_str_param("did", params).map_err(error_err!())?;
        let mut ver58 = get_str_param("ver", params).map_err(error_err!())?;

        ver58 =   if ver58.starts_with("~") { &ver58[1..] } else { ver58 } ;

        let mut did = did58.from_base58().unwrap();
        let mut ver = ver58.from_base58().unwrap();

        did.append(&mut ver); // + ver.concat()

        let full_key = did.to_base58();

        Ok(println_succ!("\n{}\n", full_key))


    }
}


pub mod encrypt_dh {
    use super::*;

    command!(CommandMetadata::build("encdh", "Encrypt using DH common secret algorithm")
                .add_required_param("mykey", "Local validation key to use")
                .add_required_param("theirkey", "Remote validation key to use")
                .add_required_param("msg", "Message text")
                .add_example("crypto enc  mykey=...fullkey...   theirkey=...fullkey...    msg=...msgtext... ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let mykey = get_str_param("mykey", params).map_err(error_err!())?;
        let theirkey = get_str_param("theirkey", params).map_err(error_err!())?;
        let msg = get_str_param("msg", params).map_err(error_err!())?;

        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        trace!(r#"Crypto::encrypt_dh try: wallet {} mykey {}, theirkey {}, msg {:?}"#, wallet_handle, mykey, theirkey, msg);

        let res = Crypto::encrypt_dh(wallet_handle, mykey, theirkey, msg);

        trace!(r#"Crypto::encrypt_dh return: {:?}"#, res);

        let res = match res {
            Ok(base58msg) => Ok(println_succ!("message encrypted \n\n{}\n", base58msg)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }

}

pub mod decrypt_dh
{
    use super::*;

    command!(CommandMetadata::build("decdh", "Decrypt using DH common secret algorithm")
                .add_required_param("key", "Local validation key to use")
                .add_required_param("msg", "Cipher text")
                .add_example("crypto enc  mykey=...fullkey...   theirkey=...fullkey...    msg=...cipher... ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let key = get_str_param("key", params).map_err(error_err!())?;
        let msg = get_str_param("msg", params).map_err(error_err!())?;


        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };


        trace!(r#"Crypto::decrypt_dh try: key {}, msg {:?}"#, key, msg);

        let res = Crypto::decrypt_dh(wallet_handle, key, msg);

        trace!(r#"Crypto::decrypt_dh return: {:?}"#, res);

        let res = match res {
            Ok((decoded_msg, their_key)) => Ok(println_succ!("message decrypted \n\n{}\n\nremote key used {}\n", decoded_msg, their_key)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}

pub mod encrypt {
    use super::*;

    command!(CommandMetadata::build("enc", "Encrypt anonymously")
                .add_required_param("did", "DID to use to encrypt")
                .add_required_param("msg", "Message text")
                .add_example("crypto enc  did=VsKV7grR1BUE29mG2Fm2kX msg={ did: XXXXXXXXXXXXX ; nonce: 123456789 } ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let msg = get_str_param("msg", params).map_err(error_err!())?;
        let did = get_str_param("did", params).map_err(error_err!())?;


        let pool_handle = ensure_connected_pool_handle(&ctx)?;
        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let key = Crypto::get_key_for_did(pool_handle,wallet_handle,did).unwrap();

        trace!(r#"Crypto::encrypt try: key {}, msg {:?}"#, key, msg);

        let res = Crypto::encrypt(key.as_str(), msg);

        trace!(r#"Crypto::encrypt return: {:?}"#, res);

        let res = match res {
            Ok(base64msg) => Ok(println_succ!("message encrypted \n\n{}\n", base64msg)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }

}


pub mod decrypt{

    use super::*;

    command!(CommandMetadata::build("dec", "Decrypt anonymously")
                //.add_main_param("name", "The name of the wallet containing key")
                .add_required_param("did", "DID to use")
                .add_required_param("msg", "Cipher text")
                .add_example("crypto enc  did=VsKV7grR1BUE29mG2Fm2kX msg=... ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        //let wallet_name = get_str_param("name", params).map_err(error_err!())?;

        let did = get_str_param("did", params).map_err(error_err!())?;
        let msg = get_str_param("msg", params).map_err(error_err!())?;

        let pool_handle = ensure_connected_pool_handle(&ctx)?;
        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let key = Crypto::get_key_for_did(pool_handle,wallet_handle,did).unwrap();


        trace!(r#"Crypto::decrypt try: key {}, msg {:?}"#, key, msg);

        let res = Crypto::decrypt(wallet_handle, key.as_str(), msg);

        trace!(r#"Crypto::decrypt return: {:?}"#, res);

        let res = match res {
            Ok(decoded_msg) => Ok(println_succ!("message decrypted \n\n{}\n", decoded_msg)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }

}

pub mod create_schema{

    use super::*;

    command!(CommandMetadata::build("schema", "Create schema")
                .add_required_param("did", "DID of the issuer")
                .add_required_param("name", "Schema name")
                .add_required_param("v","Schema version")
                .add_required_param("attr","Schema attributes")
                .add_example("crypto schema  did=... name=myschema v=1 attr=\"[\\\"age\\\", \\\"sex\\\", \\\"height\\\", \\\"name\\\"]\" ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        //let wallet_name = get_str_param("name", params).map_err(error_err!())?;

        let did = get_str_param("did", params).map_err(error_err!())?;
        let name = get_str_param("name", params).map_err(error_err!())?;
        let version = get_str_param("v", params).map_err(error_err!())?;
        let attributes = get_str_param("attr", params).map_err(error_err!())?;


        let res = Anoncreds::create_schema(did,name,version,attributes);

        trace!(r#"Crypto::decrypt return: {:?}"#, res);

        let res = match res {
            Ok((schema_id,schema_json)) => Ok(println_succ!("schema {}\n\n{}\n", schema_id , schema_json)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}

pub mod create_credential_def{
    use super::*;

    command!(CommandMetadata::build("cdef", "Create credential definition")
                .add_required_param("did", "DID of the issuer")
                .add_required_param("schema", "Schema in JSON")
                .add_required_param("tag","Tag")
                .add_required_param("sigtype","Schema signature type")
                .add_required_param("cfg", "Config")
                .add_example("crypto cdef  did=... schema=\"{ ... }\"  tag=TAG sigtype=CL cfg={\"support_revocation\":true} ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        //let wallet_name = get_str_param("name", params).map_err(error_err!())?;

        let did = get_str_param("did", params).map_err(error_err!())?;
        let schema_json = get_str_param("schema", params).map_err(error_err!())?;
        let tag = get_str_param("tag", params).map_err(error_err!())?;
        let signature_type = get_str_param("sigtype", params).map_err(error_err!())?;
        let config_json = get_str_param("cfg", params).map_err(error_err!())?;


        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let res = Anoncreds::create_credential_def(wallet_handle,did,schema_json,tag,signature_type,config_json);

        trace!(r#"Crypto::decrypt return: {:?}"#, res);

        let res = match res {
            Ok((def_id,def_json)) => Ok(println_succ!("cred definition {}\n\n{}\n", def_id , def_json)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}


pub mod create_credential_offer{

    use super::*;

    command!(CommandMetadata::build("offer", "Create credential offer")
                .add_required_param("cdefid", "Credential definition id")
                .add_example("crypto offer cdefid=... ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        //let wallet_name = get_str_param("name", params).map_err(error_err!())?;

        let cdefid = get_str_param("cdefid", params).map_err(error_err!())?;

        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let res = Anoncreds::create_credential_offer(wallet_handle, cdefid);

        trace!(r#"Anoncreds::create_credential_offer return: {:?}"#, res);

        let res = match res {
            Ok(offer_json) => Ok(println_succ!("credential offer\n\n{}\n", offer_json)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}



pub mod create_master_key{

    use super::*;

    command!(CommandMetadata::build("master", "Create master secret")
                .add_required_param("id", "Master secret id")
                .add_example("crypto master id=... ")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let id = get_str_param("id", params).map_err(error_err!())?;

        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let res = Anoncreds::create_master_secret(wallet_handle, id);

        trace!(r#"Anoncreds::create_master_key return: {:?}"#, res);

        let res = match res {
            Ok(master_key_id) => Ok(println_succ!("master key id\n\n{}\n", master_key_id)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}


pub mod create_credential_request{

    use super::*;

    command!(CommandMetadata::build("request", "Create credential request")
                .add_required_param("did", "Prover DID")
                 .add_required_param("offer", "Credential offer")
                  .add_required_param("cdef", "Credential definition")
                   .add_required_param("id", "Master secret id")
                .add_example("crypto request did=... offer=... cdef=... id=...")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);


        let did = get_str_param("did", params).map_err(error_err!())?;
        let offer = get_str_param("offer", params).map_err(error_err!())?;
        let cdef = get_str_param("cdef", params).map_err(error_err!())?;
        let id = get_str_param("id", params).map_err(error_err!())?;


        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let res = Anoncreds::create_credential_request(wallet_handle, did,offer,cdef,id);

        trace!(r#"Anoncreds::create_credential_request return: {:?}"#, res);

        let res = match res {
            Ok((req,metadata)) => Ok(println_succ!("credential request\n\n{}\nmetadata\n{}\n",req, metadata )),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }


}


pub mod create_credential{

    use super::*;


    command!(CommandMetadata::build("credential", "Create credential ")
                 .add_required_param("offer", "Credential offer")
                  .add_required_param("request", "Credential request")
                   .add_required_param("values", "Credential values")
                .add_example("crypto credential offer=... request=... values=...")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);


        let request = get_str_param("request", params).map_err(error_err!())?;
        let offer = get_str_param("offer", params).map_err(error_err!())?;
        let values = get_str_param("values", params).map_err(error_err!())?;


        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        let res = Anoncreds::create_credential(wallet_handle, offer,request,values);

        trace!(r#"Anoncreds::create_credential_request return: {:?}"#, res);

        let res = match res {
            Ok((cred,revoc_id,revoc_delta)) => Ok(println_succ!("credential\n\n{}\n{} {}\n", cred, revoc_id, revoc_delta )),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }
}
