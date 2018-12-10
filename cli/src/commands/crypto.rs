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


pub mod auth_encrypt {
    use super::*;

    command!(CommandMetadata::build("authenc", "Encrypt using common secret and convert to base64")
                .add_required_param("did", "Local DID to use")
                .add_required_param("theirkey", "Remote validation key to use")
                .add_required_param("msg", "Message text")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let did = get_str_param("did", params).map_err(error_err!())?;
        let theirkey = get_str_param("theirkey", params).map_err(error_err!())?;
        let msg = get_str_param("msg", params).map_err(error_err!())?;


        let pool_handle = ensure_connected_pool_handle(&ctx)?;
        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };

        trace!(r#"Crypto::auth_encrypt try: wallet {} mykey {}, theirkey {}, msg {:?}"#, wallet_handle, did, theirkey, msg);

        let my_verkey = Crypto::get_key_for_did(pool_handle,wallet_handle,did).unwrap();

        let res = Crypto::encrypt_dh(wallet_handle, my_verkey.as_str(), theirkey, msg);

        trace!(r#"Crypto::auth_encrypt return: {:?}"#, res);

        let res = match res {
            Ok(base64msg) => Ok(println_succ!("{}\n", base64msg)),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }

}

pub mod auth_decrypt
{
    use super::*;

    command!(CommandMetadata::build("authdec", "Decrypt base64 cyphertext using common secret")
                .add_required_param("did", "Local validation key to use")
                .add_required_param("msg", "Cipher text")
                .finalize()
    );

    fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
        trace!("execute >> ctx {:?} params {:?}", ctx, params);

        let did = get_str_param("did", params).map_err(error_err!())?;
        let msg = get_str_param("msg", params).map_err(error_err!())?;


        let wallet_handle =
            match get_opened_wallet(ctx){
                Some((handle, _)) => handle,
                None => {
                    return Err(println_err!("No wallets opened"))
                }
            };


        trace!(r#"Crypto::authdec try: key {}, msg {:?}"#, did, msg);

        let pool_handle = ensure_connected_pool_handle(&ctx)?;
        let my_verkey = Crypto::get_key_for_did(pool_handle,wallet_handle,did).unwrap();

        let res = Crypto::decrypt_dh(wallet_handle, my_verkey.as_str(), msg);

        trace!(r#"Crypto::authdec return: {:?}"#, res);

        let res = match res {
            Ok((decoded_msg, their_key)) => Ok(println_succ!("{}\n\nremote key used {}\n", decoded_msg, their_key)),
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
            Ok((cred,revoc_id,revoc_delta)) => Ok(println_succ!("credential\n\n{}\n{:?} {:?}\n", cred, revoc_id, revoc_delta )),
            Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
        };

        trace!("execute << {:?}", res);
        res
    }
}

pub mod revocation  {

    use super::*;

    pub mod create_registry {
        use super::*;

        command!(CommandMetadata::build("revoc-reg", "Create revocation registry")
                 .add_required_param("did", "DID of the issuer")
                 .add_optional_param("type", "revocation definition type")
                 .add_required_param("tag", "revocation definition tag")
                 .add_required_param("cdef_id", "credential definition id")
                 //.add_("tail_config", "tail configuration (JSON)")
                .add_example("revoc-reg did=  tag= cdef_id= ")
                .finalize());

        fn execute(ctx: &CommandContext, params: &CommandParams) -> Result<(), ()> {
            trace!("execute >> ctx {:?} params {:?}", ctx, params);

            let issuer_did = get_str_param("did", params).map_err(error_err!())?;
            let revoc_def_type = get_opt_str_param("type", params).map_err(error_err!())?;
            let tag = get_str_param("tag", params).map_err(error_err!())?;
            let cred_def_id = get_str_param("cdef_id",params).map_err(error_err!())?;



            let wallet_handle =
                match get_opened_wallet(ctx) {
                    Some((handle, _)) => handle,
                    None => {
                        return Err(println_err!("No wallets opened"))
                    }
                };

            let type_ = match revoc_def_type
                {
                    Some(revoc_def_type) => revoc_def_type,
                    None => "CL_ACCUM"
                };

            //let rr_config =  "{ \"issuance_type\": \"ISSUANCE_BY_DEFAULT\" , \"max_cred_num\" : \"1000\" }";
            let rr_config = "{}";
            let tails_writer_handle = 1;

            let res = Anoncreds::create_and_store_revoc_reg(wallet_handle, issuer_did , type_, tag, cred_def_id,

                                                            rr_config,tails_writer_handle);


            let res = match res {
                Ok((rev_reg_id, revoc_reg_def_json, revoc_reg_json)) => Ok(println_succ!("registry id {}\nregistry definition {}\nregistry {}\n", rev_reg_id, revoc_reg_def_json, revoc_reg_json )),
                Err(err) => Err(println_err!("Indy SDK error occurred {:?}", err)),
            };

            trace!("execute << {:?}", res);
            res
        }
    }

}