extern crate serde;
extern crate serde_json;
extern crate indy_crypto;

use super::constants::{SCHEMA, GET_SCHEMA, HIGH_LEVEL_SCHEMA};
use super::response::GetReplyResultV1;

use self::indy_crypto::utils::json::{JsonDecodable, JsonEncodable};

use std::collections::HashSet;

#[derive(Serialize, PartialEq, Debug)]
pub struct SchemaOperation {
    #[serde(rename = "type")]
    pub _type: String,
    pub data: SchemaOperationData,
}

impl SchemaOperation {
    pub fn new(data: SchemaOperationData) -> SchemaOperation {
        SchemaOperation {
            data,
            _type: HIGH_LEVEL_SCHEMA.to_string()
        }
    }
}

impl JsonEncodable for SchemaOperation {}

#[derive(Serialize, PartialEq, Debug, Deserialize)]
pub struct SchemaOperationData {
    pub name: String,
    pub version: String,
    pub attr_names: HashSet<String>
}

impl SchemaOperationData {
    pub fn new(name: String, version: String, attr_names: HashSet<String>) -> SchemaOperationData {
        SchemaOperationData {
            name,
            version,
            attr_names
        }
    }
}

impl JsonEncodable for SchemaOperationData {}

impl<'a> JsonDecodable<'a> for SchemaOperationData {}

#[derive(Serialize, PartialEq, Debug)]
pub struct GetSchemaOperation {
    #[serde(rename = "type")]
    pub _type: String,
    pub dest: String,
    pub data: GetSchemaOperationData
}

impl GetSchemaOperation {
    pub fn new(dest: String, data: GetSchemaOperationData) -> GetSchemaOperation {
        GetSchemaOperation {
            _type: GET_SCHEMA.to_string(),
            dest,
            data
        }
    }
}

impl JsonEncodable for GetSchemaOperation {}

#[derive(Serialize, PartialEq, Debug, Deserialize)]
pub struct GetSchemaOperationData {
    pub name: String,
    pub version: String
}

impl GetSchemaOperationData {
    pub fn new(name: String, version: String) -> GetSchemaOperationData {
        GetSchemaOperationData {
            name,
            version
        }
    }
}

impl JsonEncodable for GetSchemaOperationData {}

impl<'a> JsonDecodable<'a> for GetSchemaOperationData {}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GetSchemaReplyResult {
    GetSchemaReplyResultV0(GetSchemaResultV0),
    GetSchemaReplyResultV1(GetReplyResultV1<GetSchemaResultDataV1>)
}

impl<'a> JsonDecodable<'a> for GetSchemaReplyResult {}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultV0 {
    pub seq_no: u32,
    pub data: SchemaOperationData,
    pub dest: String
}

impl<'a> JsonDecodable<'a> for GetSchemaResultV0 {}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultDataV1 {
    pub ver: String,
    pub id: String,
    pub schema_name: String,
    pub schema_version: String,
    pub value: GetSchemaResultDataValueV1
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSchemaResultDataValueV1 {
    pub attr_names: HashSet<String>
}

impl<'a> JsonDecodable<'a> for GetSchemaResultDataV1 {}
