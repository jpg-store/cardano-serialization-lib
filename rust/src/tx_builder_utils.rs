use super::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use serde_json::{Map, Value as Val};
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen::JsCast;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use web_sys::{Request, RequestInit, Response};

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemerResult {
    pub result: Option<EvaluationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub EvaluationResult: HashMap<String, ExUnitResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExUnitResult {
    pub memory: u64,
    pub steps: u64,
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct Blockfrost {
    url: String,
    project_id: String,
}

#[wasm_bindgen]
impl Blockfrost {
    pub fn new(url: String, project_id: String) -> Self {
        Self {
            url: url.clone(),
            project_id: project_id.clone(),
        }
    }
    pub fn url(&self) -> String {
        self.url.clone()
    }
    pub fn project_id(&self) -> String {
        self.project_id.clone()
    }
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "emscripten"))))]
pub async fn get_ex_units(tx: Transaction, bf: &Blockfrost) -> Result<Redeemers, JsError> {
    Ok(Redeemers::new())
}

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
pub async fn get_ex_units(tx: Transaction, bf: &Blockfrost) -> Result<Redeemers, JsError> {
    if bf.url.is_empty() || bf.project_id.is_empty() {
        return Err(JsError::from_str(
            "Blockfrost not set. Can't calculate ex units",
        ));
    }

    let mut opts = RequestInit::new();
    opts.method("POST");
    let tx_hex = hex::encode(tx.to_bytes());
    opts.body(Some(&JsValue::from(tx_hex)));

    let url = &bf.url;

    let request = Request::new_with_str_and_init(&url, &opts)?;
    request.headers().set("Content-Type", "application/cbor")?;
    request.headers().set("project_id", &bf.project_id)?;

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let json = JsFuture::from(resp.json()?).await?;

    // Use serde to parse the JSON into a struct.
    let redeemer_result: RedeemerResult = json.into_serde().unwrap();

    match redeemer_result.result {
        Some(res) => {
            let mut redeemers = Redeemers::new();
            for (pointer, eu) in &res.EvaluationResult {
                let r: Vec<&str> = pointer.split(":").collect();
                let tag = match r[0] {
                    "spend" => RedeemerTag::new_spend(),
                    "mint" => RedeemerTag::new_mint(),
                    _ => return Err(JsValue::NULL),
                };
                let index = &to_bignum(r[1].parse::<u64>().unwrap());
                let ex_units = ExUnits::new(&to_bignum(eu.memory), &to_bignum(eu.steps));

                for tx_redeemer in &tx.witness_set.redeemers.clone().unwrap().0 {
                    if tx_redeemer.tag() == tag && tx_redeemer.index() == *index {
                        let updated_redeemer = Redeemer::new(
                            &tx_redeemer.tag(),
                            &tx_redeemer.index(),
                            &tx_redeemer.data(),
                            &ex_units,
                        );
                        redeemers.add(&updated_redeemer);
                    }
                }
            }

            Ok(redeemers)
        }

        None => Err(JsValue::NULL),
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScriptWitnessKind {
    NativeWitness,
    PlutusWitness,
}

#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub enum ScriptWitnessEnum {
    NativeWitness(NativeScript),
    PlutusWitness(PlutusWitness),
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct PlutusWitness {
    plutus_data: Option<PlutusData>,
    redeemer: PlutusData,
    script: Option<PlutusScript>,
}

#[wasm_bindgen]
impl PlutusWitness {
    pub fn new_plutus_v1(
        plutus_data: &PlutusData,
        redeemer: &PlutusData,
        script: PlutusScript,
    ) -> Self {
        Self {
            plutus_data: Some(plutus_data.clone()),
            redeemer: redeemer.clone(),
            script: Some(script.clone()),
        }
    }

    // Script is optional in Plutus v2, if script is supplied through reference input
    pub fn new_plutus_v2(
        plutus_data: &PlutusData,
        redeemer: &PlutusData,
        script: Option<PlutusScript>,
    ) -> Self {
        Self {
            plutus_data: Some(plutus_data.clone()),
            redeemer: redeemer.clone(),
            script: script.clone(),
        }
    }

    pub fn plutus_data(&self) -> Option<PlutusData> {
        self.plutus_data.clone()
    }
    pub fn redeemer(&self) -> PlutusData {
        self.redeemer.clone()
    }
    pub fn script(&self) -> Option<PlutusScript> {
        self.script.clone()
    }
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct ScriptWitness(ScriptWitnessEnum);

to_from_json!(ScriptWitness);

#[wasm_bindgen]
impl ScriptWitness {
    pub fn new_native_witness(native_script: &NativeScript) -> Self {
        Self(ScriptWitnessEnum::NativeWitness(native_script.clone()))
    }
    pub fn new_plutus_witness(plutus_witness: &PlutusWitness) -> Self {
        Self(ScriptWitnessEnum::PlutusWitness(plutus_witness.clone()))
    }

    pub fn kind(&self) -> ScriptWitnessKind {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(_) => ScriptWitnessKind::NativeWitness,
            ScriptWitnessEnum::PlutusWitness(_) => ScriptWitnessKind::PlutusWitness,
        }
    }

    pub fn as_native_witness(&self) -> Option<NativeScript> {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(native_script) => Some(native_script.clone()),
            _ => None,
        }
    }

    pub fn as_plutus_witness(&self) -> Option<PlutusWitness> {
        match &self.0 {
            ScriptWitnessEnum::PlutusWitness(plutus_witness) => Some(plutus_witness.clone()),
            _ => None,
        }
    }
}
