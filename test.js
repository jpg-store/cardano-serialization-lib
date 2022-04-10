const S = require("./rust/pkg");

const input = S.TransactionInput.from_json(
  JSON.stringify({
    transaction_id:
      "e0e543aff209fe69d686592ba04e04dcee4add49defdfe887cbd9c8f7e2c2e93",
    index: "0",
  })
);

const v0 = S.Value.new(S.BigNum.from_str("0"));
const v1 = S.Value.new(S.BigNum.from_str("1"));

console.log(v0.compare(v1));
