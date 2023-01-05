import Signer from "./signer";
const SECRET_KEY = "!@#$%$";

const signer = new Signer(SECRET_KEY);

const email = "admin@goatnet.com";
const tokenId = 23;
const transactionId = "fff86029-52b4-4e88-bede-e31909e15709";
const contractId = "ecc6c7b1-c53a-44f1-bc3b-aa5c26a92065";

const encoded = signer.encode(
  JSON.stringify({ email, tokenId, transactionId, contractId })
);

console.log("encoded", encoded);

const contents = signer.decode(encoded);
console.log(contents);
