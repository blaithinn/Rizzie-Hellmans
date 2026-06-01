const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });

const { ethers } = require('ethers');
const contractJson = require('../../docs/blockchain/contract.json');

const { SEPOLIA_RPC_URL, SERVER_WALLET_PRIVATE_KEY, CONTRACT_ADDRESS } = process.env;

let contract;

if (SEPOLIA_RPC_URL && SERVER_WALLET_PRIVATE_KEY && CONTRACT_ADDRESS) {
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(SERVER_WALLET_PRIVATE_KEY, provider);
  contract = new ethers.Contract(CONTRACT_ADDRESS, contractJson.abi, wallet);
}

async function writeHashToChain(enc, ciphertext) {
  if (!contract) {
    console.error('blockchain: missing env vars, skipping chain write');
    return null;
  }
  try {
    const encBytes = Buffer.from(enc, 'base64');
    const ciphertextBytes = Buffer.from(ciphertext, 'base64');
    const combined = Buffer.concat([encBytes, ciphertextBytes]);
    const hash = ethers.keccak256(combined);

    const tx = await contract.storeHash(hash);
    await tx.wait(1);
    return tx.hash;
  } catch (err) {
    console.error('blockchain: writeHashToChain failed:', err);
    return null;
  }
}

module.exports = { writeHashToChain };
