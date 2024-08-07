import {AlchemyProvider, Wallet, Contract, ContractFactory, TransactionRequest} from 'ethers';
import {SPHINCSPlusVerifier__factory} from "./typechain-types/factories/sphincsplus-verifier.sol"
import {SPHINCSPlus} from "./typechain-types/sphincsplus.sol"
import { randomBytes } from 'crypto';

// load .env file
require('@dotenvx/dotenvx').config()

const contractAddreess = "0xa691585C3FE0108289e0Ed32E4F2550f664dFC7D";
const privateKey = process.env.PRIVATE_KEY as string;
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const network = 'sepolia';
const provider = new AlchemyProvider(network, ALCHEMY_API_KEY);

const wallet = new Wallet(privateKey, provider);

const abi = SPHINCSPlusVerifier__factory.abi;
const bytecode = SPHINCSPlusVerifier__factory.bytecode;

const estimateGas = async () => {
    const verifier = new Contract(contractAddreess, abi, wallet);

    // const contract = await factory.deploy();
    // await contract.waitForDeployment();

    // console.log('Contract Address:', await contract.getAddress());

    const { chainId } = await provider.getNetwork();
    const { maxFeePerGas, maxPriorityFeePerGas } = await provider.getFeeData();
    const requestParams: TransactionRequest = {
        type: 2,
        // from: contractTx.from,
        maxFeePerGas,
        maxPriorityFeePerGas,
        chainId,
      };
    
    const sig: SPHINCSPlus.SPHINCS_SIGStruct = {
        R: randomBytes(32),
        SIG_FORS: {
            AUTH: [randomBytes(32)],
            SK: [randomBytes(32)]
        },
        SIG_HT: {
            AUTH: [randomBytes(32)]
        }
    };
    const pk: SPHINCSPlus.SPHINCS_PKStruct = {
        PKroot: randomBytes(32),
        PKseed: randomBytes(32),
    };
    // Estimate gas for verify method
    const gasEstimate = await verifier.verify.estimateGas(
            Buffer.from('Test message', 'utf-8'),
            sig,
            pk,
            requestParams,
        );
    console.log('Gas Estimate for verify method:', gasEstimate.toString());
};

estimateGas();