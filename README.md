# SPHINCS+ signature verification for solidity

## CAUTION!!

This is a work in progress.

- `npm test` failes because of mussive gas usages.

## About

- `SPHINCS+` signature scheme verification logic implementation in solidity.
- Based on Golang implementation of SPHINCS+ signature scheme.
  - https://github.com/kasperdi/SPHINCSPLUS-golang

## How to use

```bash
npm install
```

```bash
npm run types
npm run compile
npm test
npm run deploy
```

## TODO

[ ] use of abi.encode(abi.encodePacked) should be considered.
