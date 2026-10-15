#pragma once
// Template. Copy this file to secrets.h (same folder) and put your wallet's
// keys there. secrets.h is listed in .gitignore and never goes into git.
// Never publish a file or a firmware image with real keys.
//
// A wallet with the CryptoNote key hierarchy (regular Monero seed / polyseed):
// these two keys are enough for legacy outputs, new Carrot outputs and FCMP++
// signing (SA/L). Such a wallet has no separate Carrot keys (k_ps, k_gi, s_vb,
// s_ga): those exist only in wallets with the new Carrot hierarchy, which
// monero-wallet-gui on this branch does not create yet.

// Required: private keys, 64 hex characters each
// (monero-wallet-gui: Settings -> Wallet -> Show seed & keys).
#define SPEND_SECRET_KEY_HEX ""
#define VIEW_SECRET_KEY_HEX  ""

// Optional: the wallet's public keys (same page). If set, the device checks
// them against the private keys at startup and refuses to work on a mismatch,
// which catches typos. Leave empty strings to skip the check.
#define SPEND_PUBLIC_KEY_HEX ""
#define VIEW_PUBLIC_KEY_HEX  ""

// Network the device reports to the PC program (INFO): 0 mainnet,
// 1 testnet (daemon RPC port 28081), 2 stagenet. Does not affect signing.
#define WALLET_NETWORK 1

// Wallet name shown by the PC program (up to 31 characters).
#define WALLET_NAME "MoneroCarrot"
