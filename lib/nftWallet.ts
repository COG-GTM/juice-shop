/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

let mnemonic: Promise<string> | undefined

// Uses NFT_WALLET_MNEMONIC if set, otherwise a disposable wallet generated per server start
export async function getNftWalletMnemonic (): Promise<string> {
  mnemonic ??= (async () => {
    if (process.env.NFT_WALLET_MNEMONIC) return process.env.NFT_WALLET_MNEMONIC
    const { Mnemonic, randomBytes } = await import('ethers')
    return Mnemonic.fromEntropy(randomBytes(16)).phrase
  })()
  return await mnemonic
}
