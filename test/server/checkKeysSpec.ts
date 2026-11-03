/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import sinon from 'sinon'
import chai from 'chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { checkKeys } from '../../routes/checkKeys'
const expect = chai.expect

const leakedSeedPhrase = () => {
  const users = fs.readFileSync(path.resolve(__dirname, '../../data/static/users.yml'), 'utf8')
  return /\/juicy-nft : "([a-z ]+)"/.exec(users)?.[1] ?? ''
}

describe('checkKeys', () => {
  let res: any

  beforeEach(() => {
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    challenges.nftUnlockChallenge = { solved: false, save: () => ({ then () { } }) } as unknown as Challenge
  })

  it('should not contain a BIP-39 mnemonic or derive the wallet from one', () => {
    const source = fs.readFileSync(path.resolve(__dirname, '../../routes/checkKeys.ts'), 'utf8')

    expect(/['"`](?:[a-z]{3,8} ){11,23}[a-z]{3,8}['"`]/.test(source), 'mnemonic-like literal in routes/checkKeys.ts').to.equal(false)
    expect(source.includes(leakedSeedPhrase()), 'leaked seed phrase in routes/checkKeys.ts').to.equal(false)
    expect(source.includes('fromPhrase'), 'fromPhrase call in routes/checkKeys.ts').to.equal(false)
  })

  it('should accept the private key derived from the leaked seed phrase and solve "nftUnlockChallenge"', async () => {
    const { HDNodeWallet } = await import('ethers')
    const privateKey = HDNodeWallet.fromPhrase(leakedSeedPhrase()).privateKey

    await checkKeys()({ body: { privateKey } } as any, res)

    expect(res.status.firstCall.args[0]).to.equal(200)
    expect(res.json.firstCall.args[0].success).to.equal(true)
    expect(challenges.nftUnlockChallenge.solved).to.equal(true)
  })

  it('should recognize the public wallet address', async () => {
    await checkKeys()({ body: { privateKey: '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05' } } as any, res)

    expect(res.status.firstCall.args[0]).to.equal(401)
    expect(res.json.firstCall.args[0].message).to.equal('Looks like you entered the public address of my ethereum wallet!')
    expect(challenges.nftUnlockChallenge.solved).to.equal(false)
  })

  it('should recognize the public wallet key', async () => {
    await checkKeys()({ body: { privateKey: '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506' } } as any, res)

    expect(res.status.firstCall.args[0]).to.equal(401)
    expect(res.json.firstCall.args[0].message).to.equal('Looks like you entered the public key of my ethereum wallet!')
    expect(challenges.nftUnlockChallenge.solved).to.equal(false)
  })

  it('should reject other or missing keys as non-Ethereum private keys', async () => {
    for (const body of [{}, { privateKey: 'lalalala' }, { privateKey: ['0x5bcc'] }, { privateKey: '0x' + '0'.repeat(64) }]) {
      res.status.resetHistory()
      res.json.resetHistory()

      await checkKeys()({ body } as any, res)

      expect(res.status.firstCall.args[0]).to.equal(401)
      expect(res.json.firstCall.args[0].message).to.equal('Looks like you entered a non-Ethereum private key to access me.')
    }
    expect(challenges.nftUnlockChallenge.solved).to.equal(false)
  })
})
