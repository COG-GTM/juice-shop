/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkKeys } from '../../routes/checkKeys'
const expect = chai.expect
chai.use(sinonChai)

describe('checkKeys', () => {
  const privateKey = '0x' + crypto.randomBytes(32).toString('hex')
  let req: any
  let res: any
  let configStub: sinon.SinonStub

  beforeEach(() => {
    const originalGet = config.get.bind(config)
    configStub = sinon.stub(config, 'get').callsFake((key: string) => key === 'challenges.nftUnlockPrivateKeyHash'
      ? crypto.createHash('sha256').update(privateKey).digest('hex')
      : originalGet(key))
    req = { body: {} }
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    challenges.nftUnlockChallenge = { solved: false, save: () => ({ then () { } }) } as unknown as Challenge
  })

  afterEach(() => {
    configStub.restore()
  })

  it('should not embed a wallet mnemonic in the route source', () => {
    const source = fs.readFileSync(path.resolve('routes/checkKeys.ts'), 'utf8')

    expect(source).to.not.match(/fromPhrase|mnemonic/i)
    expect(source).to.not.match(/'(?:[a-z]+ ){11,23}[a-z]+'/)
  })

  it('should accept the private key whose SHA-256 matches the configured hash and solve the challenge', async () => {
    req.body.privateKey = privateKey

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(200)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: true }))
    expect(challenges.nftUnlockChallenge.solved).to.equal(true)
  })

  it('should reject any other private key without solving the challenge', async () => {
    req.body.privateKey = '0x' + crypto.randomBytes(32).toString('hex')

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.' }))
    expect(challenges.nftUnlockChallenge.solved).to.equal(false)
  })

  it('should reject non-string input without solving the challenge', async () => {
    req.body.privateKey = { $ne: null }

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(challenges.nftUnlockChallenge.solved).to.equal(false)
  })

  it('should recognize the public wallet address', async () => {
    req.body.privateKey = '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05'

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ message: 'Looks like you entered the public address of my ethereum wallet!' }))
  })

  it('should recognize the public wallet key', async () => {
    req.body.privateKey = '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506'

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ message: 'Looks like you entered the public key of my ethereum wallet!' }))
  })
})
