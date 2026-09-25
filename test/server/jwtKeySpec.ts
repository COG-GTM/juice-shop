/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import chai from 'chai'
import sinon from 'sinon'
import jwt from 'jsonwebtoken'

const expect = chai.expect

type Security = typeof import('../../lib/insecurity')

const generateKey = () => crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' }
}).privateKey

const publicKeyOf = (privateKey: string) => crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()

describe('jwt signing key', () => {
  let directory: string
  let keyFile: string

  const loadSecurity = (): Security => {
    delete require.cache[require.resolve('../../lib/insecurity')]
    return require('../../lib/insecurity')
  }

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-jwt-'))
    keyFile = path.join(directory, 'jwt.key')
    process.env.JWT_PRIVATE_KEY_FILE = keyFile
    delete process.env.JWT_PRIVATE_KEY
  })

  afterEach(() => {
    sinon.restore()
    delete process.env.JWT_PRIVATE_KEY
    delete process.env.JWT_PRIVATE_KEY_FILE
    fs.rmSync(directory, { recursive: true, force: true })
    loadSecurity()
  })

  it('uses the PEM key given in JWT_PRIVATE_KEY', () => {
    const key = generateKey()
    process.env.JWT_PRIVATE_KEY = key

    expect(loadSecurity().publicKey).to.equal(publicKeyOf(key))
    expect(fs.existsSync(keyFile)).to.equal(false)
  })

  it('uses a base64-encoded key given in JWT_PRIVATE_KEY', () => {
    const key = generateKey()
    process.env.JWT_PRIVATE_KEY = Buffer.from(key, 'utf8').toString('base64')

    expect(loadSecurity().publicKey).to.equal(publicKeyOf(key))
  })

  it('uses the key stored in the file given by JWT_PRIVATE_KEY_FILE', () => {
    const key = generateKey()
    fs.writeFileSync(keyFile, key)

    expect(loadSecurity().publicKey).to.equal(publicKeyOf(key))
  })

  it('generates a key file for a fresh installation and reuses it afterwards', () => {
    const publicKey = loadSecurity().publicKey

    expect(fs.readFileSync(keyFile, 'utf8')).to.contain('-----BEGIN PRIVATE KEY-----')
    if (process.platform !== 'win32') {
      expect(fs.statSync(keyFile).mode & 0o777).to.equal(0o600)
    }
    expect(loadSecurity().publicKey).to.equal(publicKey)
  })

  it('shares the generated key between processes without hard links', () => {
    const withoutHardLinks = () => {
      sinon.restore()
      sinon.stub(fs, 'linkSync').throws(Object.assign(new Error('EPERM'), { code: 'EPERM' }))
      return loadSecurity().publicKey
    }

    const publicKey = withoutHardLinks()

    expect(fs.readFileSync(keyFile, 'utf8')).to.contain('-----BEGIN PRIVATE KEY-----')
    expect(withoutHardLinks()).to.equal(publicKey)
  })

  it('falls back to an ephemeral key when the key file cannot be written', () => {
    process.env.JWT_PRIVATE_KEY_FILE = path.join(directory, 'missing', 'jwt.key')

    const publicKey = loadSecurity().publicKey

    expect(publicKey).to.contain('-----BEGIN PUBLIC KEY-----')
    expect(loadSecurity().publicKey).to.not.equal(publicKey)
  })

  it('issues tokens that only verify against the key in use', () => {
    const security = loadSecurity()
    const token = security.authorize({ data: { id: 1 } })
    const foreignToken = jwt.sign({ data: { id: 1 } }, generateKey(), { algorithm: 'RS256' })

    expect(security.verify(token)).to.equal(true)
    expect(security.verify(foreignToken)).to.equal(false)
  })
})
