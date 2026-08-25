/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { assertSafeFetchUrl, isForbiddenAddress } from '../../lib/urlSecurity'

import chai from 'chai'
const expect = chai.expect

async function rejectionMessage (promise: Promise<unknown>) {
  try {
    await promise
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
  return undefined
}

describe('urlSecurity', () => {
  describe('isForbiddenAddress', () => {
    it('forbids loopback, private, link-local and reserved IPv4 addresses', () => {
      expect(isForbiddenAddress('127.0.0.1')).to.equal(true)
      expect(isForbiddenAddress('10.1.2.3')).to.equal(true)
      expect(isForbiddenAddress('172.16.0.1')).to.equal(true)
      expect(isForbiddenAddress('192.168.1.1')).to.equal(true)
      expect(isForbiddenAddress('169.254.169.254')).to.equal(true)
      expect(isForbiddenAddress('0.0.0.0')).to.equal(true)
      expect(isForbiddenAddress('255.255.255.255')).to.equal(true)
    })

    it('forbids loopback, unique-local and link-local IPv6 addresses', () => {
      expect(isForbiddenAddress('::1')).to.equal(true)
      expect(isForbiddenAddress('::')).to.equal(true)
      expect(isForbiddenAddress('fd00::1')).to.equal(true)
      expect(isForbiddenAddress('fe80::1')).to.equal(true)
      expect(isForbiddenAddress('::ffff:169.254.169.254')).to.equal(true)
    })

    it('allows public addresses', () => {
      expect(isForbiddenAddress('1.1.1.1')).to.equal(false)
      expect(isForbiddenAddress('2606:4700:4700::1111')).to.equal(false)
    })

    it('forbids anything that is not an IP address', () => {
      expect(isForbiddenAddress('not.an.ip')).to.equal(true)
    })
  })

  describe('assertSafeFetchUrl', () => {
    it('rejects non-HTTP(S) protocols', async () => {
      expect(await rejectionMessage(assertSafeFetchUrl('file:///etc/passwd'))).to.contain('unsupported protocol')
    })

    it('rejects URLs containing credentials', async () => {
      expect(await rejectionMessage(assertSafeFetchUrl('http://user:pass@example.com/image.png'))).to.contain('must not contain credentials')
    })

    it('rejects the cloud metadata address', async () => {
      expect(await rejectionMessage(assertSafeFetchUrl('http://169.254.169.254/latest/meta-data/'))).to.contain('non-public address')
    })

    it('rejects loopback literals', async () => {
      expect(await rejectionMessage(assertSafeFetchUrl('http://127.0.0.1:3000/solve/challenges/server-side'))).to.contain('non-public address')
      expect(await rejectionMessage(assertSafeFetchUrl('http://[::1]:3000/'))).to.contain('non-public address')
    })

    it('rejects hostnames resolving to a non-public address', async () => {
      expect(await rejectionMessage(assertSafeFetchUrl('http://localhost:3000/'))).to.contain('non-public address')
    })

    it('accepts a public IP address', async () => {
      const url = await assertSafeFetchUrl('https://1.1.1.1/image.png')
      expect(url.hostname).to.equal('1.1.1.1')
    })
  })
})
