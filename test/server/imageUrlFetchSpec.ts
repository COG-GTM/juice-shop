/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import sinon from 'sinon'
import chai from 'chai'
import { isPrivateAddress, validateImageUrl } from '../../lib/imageUrlFetch'

const expect = chai.expect

const rejectionMessage = async (promise: Promise<unknown>) => {
  try {
    await promise
  } catch (error) {
    return (error as Error).message
  }
  return undefined
}

describe('imageUrlFetch', () => {
  describe('isPrivateAddress', () => {
    it('should detect loopback, link-local, private and reserved ranges', () => {
      for (const address of ['127.0.0.1', '0.0.0.0', '10.1.2.3', '169.254.169.254', '172.20.0.1', '192.168.0.5', '100.100.100.100', '::1', '::ffff:127.0.0.1', 'fd00::1', 'fe80::1']) {
        expect(isPrivateAddress(address), address).to.equal(true)
      }
    })

    it('should accept public addresses', () => {
      for (const address of ['8.8.8.8', '172.15.0.1', '2606:4700:4700::1111']) {
        expect(isPrivateAddress(address), address).to.equal(false)
      }
    })

    it('should treat non-IP input as private', () => {
      expect(isPrivateAddress('example.com')).to.equal(true)
    })
  })

  describe('validateImageUrl', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('should reject relative urls', async () => {
      expect(await rejectionMessage(validateImageUrl('cataas.com/cat'))).to.contain('not a valid absolute url')
    })

    it('should reject non-http(s) schemes', async () => {
      expect(await rejectionMessage(validateImageUrl('file:///etc/passwd'))).to.contain('protocol file: is not allowed')
    })

    it('should reject urls with credentials', async () => {
      sinon.stub(dns, 'lookup').resolves([{ address: '8.8.8.8', family: 4 }] as any)
      expect(await rejectionMessage(validateImageUrl('https://user:pass@example.com/cat.png'))).to.contain('must not contain credentials')
    })

    it('should reject uncommon ports', async () => {
      sinon.stub(dns, 'lookup').resolves([{ address: '8.8.8.8', family: 4 }] as any)
      expect(await rejectionMessage(validateImageUrl('http://example.com:9200/cat.png'))).to.contain('port 9200 is not allowed')
    })

    it('should reject the cloud metadata address', async () => {
      expect(await rejectionMessage(validateImageUrl('http://169.254.169.254/latest/meta-data/'))).to.contain('non-public address')
    })

    it('should reject hostnames resolving to a private address', async () => {
      sinon.stub(dns, 'lookup').resolves([{ address: '127.0.0.1', family: 4 }] as any)
      expect(await rejectionMessage(validateImageUrl('http://localtest.me/cat.png'))).to.contain('non-public address')
    })

    it('should reject hostnames that cannot be resolved', async () => {
      sinon.stub(dns, 'lookup').rejects(new Error('ENOTFOUND'))
      expect(await rejectionMessage(validateImageUrl('https://no.such.host/cat.png'))).to.contain('could not be resolved')
    })

    it('should accept a public image url', async () => {
      sinon.stub(dns, 'lookup').resolves([{ address: '8.8.8.8', family: 4 }] as any)
      const url = await validateImageUrl('https://example.com/cat.png')
      expect(url.href).to.equal('https://example.com/cat.png')
    })
  })
})
