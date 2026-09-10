/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { fetchExternalImage, isDeniedIpAddress, parseExternalImageUrl } from '../../lib/ssrfProtection'

import chai from 'chai'
const expect = chai.expect

describe('ssrfProtection', () => {
  describe('isDeniedIpAddress', () => {
    it('denies the cloud metadata address', () => {
      expect(isDeniedIpAddress('169.254.169.254')).to.equal(true)
    })

    it('denies loopback addresses', () => {
      expect(isDeniedIpAddress('127.0.0.1')).to.equal(true)
      expect(isDeniedIpAddress('127.42.42.42')).to.equal(true)
      expect(isDeniedIpAddress('::1')).to.equal(true)
    })

    it('denies private and reserved IPv4 ranges', () => {
      expect(isDeniedIpAddress('10.1.2.3')).to.equal(true)
      expect(isDeniedIpAddress('172.16.0.1')).to.equal(true)
      expect(isDeniedIpAddress('172.31.255.255')).to.equal(true)
      expect(isDeniedIpAddress('192.168.1.1')).to.equal(true)
      expect(isDeniedIpAddress('100.64.0.1')).to.equal(true)
      expect(isDeniedIpAddress('0.0.0.0')).to.equal(true)
      expect(isDeniedIpAddress('255.255.255.255')).to.equal(true)
    })

    it('denies private IPv6 ranges and IPv4 addresses tunneled through IPv6', () => {
      expect(isDeniedIpAddress('fd00::1')).to.equal(true)
      expect(isDeniedIpAddress('fe80::1%eth0')).to.equal(true)
      expect(isDeniedIpAddress('ff02::1')).to.equal(true)
      expect(isDeniedIpAddress('::ffff:169.254.169.254')).to.equal(true)
      expect(isDeniedIpAddress('::ffff:a9fe:a9fe')).to.equal(true)
      expect(isDeniedIpAddress('64:ff9b::169.254.169.254')).to.equal(true)
      expect(isDeniedIpAddress('2002:a9fe:a9fe::1')).to.equal(true)
    })

    it('denies anything that is not an IP address', () => {
      expect(isDeniedIpAddress('metadata.google.internal')).to.equal(true)
      expect(isDeniedIpAddress('')).to.equal(true)
    })

    it('allows globally routable addresses', () => {
      expect(isDeniedIpAddress('1.1.1.1')).to.equal(false)
      expect(isDeniedIpAddress('172.32.0.1')).to.equal(false)
      expect(isDeniedIpAddress('93.184.216.34')).to.equal(false)
      expect(isDeniedIpAddress('2606:4700:4700::1111')).to.equal(false)
      expect(isDeniedIpAddress('::ffff:1.1.1.1')).to.equal(false)
    })
  })

  describe('parseExternalImageUrl', () => {
    it('accepts https URLs', () => {
      expect(parseExternalImageUrl('https://placekitten.com/100/100').hostname).to.equal('placekitten.com')
    })

    it('rejects any other protocol', () => {
      expect(() => parseExternalImageUrl('http://169.254.169.254/latest/meta-data/')).to.throw('Only https URLs are accepted')
      expect(() => parseExternalImageUrl('file:///etc/passwd')).to.throw('Only https URLs are accepted')
      expect(() => parseExternalImageUrl('gopher://localhost:6379/_FLUSHALL')).to.throw('Only https URLs are accepted')
    })

    it('rejects URLs with embedded credentials', () => {
      expect(() => parseExternalImageUrl('https://user:pass@example.com/cat.png')).to.throw('embedded credentials')
    })

    it('rejects IP literals pointing at non-public addresses', () => {
      expect(() => parseExternalImageUrl('https://169.254.169.254/latest/meta-data/')).to.throw('non-public address')
      expect(() => parseExternalImageUrl('https://[::1]/cat.png')).to.throw('non-public address')
    })

    it('rejects malformed URLs', () => {
      expect(() => parseExternalImageUrl('cataas.com/cat')).to.throw('is not a valid URL')
    })
  })

  describe('fetchExternalImage', () => {
    async function expectRejection (promise: Promise<unknown>, message: string) {
      try {
        await promise
      } catch (error) {
        expect((error as Error).message).to.contain(message)
        return
      }
      expect.fail(`Expected rejection with message containing "${message}"`)
    }

    it('refuses to request a URL that resolves to a non-public address', async () => {
      await expectRejection(fetchExternalImage('https://localhost/cat.png'), 'non-public address')
      await expectRejection(fetchExternalImage('https://127.0.0.1/cat.png'), 'non-public address')
      await expectRejection(fetchExternalImage('https://169.254.169.254/latest/meta-data/'), 'non-public address')
    })

    it('refuses to request a URL that is not https', async () => {
      await expectRejection(fetchExternalImage('http://169.254.169.254/latest/meta-data/'), 'Only https URLs are accepted')
    })
  })
})
