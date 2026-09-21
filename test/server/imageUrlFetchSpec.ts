/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { fetchProfileImage } from '../../lib/imageUrlFetch'

import chai from 'chai'
const expect = chai.expect

async function expectRejection (url: string) {
  try {
    await fetchProfileImage(url)
  } catch (error) {
    return error as Error
  }
  return expect.fail(`expected ${url} to be rejected`)
}

describe('imageUrlFetch', () => {
  describe('fetchProfileImage', () => {
    it('rejects non-https urls', async () => {
      expect((await expectRejection('http://example.com/image.png')).message).to.equal('only https urls are allowed for profile images')
    })

    it('rejects urls without a scheme', async () => {
      expect(await expectRejection('example.com/image.png')).to.be.an('error')
    })

    it('rejects file urls', async () => {
      expect((await expectRejection('file:///etc/passwd')).message).to.equal('only https urls are allowed for profile images')
    })

    it('rejects loopback addresses', async () => {
      expect((await expectRejection('https://127.0.0.1/image.png')).message).to.equal('url resolves to a non-public address')
      expect((await expectRejection('https://[::1]/image.png')).message).to.equal('url resolves to a non-public address')
    })

    it('rejects hostnames resolving to loopback addresses', async () => {
      expect((await expectRejection('https://localhost/image.png')).message).to.equal('url resolves to a non-public address')
    })

    it('rejects the cloud metadata address', async () => {
      expect((await expectRejection('https://169.254.169.254/latest/meta-data/')).message).to.equal('url resolves to a non-public address')
    })

    it('rejects private network addresses', async () => {
      for (const host of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '[fd00::1]', '[::ffff:10.0.0.1]']) {
        expect((await expectRejection(`https://${host}/image.png`)).message).to.equal('url resolves to a non-public address')
      }
    })
  })
})
