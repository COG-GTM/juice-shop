/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import sinon from 'sinon'
import chai from 'chai'
import { getVideo, parseByteRange } from '../../routes/videoHandler'
const expect = chai.expect

const sourceVideo = 'frontend/src/assets/public/videos/owasp_promo.mp4'

describe('videoHandler', () => {
  describe('parseByteRange', () => {
    it('should parse closed ranges', () => {
      expect(parseByteRange('bytes=0-1023', 5000)).to.deep.equal({ start: 0, end: 1023 })
    })

    it('should parse open-ended ranges', () => {
      expect(parseByteRange('bytes=100-', 5000)).to.deep.equal({ start: 100, end: 4999 })
    })

    it('should parse suffix ranges', () => {
      expect(parseByteRange('bytes=-500', 5000)).to.deep.equal({ start: 4500, end: 4999 })
      expect(parseByteRange('bytes=-9000', 5000)).to.deep.equal({ start: 0, end: 4999 })
    })

    it('should clamp oversized ends and suffixes to the file size as per RFC 9110', () => {
      expect(parseByteRange('bytes=4000-9000', 5000)).to.deep.equal({ start: 4000, end: 4999 })
      expect(parseByteRange('bytes=0-99999999999999999999', 5000)).to.deep.equal({ start: 0, end: 4999 })
      expect(parseByteRange('bytes=-99999999999999999999', 5000)).to.deep.equal({ start: 0, end: 4999 })
    })

    it('should reject malformed or unsatisfiable ranges', () => {
      for (const range of ['bytes=abc-', 'bytes=-', 'bytes=-0', 'bytes=1-x', 'bytes=10-5', 'bytes=5000-', 'bytes=0-1,5-9', 'items=0-1', 'bytes=99999999999999999999-']) {
        expect(parseByteRange(range, 5000), range).to.equal(null)
      }
    })
  })

  describe('getVideo', () => {
    let server: http.Server
    let port: number
    let streams: fs.ReadStream[]

    beforeEach((done) => {
      streams = []
      const createReadStream = fs.createReadStream
      sinon.stub(fs, 'statSync').returns({ size: fs.lstatSync(sourceVideo).size } as any)
      sinon.stub(fs, 'createReadStream').callsFake((_path: any, options?: any) => {
        const stream = createReadStream(sourceVideo, options)
        streams.push(stream)
        return stream
      })
      server = http.createServer(getVideo() as any).listen(0, () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    afterEach((done) => {
      sinon.restore()
      server.close(() => { done() })
    })

    function requestAndAbort (headers: Record<string, string>) {
      return new Promise<void>((resolve, reject) => {
        const req = http.get({ port, path: '/video', headers }, (res) => {
          res.once('data', () => {
            req.destroy()
            resolve()
          })
        })
        req.on('error', (err: NodeJS.ErrnoException) => { if (err.code !== 'ECONNRESET') reject(err) })
      })
    }

    async function waitUntilAllClosed () {
      for (let i = 0; i < 100 && streams.some(s => !s.closed); i++) {
        await new Promise(resolve => setTimeout(resolve, 20))
      }
    }

    it('should close the file stream when the client aborts a full download', async () => {
      await requestAndAbort({})
      await waitUntilAllClosed()
      expect(streams).to.have.lengthOf(1)
      expect(streams[0].closed).to.equal(true)
    })

    it('should close the file stream when the client aborts a range download', async () => {
      await requestAndAbort({ Range: 'bytes=0-' })
      await waitUntilAllClosed()
      expect(streams).to.have.lengthOf(1)
      expect(streams[0].closed).to.equal(true)
    })

    it('should answer 416 without opening the file for invalid ranges', async () => {
      const res = await new Promise<http.IncomingMessage>((resolve) => {
        http.get({ port, path: '/video', headers: { Range: 'bytes=abc-' } }, (res) => { res.resume(); resolve(res) })
      })
      expect(res.statusCode).to.equal(416)
      expect(res.headers['content-range']).to.match(/^bytes \*\/\d+$/)
      expect(streams).to.have.lengthOf(0)
    })
  })
})
