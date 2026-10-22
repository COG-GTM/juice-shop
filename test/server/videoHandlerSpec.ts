/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { promotionVideo, serializeSubtitles } from '../../routes/videoHandler'

const expect = chai.expect
chai.use(sinonChai)

const exploit = 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHi</script><script>alert(`xss`)</script>\n'

describe('videoHandler', () => {
  describe('serializeSubtitles', () => {
    it('should round-trip subtitle content through JSON.parse', () => {
      for (const subs of [exploit, 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nA & B <i>c</i> $\' $` $&\n']) {
        expect(JSON.parse(serializeSubtitles(subs))).to.equal(subs)
      }
    })

    it('should not contain characters that can close or open markup inside a <script> block', () => {
      expect(serializeSubtitles(exploit + '<!-- <script')).to.not.match(/[<>&]/)
    })
  })

  describe('promotionVideo', () => {
    let readFileSync: sinon.SinonStub
    let configGet: sinon.SinonStub
    let originalChallenge: Challenge

    const render = async (): Promise<string> => await new Promise((resolve) => {
      promotionVideo()({} as any, { send: resolve } as any)
    })

    beforeEach(() => {
      const original = fs.readFileSync
      readFileSync = sinon.stub(fs, 'readFileSync').callsFake((path: any, options?: any) => {
        if (String(path).startsWith('frontend/dist/frontend/assets/public/videos/')) return exploit
        return original(path, options)
      })
      configGet = sinon.stub(config, 'get').callThrough()
      originalChallenge = challenges.videoXssChallenge
      challenges.videoXssChallenge = { solved: false, save: () => ({ then () { } }) } as unknown as Challenge
    })

    afterEach(() => {
      readFileSync.restore()
      configGet.restore()
      challenges.videoXssChallenge = originalChallenge
    })

    it('should embed malicious subtitles as inert JSON data', async () => {
      const html = await render()

      expect(html).to.not.contain('</script><script>alert(`xss`)')
      const match = /<script id="subtitle" type="application\/json"[^>]*>([^<]*)<\/script>/.exec(html)
      expect(match?.[1]).to.be.a('string')
      expect(JSON.parse(match?.[1] ?? '')).to.equal(exploit)
    })

    it('should only read the configured subtitles file name from the videos folder', async () => {
      configGet.withArgs('application.promotion.subtitles').returns('..%2F..%2F..%2F..%2Fetc%2Fpasswd')

      await render()

      expect(readFileSync).to.have.been.calledWith('frontend/dist/frontend/assets/public/videos/passwd', 'utf8')
    })
  })
})
