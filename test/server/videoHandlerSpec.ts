/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
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

    it('should not contain characters that can terminate or open markup inside a <script> block', () => {
      const serialized = serializeSubtitles(exploit + '<!-- <script')
      expect(serialized).to.not.match(/[<>&]/)
    })
  })

  describe('promotionVideo', () => {
    let readFileSync: sinon.SinonStub
    let save: any

    beforeEach(() => {
      const original = fs.readFileSync
      readFileSync = sinon.stub(fs, 'readFileSync').callsFake((path: any, options?: any) => {
        if (String(path).endsWith('.vtt')) return exploit
        return original(path, options)
      })
      save = () => ({ then () { } })
      challenges.videoXssChallenge = { solved: false, save } as unknown as Challenge
    })

    afterEach(() => {
      readFileSync.restore()
    })

    it('should embed malicious subtitles as inert JSON data', async () => {
      const html: string = await new Promise((resolve) => {
        promotionVideo()({} as any, { send: resolve } as any)
      })

      expect(html).to.not.contain('</script><script>alert(`xss`)')
      const match = /<script id="subtitle" type="application\/json"[^>]*>([^<]*)<\/script>/.exec(html)
      expect(match?.[1]).to.be.a('string')
      expect(JSON.parse(match?.[1] ?? '')).to.equal(exploit)
    })
  })
})
