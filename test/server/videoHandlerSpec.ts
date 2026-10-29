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
import { promotionCsp, promotionVideo, serializeSubtitles } from '../../routes/videoHandler'

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

    let headers: Record<string, string>
    const render = async (handler = promotionVideo()): Promise<string> => await new Promise((resolve, reject) => {
      headers = {}
      handler({} as any, { send: resolve, set: (name: string, value: string) => { headers[name] = value } } as any, reject)
    })
    const reads = (file: string) => readFileSync.getCalls().filter(call => call.args[0] === file).length

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

    it('should send a nonce-based Content-Security-Policy that covers every executable script tag', async () => {
      const html = await render()

      const nonce = /'nonce-([A-Za-z0-9+/=]+)'/.exec(headers['Content-Security-Policy'])?.[1]
      expect(nonce).to.be.a('string')
      expect(headers['Content-Security-Policy']).to.equal(promotionCsp(nonce ?? ''))
      const scriptTags = (html.match(/<script(?=[\s>])[^>]*>/g) ?? []).filter(tag => !tag.includes('type="application/json"'))
      expect(scriptTags.length).to.be.greaterThan(1)
      for (const tag of scriptTags) {
        expect(tag).to.contain(`nonce="${nonce}"`)
      }
    })

    it('should use a fresh nonce for every response', async () => {
      await render()
      const first = headers['Content-Security-Policy']
      await render()
      expect(headers['Content-Security-Policy']).to.not.equal(first)
    })

    it('should only read the configured subtitles file name from the videos folder', async () => {
      configGet.withArgs('application.promotion.subtitles').returns('../../../../etc/passwd')

      await render()

      expect(readFileSync).to.have.been.calledWith('frontend/dist/frontend/assets/public/videos/passwd', 'utf8')
    })

    it('should read the downloaded file name for subtitles configured as URL', async () => {
      configGet.withArgs('application.promotion.subtitles').returns('https://example.com/subs/..%2F..%2Fpasswd?x=1')

      await render()

      expect(readFileSync).to.have.been.calledWith('frontend/dist/frontend/assets/public/videos/passwd', 'utf8')
    })

    it('should not URL-decode local subtitles file names', async () => {
      configGet.withArgs('application.promotion.subtitles').returns('promo%OFF.vtt')

      await render()

      expect(readFileSync).to.have.been.calledWith('frontend/dist/frontend/assets/public/videos/promo%OFF.vtt', 'utf8')
    })

    it('should pass subtitles read errors to the error handler', async () => {
      readFileSync.withArgs('frontend/dist/frontend/assets/public/videos/missing.vtt').throws(new Error('ENOENT'))
      configGet.withArgs('application.promotion.subtitles').returns('missing.vtt')

      const error = await render().then(() => null, (e: Error) => e)
      expect(error?.message).to.equal('ENOENT')
    })

    it('should compile the template only once when the route is created', async () => {
      const handler = promotionVideo()
      const first = await render(handler)
      readFileSync.withArgs('views/promotionVideo.pug').returns('p #{process.version}')

      const second = await render(handler)

      expect(second.replace(/nonce="[^"]+"/g, '')).to.equal(first.replace(/nonce="[^"]+"/g, ''))
      expect(reads('views/promotionVideo.pug')).to.equal(1)
    })

    it('should serve subtitles that are replaced after the route was created', async () => {
      const handler = promotionVideo()
      await render(handler)
      const replaced = 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nreplaced\n'
      readFileSync.withArgs('frontend/dist/frontend/assets/public/videos/owasp_promo.vtt').returns(replaced)

      const html = await render(handler)

      const match = /<script id="subtitle" type="application\/json"[^>]*>([^<]*)<\/script>/.exec(html)
      expect(JSON.parse(match?.[1] ?? '')).to.equal(replaced)
    })

    it('should retry reading the subtitles on the next request after a failure', async () => {
      let missing = true
      readFileSync.withArgs('frontend/dist/frontend/assets/public/videos/owasp_promo.vtt').callsFake(() => {
        if (missing) throw new Error('ENOENT')
        return exploit
      })
      const handler = promotionVideo()
      const error = await render(handler).then(() => null, (e: Error) => e)
      expect(error?.message).to.equal('ENOENT')

      missing = false
      const html = await render(handler)

      expect(html).to.contain('<script id="subtitle" type="application/json"')
      expect(reads('views/promotionVideo.pug')).to.equal(1)
    })
  })
})
