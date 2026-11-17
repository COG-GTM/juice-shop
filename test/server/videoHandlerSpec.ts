/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import sinon from 'sinon'
import chai from 'chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { promotionVideo } from '../../routes/videoHandler'

const expect = chai.expect

describe('videoHandler', () => {
  const realReadFileSync = fs.readFileSync
  let readFileSyncStub: sinon.SinonStub

  beforeEach(() => {
    challenges.videoXssChallenge = { solved: true, save: () => ({ then () {} }) } as unknown as Challenge
    readFileSyncStub = sinon.stub(fs, 'readFileSync').callsFake((path: any, options?: any) => {
      if (String(path).endsWith('.vtt')) {
        return 'WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nHi</script><script>alert(`xss`)</script>'
      }
      return realReadFileSync(path, options)
    })
  })

  afterEach(() => {
    readFileSyncStub.restore()
  })

  it('should HTML-encode subtitles so they cannot break out into a script', async () => {
    const html: string = await new Promise((resolve) => {
      promotionVideo()({} as any, { send: resolve } as any)
    })

    expect(html).to.not.contain('<script>alert(`xss`)</script>')
    expect(html).to.not.contain('<script id="subtitle"')
    expect(html).to.contain('<div id="subtitle" hidden data-label="English" data-lang="en">WEBVTT')
    expect(html).to.contain('00:00:00.000 --&gt; 00:00:01.000')
    expect(html).to.contain('Hi&lt;/script&gt;&lt;script&gt;alert(`xss`)&lt;/script&gt;')
  })
})
