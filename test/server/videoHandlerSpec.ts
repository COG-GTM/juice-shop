/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { encodeSubtitlesForScriptBlock } from '../../routes/videoHandler'

const expect = chai.expect

describe('videoHandler', () => {
  describe('encodeSubtitlesForScriptBlock', () => {
    it('should not contain characters that can terminate or alter a <script> block', () => {
      const encoded = encodeSubtitlesForScriptBlock('</script><script>alert(`xss`)</script><!-- & \u2028\u2029')
      expect(encoded).to.not.match(/[<>&\u2028\u2029]/)
    })

    it('should round-trip subtitle content through JSON.parse', () => {
      const subs = 'WEBVTT\r\n\r\n00:00:01.396 --> 00:00:03.219\n"OWASP" is <b>a</b> non profit & more\u2028'
      expect(JSON.parse(encodeSubtitlesForScriptBlock(subs))).to.equal(subs)
    })
  })
})
