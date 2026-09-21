/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { limitMessages } from '../../routes/chat'
const expect = chai.expect

function message (content: string) {
  return { role: 'user', content }
}

describe('chat', () => {
  describe('limitMessages', () => {
    it('should pass through a short conversation unchanged', () => {
      const messages = [message('hello'), message('how are you?')]
      expect(limitMessages(messages)).to.deep.equal({ messages })
    })

    it('should reject a non-array payload', () => {
      expect(limitMessages('not an array').error).to.equal('Invalid messages payload')
    })

    it('should reject a single oversized message', () => {
      expect(limitMessages([message('a'.repeat(8193))]).error).to.match(/^Message too long/)
    })

    it('should count fields other than content towards the message size', () => {
      expect(limitMessages([{ role: 'user', content: 'hi', metadata: 'a'.repeat(8193) }]).error).to.match(/^Message too long/)
    })

    it('should keep only the most recent messages when the count limit is exceeded', () => {
      const messages = Array.from({ length: 60 }, (_, i) => message(`message ${i}`))
      expect(limitMessages(messages).messages).to.deep.equal(messages.slice(-50))
    })

    it('should drop oldest messages when the total character limit is exceeded', () => {
      const messages = Array.from({ length: 10 }, () => message('a'.repeat(8000)))
      const limited = limitMessages(messages).messages
      expect(limited.length).to.be.below(messages.length)
      expect(limited[limited.length - 1]).to.deep.equal(messages[messages.length - 1])
    })
  })
})
