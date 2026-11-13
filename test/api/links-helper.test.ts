/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { containsLink } from './helpers/links'

const paste = 'https://pastebin.com/90dUgd7s'

void describe('containsLink', () => {
  void it('finds the link as plain text, in an href and before punctuation', () => {
    assert.ok(containsLink(`see ${paste} for details`, paste))
    assert.ok(containsLink(`<a href="${paste}" rel="nofollow">paste</a>`, paste))
    assert.ok(containsLink(`&lt;a href=&quot;${paste}&quot;&gt;`, paste))
    assert.ok(containsLink(`(${paste}).`, paste))
  })

  void it('rejects the URL embedded in another host or path', () => {
    assert.equal(containsLink(`https://evil.example/?u=${paste}`, paste), false)
    assert.equal(containsLink(`https://evil.example/${paste}`, paste), false)
    assert.equal(containsLink('https://pastebin.com.evil.example/90dUgd7s', paste), false)
    assert.equal(containsLink('https://evilpastebin.com/90dUgd7s', paste), false)
    assert.equal(containsLink('http://pastebin.com/90dUgd7s', paste), false)
  })

  void it('rejects a different paste id', () => {
    assert.equal(containsLink('https://pastebin.com/90dUgd7sX', paste), false)
    assert.equal(containsLink('https://pastebin.com/90dUgd7s/raw', paste), false)
    assert.equal(containsLink('no links here', paste), false)
  })
})
