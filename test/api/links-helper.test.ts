/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { containsLink } from './helpers/links'

const paste = 'https://pastebin.com/4U1V1UjU'

void describe('containsLink', () => {
  void it('finds the exact link in plain text, attributes and escaped HTML', () => {
    assert.ok(containsLink(`see ${paste}.`, paste))
    assert.ok(containsLink(`<a href="${paste}" rel="nofollow">${paste}</a>`, paste))
    assert.ok(containsLink(`&lt;a href=&quot;${paste}&quot;&gt;`, paste))
    assert.ok(containsLink(`(${paste})`, paste))
  })

  void it('rejects the URL embedded in another host or path', () => {
    assert.equal(containsLink('https://evil.example/https://pastebin.com/4U1V1UjU', paste), false)
    assert.equal(containsLink('https://pastebin.com.evil.example/4U1V1UjU', paste), false)
    assert.equal(containsLink('https://evil-pastebin.com/4U1V1UjU', paste), false)
    assert.equal(containsLink('https://pastebin.com/4U1V1UjUx', paste), false)
    assert.equal(containsLink('http://pastebin.com/4U1V1UjU', paste), false)
    assert.equal(containsLink('https://user@evil.example/?u=https://pastebin.com/4U1V1UjU', paste), false)
  })

  void it('rejects bodies without the link', () => {
    assert.equal(containsLink('', paste), false)
    assert.equal(containsLink('pastebin.com/4U1V1UjU', paste), false)
  })
})
