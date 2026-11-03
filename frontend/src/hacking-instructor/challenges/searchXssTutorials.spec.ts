/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { DomXssInstruction } from './domXss'
import { BonusPayloadInstruction } from './bonusPayload'
import { type ChallengeInstruction } from '../'

function searchValueHints (instruction: ChallengeInstruction) {
  return instruction.hints.filter(hint => /hit enter/i.test(hint.text))
}

describe('search XSS tutorials', () => {
  let searchValue: HTMLSpanElement

  beforeEach(() => {
    searchValue = document.createElement('span')
    searchValue.id = 'searchValue'
    document.body.appendChild(searchValue)
  })

  afterEach(() => {
    searchValue.remove()
  })

  async function expectResolvedWithText (resolved: () => Promise<void>, text: string) {
    searchValue.textContent = text
    await expect(Promise.race([
      resolved().then(() => 'resolved'),
      new Promise(resolve => setTimeout(() => { resolve('timeout') }, 1000))
    ])).resolves.toBe('resolved')
  }

  it('should advance the DOM XSS tutorial when search terms are rendered as plain text', async () => {
    const hints = searchValueHints(DomXssInstruction)
    const expectedTexts = ['owasp', '<h1>owasp', '<script>alert(xss)</script>', '<iframe src="javascript:alert(`xss`)">']
    expect(hints.length).toBe(expectedTexts.length)
    for (let i = 0; i < hints.length; i++) {
      await expectResolvedWithText(hints[i].resolved, expectedTexts[i])
    }
  })

  it('should advance the Bonus Payload tutorial when the payload is rendered as plain text', async () => {
    const hints = searchValueHints(BonusPayloadInstruction)
    expect(hints.length).toBe(1)
    await expectResolvedWithText(hints[0].resolved, '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>')
  })
})
