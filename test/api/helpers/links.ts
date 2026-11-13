/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export function containsLink (body: string, href: string): boolean {
  const expected = new URL(href)
  const candidates = body.match(/https?:\/\/[^\s"'<>&()[\]{}]+/g) ?? []
  return candidates.some(candidate => {
    try {
      const url = new URL(candidate.replace(/[.,;:!?]+$/, ''))
      return url.origin === expected.origin && url.pathname === expected.pathname
    } catch {
      return false
    }
  })
}
