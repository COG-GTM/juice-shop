/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export function containsLink (body: string, href: string): boolean {
  const expected = new URL(href)
  const tokens = body.replace(/&(quot|apos|lt|gt|#34|#39);/g, ' ').split(/[\s"'<>]+/)
  return tokens.some(token => {
    try {
      const url = new URL(token.replace(/^[([{]+/, '').replace(/[)\]}.,;:!?]+$/, ''))
      return url.origin === expected.origin && url.pathname === expected.pathname
    } catch {
      return false
    }
  })
}
