/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const urlCandidate = /https?:\/\/[^\s"'<>&]+/g

function parse (value: string): URL | null {
  try {
    return new URL(value.replace(/[.,;:!?)\]]+$/, ''))
  } catch {
    return null
  }
}

export function containsLink (body: string, expected: string): boolean {
  const target = new URL(expected)
  return (body.match(urlCandidate) ?? []).some((candidate) => {
    const url = parse(candidate)
    return url !== null &&
      url.protocol === target.protocol &&
      url.hostname === target.hostname &&
      url.port === target.port &&
      url.pathname === target.pathname
  })
}
