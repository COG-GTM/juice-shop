/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export const matchesSystemIniFile = (text: string) => {
  const match = text.match(/; for 16-bit app support/gi)
  return match !== null && match.length >= 1
}

export const matchesEtcPasswdFile = (text: string) => {
  const match = text.match(/(\w*:\w*:\d*:\d*:\w*:.*)|(Note that this file is consulted directly)/gi)
  return match !== null && match.length >= 1
}
