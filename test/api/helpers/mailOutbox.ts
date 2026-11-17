/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'

const outboxDir = path.resolve('mail/outbox')

async function findLatestResetToken (email: string, since: number): Promise<string | null> {
  const files = await fs.readdir(outboxDir).catch(() => [] as string[])
  const candidates = files.filter(file => file.endsWith('.eml') && Number(file.split('-')[0]) >= since).sort().reverse()
  for (const file of candidates) {
    const mail = (await fs.readFile(path.join(outboxDir, file), 'utf8')).replace(/=\r?\n/g, '')
    if (mail.includes(`To: ${email}`)) {
      const token = /^([a-f0-9]{64})\r?$/m.exec(mail)
      if (token) return token[1]
    }
  }
  return null
}

export async function waitForPasswordResetToken (email: string, since = 0, timeoutMs = 5000): Promise<string | null> {
  const deadline = Date.now() + timeoutMs
  do {
    const token = await findLatestResetToken(email, since)
    if (token) return token
    await new Promise(resolve => setTimeout(resolve, 100))
  } while (Date.now() < deadline)
  return null
}
