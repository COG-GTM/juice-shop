/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'

export const profileImageUploadDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')

export function toProfileImageUserId (id: unknown): number | undefined {
  let value = Number.NaN
  if (typeof id === 'number') {
    value = id
  } else if (typeof id === 'string' && /^\d+$/.test(id)) {
    value = Number.parseInt(id, 10)
  }
  return Number.isSafeInteger(value) && value > 0 ? value : undefined
}

export function profileImageUploadPath (userId: number, ext: string): string | undefined {
  if (toProfileImageUserId(userId) !== userId || !/^[a-z0-9]+$/i.test(ext)) return undefined
  const filePath = path.resolve(profileImageUploadDir, `${userId}.${ext}`)
  return path.dirname(filePath) === profileImageUploadDir ? filePath : undefined
}
