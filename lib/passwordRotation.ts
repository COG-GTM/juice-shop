/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const usersRequiringPasswordChange = new Set<number>()

export function requirePasswordChange (userId: number) {
  usersRequiringPasswordChange.add(userId)
}

export function isPasswordChangeRequired (userId: number) {
  return usersRequiringPasswordChange.has(userId)
}

const rotationsInProgress = new Set<number>()

export function beginPasswordRotation (userId: number) {
  if (rotationsInProgress.has(userId)) return false
  rotationsInProgress.add(userId)
  return true
}

export function endPasswordRotation (userId: number) {
  rotationsInProgress.delete(userId)
}

export function clearPasswordChangeRequirement (userId: number) {
  usersRequiringPasswordChange.delete(userId)
}
