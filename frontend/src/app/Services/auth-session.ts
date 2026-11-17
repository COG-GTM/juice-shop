/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export interface AuthSession {
  id?: number
  email?: string
  role?: string
  lastLoginIp?: string
}

// The JWT itself lives in an HttpOnly cookie; only non-secret user details are kept client-side.
const SESSION_KEY = 'session'

export const sessionFields = ['id', 'email', 'role', 'lastLoginIp']

export function storeSession (session: AuthSession) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session))
}

export function getSession (): AuthSession | null {
  const session = localStorage.getItem(SESSION_KEY)
  if (!session) {
    return null
  }
  try {
    return JSON.parse(session)
  } catch {
    return null
  }
}

export function hasSession (): boolean {
  return getSession() !== null
}

export function clearSession () {
  localStorage.removeItem(SESSION_KEY)
}
