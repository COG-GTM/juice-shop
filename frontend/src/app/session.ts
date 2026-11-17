/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { jwtDecode } from 'jwt-decode'

// The JWT itself lives only in an HttpOnly cookie; only non-sensitive claims are kept client-side for UI state.
const SESSION_KEY = 'session'
const LEGACY_TOKEN_KEY = 'token'

export interface SessionClaims {
  data: {
    id?: number
    email?: string
    role?: string
    lastLoginIp?: string
    profileImage?: string
  }
}

export function storeSession (token: string) {
  let data: Record<string, any> | undefined
  try {
    data = jwtDecode<{ data?: Record<string, any> }>(token).data
  } catch (err) {
    console.log(err)
  }
  const claims: SessionClaims = {
    data: {
      id: data?.id,
      email: data?.email,
      role: data?.role,
      lastLoginIp: data?.lastLoginIp,
      profileImage: data?.profileImage
    }
  }
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  localStorage.setItem(SESSION_KEY, JSON.stringify(claims))
}

export function getSession (): SessionClaims | null {
  try {
    const session = localStorage.getItem(SESSION_KEY)
    return session ? JSON.parse(session) : null
  } catch {
    return null
  }
}

export function updateSessionRole (role: string) {
  const session = getSession()
  if (session) {
    session.data.role = role
    localStorage.setItem(SESSION_KEY, JSON.stringify(session))
  }
}

export function hasSession () {
  return getSession() !== null
}

export function clearSession () {
  localStorage.removeItem(SESSION_KEY)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
}
