/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { jwtDecode } from 'jwt-decode'

// The session token itself lives in the server-set HttpOnly "token" cookie.
// Only non-secret claims are persisted so the UI knows who is logged in after a reload.
const SESSION_KEY = 'session'

export interface SessionClaims {
  data: {
    id?: number
    email?: string
    role?: string
    lastLoginIp?: string
    profileImage?: string
  }
  exp?: number
}

let inMemoryToken: string | null = null

export function startSession (token: string) {
  inMemoryToken = token
  let payload: any = {}
  try {
    payload = jwtDecode(token)
  } catch (err) {
    console.log(err)
  }
  const data = payload?.data ?? {}
  const claims: SessionClaims = {
    data: {
      id: data.id,
      email: data.email,
      role: data.role,
      lastLoginIp: data.lastLoginIp,
      profileImage: data.profileImage
    },
    exp: payload?.exp
  }
  localStorage.setItem(SESSION_KEY, JSON.stringify(claims))
}

export function endSession () {
  inMemoryToken = null
  localStorage.removeItem(SESSION_KEY)
  localStorage.removeItem('token')
}

export function sessionClaims (): SessionClaims | null {
  const stored = localStorage.getItem(SESSION_KEY)
  if (!stored) {
    return null
  }
  try {
    const claims: SessionClaims = JSON.parse(stored)
    if (claims.exp && claims.exp * 1000 <= Date.now()) {
      endSession()
      return null
    }
    return claims
  } catch {
    endSession()
    return null
  }
}

export function isLoggedIn () {
  return sessionClaims() !== null
}

export function authToken () {
  return isLoggedIn() ? inMemoryToken : null
}
