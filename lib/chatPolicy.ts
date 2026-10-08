/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { rateLimit } from 'express-rate-limit'

export const maxClientMessages = 40
export const maxMessageLength = 4000
export const chatRateLimitWindowMs = 5 * 60 * 1000
export const chatRateLimitMax = 50

export interface ClientChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export type ParsedClientMessages = { messages: ClientChatMessage[], error?: undefined } | { messages?: undefined, error: string }

const clientRoles = new Set(['user', 'assistant'])

export function parseClientMessages (body: unknown): ParsedClientMessages {
  const raw = (body as { messages?: unknown } | undefined)?.messages
  if (!Array.isArray(raw) || raw.length === 0) return { error: 'messages must be a non-empty array' }
  if (raw.length > maxClientMessages) return { error: `At most ${maxClientMessages} messages are allowed` }

  const messages: ClientChatMessage[] = []
  for (const entry of raw) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return { error: 'Each message must be an object' }
    const { role, content } = entry as { role?: unknown, content?: unknown }
    if (typeof role !== 'string' || !clientRoles.has(role)) return { error: 'Only user and assistant messages are accepted' }
    if (typeof content !== 'string') return { error: 'Message content must be plain text' }
    if (content.length > maxMessageLength) return { error: `Messages must not exceed ${maxMessageLength} characters` }
    messages.push({ role: role as ClientChatMessage['role'], content })
  }
  if (messages[messages.length - 1].role !== 'user') return { error: 'The last message must be a user message' }
  return { messages }
}

export function chatRateLimiter () {
  return rateLimit({
    windowMs: chatRateLimitWindowMs,
    max: chatRateLimitMax,
    standardHeaders: 'draft-6',
    legacyHeaders: false,
    validate: false,
    message: { error: 'Too many chat requests, please try again later' }
  })
}
