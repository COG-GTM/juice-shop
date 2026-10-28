/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { fork } from 'node:child_process'

export type SandboxedParserKind = 'xml' | 'yaml'

export interface SandboxedParseRequest {
  kind: SandboxedParserKind
  data: string
  substituteEntities: boolean
  maxOutputLength: number
}

export interface SandboxedParseResult {
  status: 'ok' | 'error' | 'timeout' | 'exhausted' | 'busy'
  output?: string
  message?: string
}

export const sandboxedParserLimits = {
  timeoutMs: 2000,
  startupTimeoutMs: 15000,
  maxOldSpaceSizeMb: 64,
  maxConcurrentParsers: 2,
  maxOutputLength: 10000
}

const workerExtension = path.extname(__filename)
const workerScript = path.join(__dirname, `sandboxedParserWorker${workerExtension}`)

let runningParsers = 0

// Parsing runs in a short-lived child process that is SIGKILLed on timeout, because neither vm timeouts nor
// worker_threads can interrupt a parser stuck in native code (e.g. libxml2 reading an external entity).
export async function parseInSandbox (kind: SandboxedParserKind, data: string, { substituteEntities = false } = {}): Promise<SandboxedParseResult> {
  if (runningParsers >= sandboxedParserLimits.maxConcurrentParsers) {
    return { status: 'busy' }
  }
  runningParsers++
  try {
    return await runParser({ kind, data, substituteEntities, maxOutputLength: sandboxedParserLimits.maxOutputLength })
  } finally {
    runningParsers--
  }
}

async function runParser (request: SandboxedParseRequest): Promise<SandboxedParseResult> {
  const execArgv = [`--max-old-space-size=${sandboxedParserLimits.maxOldSpaceSizeMb}`]
  if (workerExtension === '.ts') {
    execArgv.push('--import', 'tsx')
  }

  return await new Promise<SandboxedParseResult>((resolve) => {
    let settled = false
    const child = fork(workerScript, [], { execArgv, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], serialization: 'json' })
    let timer = setTimeout(() => { finish({ status: 'error', message: 'Parser did not start' }) }, sandboxedParserLimits.startupTimeoutMs)

    function finish (result: SandboxedParseResult) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
      }
      resolve(result)
    }

    child.on('message', (message: { ready?: boolean } & SandboxedParseResult) => {
      if (message.ready === true) {
        clearTimeout(timer)
        timer = setTimeout(() => { finish({ status: 'timeout' }) }, sandboxedParserLimits.timeoutMs)
        child.send(request)
      } else {
        finish({ status: message.status, output: message.output, message: message.message })
      }
    })
    child.once('error', (err) => { finish({ status: 'error', message: err.message }) })
    child.once('exit', () => { finish({ status: 'exhausted' }) })
  })
}
