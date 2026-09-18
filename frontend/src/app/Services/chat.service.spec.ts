/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'
import { ChatService, type ChatChunk } from './chat.service'
import { provideHttpClient, withInterceptorsFromDi, HttpEventType } from '@angular/common/http'

describe('ChatService', () => {
  let service: ChatService
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        ChatService,
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    })
    service = TestBed.inject(ChatService)
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('should be created', () => {
    expect(service).toBeTruthy()
  })

  it('should stream messages correctly', async () => {
    const messages = [{ role: 'user', content: 'hello' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    expect(req.request.method).toBe('POST')

    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 25,
      total: 100,
      partialText: 'data: {"choices": [{"delta": {"content": "Hello"}}] }\n'
    })

    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {"choices": [{"delta": {"content": "Hello"}}] }\ndata: {"choices": [{"delta": {"content": " world"}}] }\ndata: [DONE]\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([
      { deltaContent: 'Hello' },
      { deltaContent: ' world' }
    ])
  })

  it('should handle tool calls', async () => {
    const messages = [{ role: 'user', content: 'test tool' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')

    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {"choices": [{"delta": {"tool_calls": [{"id": "1", "type": "function", "function": {"name": "test", "arguments": "{}"}}]}}]}\ndata: [DONE]\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks[0].deltaToolCalls).toBeDefined()
    expect(chunks[0].deltaToolCalls?.[0].function.name).toBe('test')
  })

  it('should handle error from server', async () => {
    const messages = [{ role: 'user', content: 'error' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {"error": "some_error"}\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([{ error: 'some_error' }])
  })

  it('should propagate the finish reason of a finish-only chunk', async () => {
    const messages = [{ role: 'user', content: 'finish' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {"choices": [{"finish_reason": "stop"}]}\n\ndata: [DONE]\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([{ finishReason: 'stop' }])
  })

  it('should handle malformed chunks', async () => {
    const messages = [{ role: 'user', content: 'malformed' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {not json}\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([{ error: 'invalid_chunk' }])
  })

  it('should handle chunks that are valid JSON but not objects', async () => {
    const messages = [{ role: 'user', content: 'null' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: null\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([{ error: 'invalid_chunk' }])
  })

  it('should buffer events split across progress events', async () => {
    const messages = [{ role: 'user', content: 'split' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 25,
      total: 100,
      partialText: 'data: {"choices"'
    })

    req.event({
      type: HttpEventType.DownloadProgress,
      loaded: 50,
      total: 100,
      partialText: 'data: {"choices": [{"delta": {"content": "Hi"}}]}\ndata: [DONE]\n'
    })

    req.flush('', { status: 200, statusText: 'OK' })
    await processPromise

    expect(chunks).toEqual([{ deltaContent: 'Hi' }])
  })

  it('should handle connection failure', async () => {
    const messages = [{ role: 'user', content: 'fail' }]
    const generator = service.streamMessages(messages)

    const chunks: ChatChunk[] = []
    const processPromise = (async () => {
      for await (const chunk of generator) {
        chunks.push(chunk)
      }
    })()

    const req = httpMock.expectOne('http://localhost:3000/rest/chat')
    req.error(new ErrorEvent('Network error'))

    await processPromise
    expect(chunks).toEqual([{ error: 'connection_failed' }])
  })
})
