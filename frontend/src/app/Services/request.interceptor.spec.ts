/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HTTP_INTERCEPTORS, HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'
import { RequestInterceptor } from './request.interceptor'

describe('RequestInterceptor', () => {
  let http: HttpClient
  let httpMock: HttpTestingController

  beforeEach(() => {
    localStorage.clear()
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        {
          provide: HTTP_INTERCEPTORS,
          useClass: RequestInterceptor,
          multi: true
        }
      ]
    })
    http = TestBed.inject(HttpClient)
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
    localStorage.clear()
  })

  function request () {
    http.get('/rest/test').subscribe()
    return httpMock.expectOne('/rest/test')
  }

  it('should add an Authorization header when a token is stored', () => {
    localStorage.setItem('token', 'token')

    const req = request()

    expect(req.request.headers.get('Authorization')).toBe('Bearer token')
    expect(req.request.headers.has('X-User-Email')).toBe(false)
    req.flush({})
  })

  it('should add an X-User-Email header when an email is stored', () => {
    localStorage.setItem('email', 'admin@juice-sh.op')

    const req = request()

    expect(req.request.headers.get('X-User-Email')).toBe('admin@juice-sh.op')
    expect(req.request.headers.has('Authorization')).toBe(false)
    req.flush({})
  })

  it('should add both headers when token and email are stored', () => {
    localStorage.setItem('token', 'token')
    localStorage.setItem('email', 'admin@juice-sh.op')

    const req = request()

    expect(req.request.headers.get('Authorization')).toBe('Bearer token')
    expect(req.request.headers.get('X-User-Email')).toBe('admin@juice-sh.op')
    req.flush({})
  })

  it('should not add any header when neither token nor email is stored', () => {
    const req = request()

    expect(req.request.headers.has('Authorization')).toBe(false)
    expect(req.request.headers.has('X-User-Email')).toBe(false)
    req.flush({})
  })
})
