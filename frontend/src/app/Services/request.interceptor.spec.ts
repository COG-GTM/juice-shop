/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpClient, HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { RequestInterceptor } from './request.interceptor'
import { environment } from '../../environments/environment'

describe('RequestInterceptor', () => {
  let http: HttpClient
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
      ]
    })
    http = TestBed.inject(HttpClient)
    httpMock = TestBed.inject(HttpTestingController)
    localStorage.setItem('token', 'TOKEN')
    localStorage.setItem('email', 'jim@juice-sh.op')
  })

  afterEach(() => {
    httpMock.verify()
    localStorage.removeItem('token')
    localStorage.removeItem('email')
  })

  function headersFor (url: string) {
    http.get(url).subscribe()
    const req = httpMock.expectOne(url)
    req.flush({})
    return req.request.headers
  }

  it('should add token and email headers to relative requests', () => {
    const headers = headersFor('/rest/user/whoami')
    expect(headers.get('Authorization')).toBe('Bearer TOKEN')
    expect(headers.get('X-User-Email')).toBe('jim@juice-sh.op')
  })

  it('should add token and email headers to requests against the configured host server', () => {
    const headers = headersFor(`${environment.hostServer}/rest/user/whoami`)
    expect(headers.get('Authorization')).toBe('Bearer TOKEN')
    expect(headers.get('X-User-Email')).toBe('jim@juice-sh.op')
  })

  it('should not send token or email to other hosts', () => {
    for (const url of ['https://example.org/x', 'http://localhost:3001/rest/user/whoami', 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json', '//example.org/x']) {
      const headers = headersFor(url)
      expect(headers.has('Authorization')).toBe(false)
      expect(headers.has('X-User-Email')).toBe(false)
    }
  })

  it('should not add headers when not logged in', () => {
    localStorage.removeItem('token')
    localStorage.removeItem('email')
    const headers = headersFor('/rest/user/whoami')
    expect(headers.has('Authorization')).toBe(false)
    expect(headers.has('X-User-Email')).toBe(false)
  })
})
