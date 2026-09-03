/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'
import { HTTP_INTERCEPTORS, HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

import { RequestInterceptor } from './request.interceptor'

describe('RequestInterceptor', () => {
  let http: HttpClient
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting()
      ]
    })
    http = TestBed.inject(HttpClient)
    httpMock = TestBed.inject(HttpTestingController)
    localStorage.clear()
  })

  afterEach(() => {
    httpMock.verify()
    localStorage.clear()
  })

  it('should add the application token as Authorization header', () => {
    localStorage.setItem('token', 'app-token')
    http.get('/rest/x').subscribe()

    const req = httpMock.expectOne('/rest/x')
    expect(req.request.headers.get('Authorization')).toBe('Bearer app-token')
    req.flush({})
  })

  it('should not overwrite an Authorization header already set on the request', () => {
    localStorage.setItem('token', 'app-token')
    http.get('https://www.googleapis.com/oauth2/v1/userinfo?alt=json', { headers: { Authorization: 'Bearer google-token' } }).subscribe()

    const req = httpMock.expectOne('https://www.googleapis.com/oauth2/v1/userinfo?alt=json')
    expect(req.request.headers.get('Authorization')).toBe('Bearer google-token')
    req.flush({})
  })

  it('should not add an Authorization header without a stored token', () => {
    http.get('/rest/x').subscribe()

    const req = httpMock.expectOne('/rest/x')
    expect(req.request.headers.has('Authorization')).toBe(false)
    req.flush({})
  })
})
