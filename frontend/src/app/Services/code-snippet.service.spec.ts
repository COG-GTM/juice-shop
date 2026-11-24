/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { CodeSnippetService } from './code-snippet.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('CodeSnippetService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [CodeSnippetService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(CodeSnippetService)

        expect(service).toBeTruthy()
    })

    it('should get single snippet directly from the rest api', () => {
        const service = TestBed.inject(CodeSnippetService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.get('testChallenge').subscribe((data) => (res = data))

        const req = httpMock.expectOne('http://localhost:3000/snippets/testChallenge')
        req.flush({ snippet: 'apiResponse' })

        expect(req.request.method).toBe('GET')
        expect(res).toEqual({ snippet: 'apiResponse' })
        httpMock.verify()
    })

    it('should keep a traversal key inside the snippets path', () => {
        const service = TestBed.inject(CodeSnippetService)
        const httpMock = TestBed.inject(HttpTestingController)

        service.get('../../rest/user/change-password?new=x&repeat=x').subscribe({ next: () => { }, error: () => { } })

        const req = httpMock.expectOne('http://localhost:3000/snippets/..%2F..%2Frest%2Fuser%2Fchange-password%3Fnew%3Dx%26repeat%3Dx')
        expect(req.request.method).toBe('GET')
        req.flush(null, { status: 404, statusText: 'Not Found' })
        httpMock.verify()
    })

    it('should handle error when getting single snippet', () => {
        const service = TestBed.inject(CodeSnippetService)
        const httpMock = TestBed.inject(HttpTestingController)

        let capturedError: any
        service.get('missing').subscribe({ next: () => { }, error: (e) => { capturedError = e } })
        const req = httpMock.expectOne('http://localhost:3000/snippets/missing')
        req.flush(null, { status: 404, statusText: 'Not Found' })
        expect(capturedError).toBeTruthy()
        expect(capturedError.status).toBe(404)
        httpMock.verify()
    })
})
