/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { ConfigurationService } from './configuration.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('ConfigurationService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [ConfigurationService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(ConfigurationService)

        expect(service).toBeTruthy()
    })

    it('should get application configuration directly from the rest api', () => {
        const service = TestBed.inject(ConfigurationService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.getApplicationConfiguration().subscribe(data => { res = data })

        const req = httpMock.expectOne('http://localhost:3000/rest/admin/application-configuration')
        req.flush({
            config: {
                version: '8.0.0',
                showGitHubLinks: false
            }
        })

        const data = res
        expect(data.version).toBe('8.0.0')
        expect(data.showGitHubLink).toBeFalsy()

        httpMock.verify()
    })

    it('should throw an error on recieving an error from the server', () => {
        const service = TestBed.inject(ConfigurationService)
        const httpMock = TestBed.inject(HttpTestingController)

        let capturedError: any
        service.getApplicationConfiguration().subscribe({ next: () => { }, error: (err) => (capturedError = err) })
        const req = httpMock.expectOne('http://localhost:3000/rest/admin/application-configuration')
        req.error(new ErrorEvent('Request failed'), { status: 404, statusText: 'Request failed' })

        expect(capturedError).toBeTruthy()
        expect(capturedError.status).toBe(404)
        expect(capturedError.statusText).toBe('Request failed')
        httpMock.verify()
    })

    it('should share a single request between all subscribers', () => {
        const service = TestBed.inject(ConfigurationService)
        const httpMock = TestBed.inject(HttpTestingController)

        const results: any[] = []
        service.getApplicationConfiguration().subscribe(data => results.push(data))
        service.getApplicationConfiguration().subscribe(data => results.push(data))

        httpMock.expectOne('http://localhost:3000/rest/admin/application-configuration').flush({ config: { application: { name: 'OWASP Juice Shop' } } })
        service.getApplicationConfiguration().subscribe(data => results.push(data))

        expect(results.length).toBe(3)
        expect(results[2].application.name).toBe('OWASP Juice Shop')
        httpMock.verify()
    })

    it('should request the configuration again after a failed request', () => {
        const service = TestBed.inject(ConfigurationService)
        const httpMock = TestBed.inject(HttpTestingController)

        service.getApplicationConfiguration().subscribe({ next: () => { }, error: () => { } })
        httpMock.expectOne('http://localhost:3000/rest/admin/application-configuration').flush(null, { status: 500, statusText: 'Server Error' })

        let res: any
        service.getApplicationConfiguration().subscribe(data => { res = data })
        httpMock.expectOne('http://localhost:3000/rest/admin/application-configuration').flush({ config: { version: '8.0.0' } })

        expect(res.version).toBe('8.0.0')
        httpMock.verify()
    })
})
