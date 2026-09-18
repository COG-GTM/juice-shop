/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { ProductService } from './product.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('ProductService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [ProductService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(ProductService)

        expect(service).toBeTruthy()
    })

    it('should search for products directly from the rest api', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.search('1').subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/products/search?q=1')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should get all products directly from the rest api', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.find(null).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/Products/')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(req.request.params.toString()).toBeFalsy()
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should get single product directly from the rest api', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.get(1).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/Products/1?d=' + encodeURIComponent(new Date().toDateString()))
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should update a product directly via the rest api', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.put(42, { name: 'Juice' }).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/Products/42')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('PUT')
        expect(req.request.body).toEqual({ name: 'Juice' })
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should handle error when updating a product', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let errorResponse: any
        service.put(42, { name: 'Juice' }).subscribe({ next: () => { }, error: (err) => (errorResponse = err) })
        const req = httpMock.expectOne('http://localhost:3000/api/Products/42')
        req.error(new ErrorEvent('Request failed'), { status: 400, statusText: 'Bad Request' })
        expect(errorResponse).toBeTruthy()
        expect(errorResponse.status).toBe(400)
        httpMock.verify()
    })

    it('should handle error when searching products', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let errorResponse: any
        service.search('1').subscribe({ next: () => { }, error: (err) => (errorResponse = err) })
        const req = httpMock.expectOne('http://localhost:3000/rest/products/search?q=1')
        req.flush(null, { status: 500, statusText: 'Server Error' })
        expect(errorResponse).toBeTruthy()
        expect(errorResponse.status).toBe(500)
        httpMock.verify()
    })

    it('should handle error when getting a single product', () => {
        const service = TestBed.inject(ProductService)
        const httpMock = TestBed.inject(HttpTestingController)

        let errorResponse: any
        service.get(1).subscribe({ next: () => { }, error: (err) => (errorResponse = err) })
        const req = httpMock.expectOne('http://localhost:3000/api/Products/1?d=' + encodeURIComponent(new Date().toDateString()))
        req.error(new ErrorEvent('Network error'))
        expect(errorResponse).toBeTruthy()
        expect(errorResponse.error).toBeTruthy()
        httpMock.verify()
    })
})
