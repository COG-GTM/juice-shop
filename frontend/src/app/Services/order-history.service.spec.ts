/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'
import { OrderHistoryService } from './order-history.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('OrderHistoryService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [OrderHistoryService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(OrderHistoryService)

        expect(service).toBeTruthy()
    })

    it('should get payment cards directly from the api', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res
        service.get().subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should get payment cards directly from the api', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res
        service.getAll().subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/orders')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should update address directly from the api', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res
        service.toggleDeliveryStatus(1, {}).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/1/delivery-status')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('PUT')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should handle error when getting order history', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let capturedError: any
        service.get().subscribe({ next: () => { }, error: (e) => { capturedError = e } })
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history')
        req.flush(null, { status: 500, statusText: 'Server Error' })
        expect(capturedError).toBeTruthy()
        expect(capturedError.status).toBe(500)
        httpMock.verify()
    })

    it('should handle error when getting all orders', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let capturedError: any
        service.getAll().subscribe({ next: () => { }, error: (e) => { capturedError = e } })
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/orders')
        req.flush(null, { status: 404, statusText: 'Not Found' })
        expect(capturedError).toBeTruthy()
        expect(capturedError.status).toBe(404)
        httpMock.verify()
    })

    it('should handle error when toggling delivery status', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)

        let capturedError: any
        service.toggleDeliveryStatus(1, {}).subscribe({ next: () => { }, error: (e) => { capturedError = e } })
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/1/delivery-status')
        req.flush(null, { status: 400, statusText: 'Bad Request' })
        expect(capturedError).toBeTruthy()
        expect(capturedError.status).toBe(400)
        httpMock.verify()
    })

    it('should open order confirmation PDF fetched from the api in a new window', () => {
        vi.useFakeTimers()
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)
        const confirmationWindow = { location: { href: '' }, close: vi.fn() }
        window.open = vi.fn().mockReturnValue(confirmationWindow)
        URL.createObjectURL = vi.fn().mockReturnValue('blob:confirmation')
        URL.revokeObjectURL = vi.fn()

        service.openConfirmation('ad9b-96017e7cb1ae7bf9')
        expect(window.open).toHaveBeenCalledWith('', '_blank')
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/ad9b-96017e7cb1ae7bf9/confirmation')
        expect(req.request.responseType).toBe('blob')
        req.flush(new Blob(['%PDF'], { type: 'application/pdf' }))
        expect(confirmationWindow.location.href).toBe('blob:confirmation')
        vi.advanceTimersByTime(60000)
        expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:confirmation')
        httpMock.verify()
        vi.useRealTimers()
    })

    it('should close the new window when order confirmation cannot be fetched', () => {
        const service = TestBed.inject(OrderHistoryService)
        const httpMock = TestBed.inject(HttpTestingController)
        const confirmationWindow = { location: { href: '' }, close: vi.fn() }
        window.open = vi.fn().mockReturnValue(confirmationWindow)
        console.log = vi.fn()

        service.openConfirmation('ad9b-96017e7cb1ae7bf9')
        httpMock.expectOne('http://localhost:3000/rest/order-history/ad9b-96017e7cb1ae7bf9/confirmation').flush(null, { status: 404, statusText: 'Not Found' })
        expect(confirmationWindow.close).toHaveBeenCalled()
        expect(console.log).toHaveBeenCalled()
        httpMock.verify()
    })
})
