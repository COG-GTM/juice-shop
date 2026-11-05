/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { BasketService } from './basket.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('BasketService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            providers: [BasketService, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const service = TestBed.inject(BasketService)

        expect(service).toBeTruthy()
    })

    it('should get basket directly from the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.find(1).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/basket/1')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should get order confirmation PDF from the authenticated rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.getOrderConfirmation('5267-f9cd5882f54c75a3').subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/order-history/5267-f9cd5882f54c75a3/confirmation')
        const pdf = new Blob(['%PDF'], { type: 'application/pdf' })
        req.flush(pdf)
        expect(req.request.method).toBe('GET')
        expect(req.request.responseType).toBe('blob')
        expect(res).toEqual(pdf)
        httpMock.verify()
    })

    it('should open the order confirmation tab synchronously and navigate it to the PDF', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)
        const confirmationWindow = { location: { href: '' }, close: vi.fn() }
        const openSpy = vi.spyOn(window, 'open').mockReturnValue(confirmationWindow as any)
        vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:http://localhost/pdf')

        service.openOrderConfirmation('5267-f9cd5882f54c75a3')
        expect(openSpy).toHaveBeenCalledWith('', '_blank')
        httpMock.expectOne('http://localhost:3000/rest/order-history/5267-f9cd5882f54c75a3/confirmation').flush(new Blob(['%PDF'], { type: 'application/pdf' }))
        expect(confirmationWindow.location.href).toBe('blob:http://localhost/pdf')
        httpMock.verify()
        vi.restoreAllMocks()
    })

    it('should close the order confirmation tab when the PDF cannot be retrieved', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)
        const confirmationWindow = { location: { href: '' }, close: vi.fn() }
        vi.spyOn(window, 'open').mockReturnValue(confirmationWindow as any)

        service.openOrderConfirmation('5267-f9cd5882f54c75a3')
        httpMock.expectOne('http://localhost:3000/rest/order-history/5267-f9cd5882f54c75a3/confirmation').flush(new Blob(), { status: 404, statusText: 'Not Found' })
        expect(confirmationWindow.close).toHaveBeenCalled()
        httpMock.verify()
        vi.restoreAllMocks()
    })

    it('should get single basket item directly from the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.get(1).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/BasketItems/1')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('GET')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should create basket item directly from the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.save().subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/BasketItems/')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('POST')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should update basket item directly from the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.put(1, {}).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/BasketItems/1')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('PUT')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should delete basket item directly from the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.del(1).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/api/BasketItems/1')
        req.flush({ data: 'apiResponse' })
        expect(req.request.method).toBe('DELETE')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should place order for basket via the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.checkout(1).subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/basket/1/checkout')
        req.flush({ orderConfirmation: 'apiResponse' })
        expect(req.request.method).toBe('POST')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should apply coupon to basket via the rest api', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        let res: any
        service.applyCoupon(1, '1234567890').subscribe((data) => (res = data))
        const req = httpMock.expectOne('http://localhost:3000/rest/basket/1/coupon/1234567890')
        req.flush({ discount: 'apiResponse' })
        expect(req.request.method).toBe('PUT')
        expect(res).toBe('apiResponse')
        httpMock.verify()
    })

    it('should emit total number of items when updating number of cart items', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        localStorage.setItem('token', 'token')
        sessionStorage.setItem('bid', '42')
        const totals: number[] = []
        service.getItemTotal().subscribe((t) => totals.push(t))

        service.updateNumberOfCartItems()
        const req = httpMock.expectOne('http://localhost:3000/rest/basket/42')
        expect(req.request.method).toBe('GET')
        req.flush({
            data: {
                Products: [
                    { BasketItem: { quantity: 2 } },
                    { BasketItem: { quantity: 3 } }
                ]
            }
        })
        expect(totals).toEqual([5])
        localStorage.removeItem('token')
        httpMock.verify()
    })

    it('should log error when updating number of cart items fails', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        localStorage.setItem('token', 'token')
        sessionStorage.setItem('bid', '99')
        const consoleSpy = vi.spyOn(console, 'log')
        consoleSpy.mockClear()

        service.updateNumberOfCartItems()
        const req = httpMock.expectOne('http://localhost:3000/rest/basket/99')
        req.error(new ErrorEvent('Request failed'), { status: 500, statusText: 'Internal Error' })

        expect(consoleSpy).toHaveBeenCalled()
        localStorage.removeItem('token')
        httpMock.verify()
    })

    it('should emit total number of guest basket items when anonymous', () => {
        const service = TestBed.inject(BasketService)

        localStorage.removeItem('token')
        sessionStorage.setItem('guestBasket', JSON.stringify([
            { ProductId: 1, quantity: 2 },
            { ProductId: 2, quantity: 3 }
        ]))

        const totals: number[] = []
        service.getItemTotal().subscribe((t) => totals.push(t))
        service.updateNumberOfCartItems()

        expect(totals).toEqual([5])
        sessionStorage.removeItem('guestBasket')
    })

    it('should silently drop malformed guest basket items', () => {
        const service = TestBed.inject(BasketService)

        sessionStorage.setItem('guestBasket', JSON.stringify([
            { ProductId: 1, quantity: 2 },
            { ProductId: '2', quantity: '3' },
            { ProductId: 0, quantity: 5 },
            { ProductId: 5, quantity: -1 },
            { ProductId: null, quantity: 4 },
            { foo: 'bar' }
        ]))

        expect(service.getGuestBasketItems()).toEqual([
            { ProductId: 1, quantity: 2 },
            { ProductId: 2, quantity: 3 }
        ])
        sessionStorage.removeItem('guestBasket')
    })

    it('should merge guest basket as best effort and continue on item errors', () => {
        const service = TestBed.inject(BasketService)
        const httpMock = TestBed.inject(HttpTestingController)

        localStorage.removeItem('token')
        sessionStorage.setItem('guestBasket', JSON.stringify([
            { ProductId: 1, quantity: 2 },
            { ProductId: 1, quantity: 1 },
            { ProductId: 2, quantity: 3 }
        ]))

        let completed = false
        service.mergeGuestBasketIntoUserBasket(42).subscribe(() => {
            completed = true
        })

        const findReq = httpMock.expectOne('http://localhost:3000/rest/basket/42')
        findReq.flush({
            data: {
                Products: [
                    { id: 1, BasketItem: { id: 100, quantity: 4 } }
                ]
            }
        })

        const putReq = httpMock.expectOne('http://localhost:3000/api/BasketItems/100')
        expect(putReq.request.method).toBe('PUT')
        expect(putReq.request.body).toEqual({ quantity: 7 })
        putReq.error(new ErrorEvent('Merge failed'), { status: 500, statusText: 'Internal Error' })

        const postReq = httpMock.expectOne('http://localhost:3000/api/BasketItems/')
        expect(postReq.request.method).toBe('POST')
        expect(postReq.request.body).toEqual({ ProductId: 2, BasketId: 42, quantity: 3 })
        postReq.flush({ data: {} })

        expect(completed).toBe(true)
        expect(sessionStorage.getItem('guestBasket')).toBeNull()
        httpMock.verify()
    })
})
