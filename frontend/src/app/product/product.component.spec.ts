/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { MatDialog } from '@angular/material/dialog'
import { of, throwError } from 'rxjs'
import { provideZoneChangeDetection } from '@angular/core'

import { ProductComponent } from './product.component'
import { ProductDetailsComponent } from '../product-details/product-details.component'
import { type Product, type ProductTableEntry } from '../Models/product.model'
import { ProductService } from '../Services/product.service'
import { BasketService } from '../Services/basket.service'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'

describe('ProductComponent', () => {
    let component: ProductComponent
    let fixture: ComponentFixture<ProductComponent>
    let productService: any
    let basketService: any
    let translateService: TranslateService
    let translateServiceGetSpy: any
    let dialog: any
    let snackBarHelper: any

    const testProduct: ProductTableEntry = {
        id: 1,
        name: 'Apple Juice',
        description: 'test product',
        image: 'apple_juice.jpg',
        price: 1.99,
        deluxePrice: 1.99,
        quantity: 5
    }

    beforeEach(async () => {
        dialog = {
            open: vi.fn().mockName("MatDialog.open")
        }
        productService = {
            search: vi.fn().mockName("ProductService.search"),
            get: vi.fn().mockName("ProductService.get")
        }
        productService.search.mockReturnValue(of([]))
        productService.get.mockReturnValue(of({ name: 'test' } as any))
        basketService = {
            find: vi.fn().mockName("BasketService.find"),
            get: vi.fn().mockName("BasketService.get"),
            put: vi.fn().mockName("BasketService.put"),
            save: vi.fn().mockName("BasketService.save"),
            updateNumberOfCartItems: vi.fn().mockName("BasketService.updateNumberOfCartItems")
        }
        basketService.find.mockReturnValue(of({ Products: [] } as any))
        basketService.get.mockReturnValue(of({ id: 1, quantity: 1 } as any))
        basketService.put.mockReturnValue(of({ ProductId: 1 } as any))
        basketService.save.mockReturnValue(of({ ProductId: 1 } as any))
        snackBarHelper = {
            open: vi.fn().mockName("SnackBarHelperService.open")
        }

        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), ProductComponent],
            providers: [
                { provide: MatDialog, useValue: dialog },
                { provide: ProductService, useValue: productService },
                { provide: BasketService, useValue: basketService },
                { provide: SnackBarHelperService, useValue: snackBarHelper },
                provideZoneChangeDetection(),
            ]
        })
            .compileComponents()

        translateService = TestBed.inject(TranslateService)
        translateServiceGetSpy = vi.spyOn(translateService, 'get').mockReturnValue(of('ok'))

        fixture = TestBed.createComponent(ProductComponent)
        component = fixture.componentInstance
        fixture.componentRef.setInput('item', testProduct)
        fixture.componentRef.setInput('isLoggedIn', true)
        fixture.componentRef.setInput('isDeluxe', false)
        fixture.detectChanges()
    })

    it('should open a modal dialog with product details', () => {
        component.showDetail({ id: 42 } as Product)
        expect(dialog.open).toHaveBeenCalledWith(ProductDetailsComponent, {
            width: '500px',
            height: 'max-content',
            data: {
                productData: { id: 42 }
            }
        })
    })

    it('should add new product to basket', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        basketService.save.mockReturnValue(of({ ProductId: 1 }))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(1)
        expect(basketService.find).toHaveBeenCalledWith(4711)
        expect(basketService.save).toHaveBeenCalledWith({ ProductId: 1, BasketId: '4711', quantity: 1 })
        expect(translateServiceGetSpy).toHaveBeenCalledWith('BASKET_ADD_PRODUCT', { product: 'Apple Juice' })
        expect(basketService.updateNumberOfCartItems).toHaveBeenCalled()
    })

    it('should not re-fetch product or basket item when adding new product to basket', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(1)
        expect(productService.get).not.toHaveBeenCalled()
        expect(basketService.get).not.toHaveBeenCalled()
        expect(basketService.put).not.toHaveBeenCalled()
    })

    it('should translate BASKET_ADD_PRODUCT message', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        basketService.save.mockReturnValue(of({ ProductId: 1 }))
        translateServiceGetSpy.mockReturnValue(of('Translation of BASKET_ADD_PRODUCT'))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(1)
        expect(snackBarHelper.open).toHaveBeenCalledWith('Translation of BASKET_ADD_PRODUCT', 'confirmBar')
    })

    it('should increase quantity of product already in basket using embedded basket item', () => {
        fixture.componentRef.setInput('item', { ...testProduct, id: 2, name: 'Tomato Juice' })
        basketService.find.mockReturnValue(of({ Products: [{ id: 1, BasketItem: { id: 41, quantity: 1 } }, { id: 2, name: 'Tomato Juice', BasketItem: { id: 42, quantity: 5 } }] }))
        basketService.put.mockReturnValue(of({ ProductId: 2 }))
        translateServiceGetSpy.mockReturnValue(of(undefined))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(2)
        expect(basketService.find).toHaveBeenCalled()
        expect(basketService.put).toHaveBeenCalledWith(42, { quantity: 6 })
        expect(basketService.get).not.toHaveBeenCalled()
        expect(basketService.save).not.toHaveBeenCalled()
        expect(productService.get).not.toHaveBeenCalled()
        expect(translateServiceGetSpy).toHaveBeenCalledWith('BASKET_ADD_SAME_PRODUCT', { product: 'Tomato Juice' })
        expect(basketService.updateNumberOfCartItems).toHaveBeenCalled()
    })

    it('should translate BASKET_ADD_SAME_PRODUCT message', () => {
        basketService.find.mockReturnValue(of({ Products: [{ id: 2, name: 'Tomato Juice', BasketItem: { id: 42, quantity: 5 } }] }))
        basketService.put.mockReturnValue(of({ ProductId: 2 }))
        translateServiceGetSpy.mockReturnValue(of('Translation of BASKET_ADD_SAME_PRODUCT'))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(2)
        expect(snackBarHelper.open).toHaveBeenCalledWith('Translation of BASKET_ADD_SAME_PRODUCT', 'confirmBar')
    })

    it('should show translation id when translating confirmation fails', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        translateServiceGetSpy.mockReturnValue(throwError(() => 'BASKET_ADD_PRODUCT'))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(1)
        expect(snackBarHelper.open).toHaveBeenCalledWith('BASKET_ADD_PRODUCT', 'confirmBar')
        expect(basketService.updateNumberOfCartItems).toHaveBeenCalled()
    })

    it('should add product to guest basket without any HTTP request when not logged in', () => {
        basketService.addToGuestBasket = vi.fn().mockName('BasketService.addToGuestBasket')
        fixture.componentRef.setInput('isLoggedIn', false)
        translateServiceGetSpy.mockReturnValue(of('Translation of BASKET_ADD_PRODUCT'))
        component.addToBasket(1)
        expect(basketService.addToGuestBasket).toHaveBeenCalledWith(1)
        expect(productService.get).not.toHaveBeenCalled()
        expect(basketService.find).not.toHaveBeenCalled()
        expect(translateServiceGetSpy).toHaveBeenCalledWith('BASKET_ADD_PRODUCT', { product: 'Apple Juice' })
        expect(snackBarHelper.open).toHaveBeenCalledWith('Translation of BASKET_ADD_PRODUCT', 'confirmBar')
    })

    it('should not add anything to basket on error retrieving basket', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        basketService.find.mockReturnValue(throwError(() => 'Error'))
        sessionStorage.setItem('bid', '815')
        component.addToBasket(undefined)
        expect(snackBarHelper.open).not.toHaveBeenCalled()
    })

    it('should log errors retrieving basket directly to browser console', () => {
        basketService.find.mockReturnValue(throwError(() => 'Error'))
        sessionStorage.setItem('bid', '815')
        console.log = vi.fn()
        component.addToBasket(2)
        expect(console.log).toHaveBeenCalledWith('Error')
        expect(basketService.put).not.toHaveBeenCalled()
        expect(basketService.save).not.toHaveBeenCalled()
    })

    it('should log errors updating basket directly to browser console', () => {
        basketService.find.mockReturnValue(of({ Products: [{ id: 1 }, { id: 2, name: 'Tomato Juice', BasketItem: { id: 42, quantity: 5 } }] }))
        basketService.put.mockReturnValue(throwError(() => 'Error'))
        sessionStorage.setItem('bid', '4711')
        console.log = vi.fn()
        component.addToBasket(2)
        expect(console.log).toHaveBeenCalledWith('Error')
        expect(basketService.updateNumberOfCartItems).not.toHaveBeenCalled()
    })

    it('should show server error when updating basket item fails', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        basketService.find.mockReturnValue(of({ Products: [{ id: 2, name: 'Tomato Juice', BasketItem: { id: 42, quantity: 5 } }] }))
        basketService.put.mockReturnValue(throwError(() => ({ error: { error: 'You can order only up to 5 items of this product.' } })))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(2)
        expect(snackBarHelper.open).toHaveBeenCalledWith('You can order only up to 5 items of this product.', 'errorBar')
    })

    it('should not add anything on error creating new basket item', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        basketService.save.mockReturnValue(throwError(() => 'Error'))
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(2)
        expect(snackBarHelper.open).toHaveBeenCalled()
        expect(basketService.updateNumberOfCartItems).not.toHaveBeenCalled()
    })

    it('should log errors creating new basket item directly to browser console', () => {
        basketService.find.mockReturnValue(of({ Products: [] }))
        basketService.save.mockReturnValue(throwError(() => 'Error'))
        console.log = vi.fn()
        sessionStorage.setItem('bid', '4711')
        component.addToBasket(2)
        expect(console.log).toHaveBeenCalledWith('Error')
    })
})
