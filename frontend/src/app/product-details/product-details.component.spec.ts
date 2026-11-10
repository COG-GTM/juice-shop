/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { provideZoneChangeDetection } from '@angular/core'
import { TranslateModule } from '@ngx-translate/core'
import { ProductReviewEditComponent } from '../product-review-edit/product-review-edit.component'
import { By } from '@angular/platform-browser'
import { MatDividerModule } from '@angular/material/divider'
import { UserService } from '../Services/user.service'
import { ProductReviewService } from '../Services/product-review.service'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { MatButtonModule } from '@angular/material/button'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MAT_DIALOG_DATA, MatDialog, MatDialogModule } from '@angular/material/dialog'
import { MatBadgeModule } from '@angular/material/badge'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { MatTooltipModule } from '@angular/material/tooltip'
import { MatIconModule } from '@angular/material/icon'
import { MatExpansionModule } from '@angular/material/expansion'

import { ProductDetailsComponent } from './product-details.component'
import { of, Subject, throwError } from 'rxjs'
import { ReactiveFormsModule } from '@angular/forms'
import { MatSnackBarModule } from '@angular/material/snack-bar'
import { type Product } from '../Models/product.model'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { CookieService } from 'ngy-cookie'

describe('ProductDetailsComponent', () => {
    let component: ProductDetailsComponent
    let fixture: ComponentFixture<ProductDetailsComponent>
    let userService: any
    let productReviewService: any
    let dialog: any
    let cookieService: any
    let dialogRefMock

    beforeEach(async () => {
        userService = {
            whoAmI: vi.fn().mockName("UserService.whoAmI"),
            isLoggedIn: new Subject()
        }
        userService.whoAmI.mockReturnValue(of({}))
        productReviewService = {
            get: vi.fn().mockName("ProductReviewService.get"),
            create: vi.fn().mockName("ProductReviewService.create")
        }
        productReviewService.get.mockReturnValue(of([]))
        productReviewService.create.mockReturnValue(of({}))
        cookieService = {
            remove: vi.fn().mockName("CookieService.remove")
        }
        dialog = {
            open: vi.fn().mockName("Dialog.open")
        }
        dialogRefMock = {
            afterClosed: () => of({})
        }
        dialog.open.mockReturnValue(dialogRefMock)

        TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                ReactiveFormsModule,
                MatDialogModule,
                MatFormFieldModule,
                MatInputModule,
                MatButtonModule,
                MatDividerModule,
                MatBadgeModule,
                MatIconModule,
                MatTooltipModule,
                MatExpansionModule,
                MatSnackBarModule,
                ProductDetailsComponent],
            providers: [
                { provide: UserService, useValue: userService },
                { provide: ProductReviewService, useValue: productReviewService },
                { provide: MatDialog, useValue: dialog },
                { provide: CookieService, useValue: cookieService },
                { provide: MAT_DIALOG_DATA, useValue: { productData: {} } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting(),
                provideZoneChangeDetection()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(ProductDetailsComponent)
        component = fixture.componentInstance
        fixture.autoDetectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should post anonymous review if no user email is returned', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({}))
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        const reviewObject = { message: 'Great product!', author: 'Anonymous' }
        expect(vi.mocked(productReviewService.create).mock.calls.length).toBe(1)
        expect(vi.mocked(productReviewService.create).mock.calls[0][0]).toBe(42)
        expect(vi.mocked(productReviewService.create).mock.calls[0][1]).toEqual(reviewObject)
    })

    it('should post review with user email as author', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({ email: 'horst@juice-sh.op' }))
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        const reviewObject = { message: 'Great product!', author: 'horst@juice-sh.op' }
        expect(vi.mocked(productReviewService.create).mock.calls.length).toBe(1)
        expect(vi.mocked(productReviewService.create).mock.calls[0][0]).toBe(42)
        expect(vi.mocked(productReviewService.create).mock.calls[0][1]).toEqual(reviewObject)
    })

    it('should log errors when retrieving user directly to browser console', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(throwError('Error'))
        console.log = vi.fn()
        component.ngOnInit()
        expect(console.log).toHaveBeenCalledWith('Error')
    })

    it('should log errors when posting review directly to browser console', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({}))
        productReviewService.create.mockReturnValue(throwError('Error'))
        console.log = vi.fn()
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        expect(console.log).toHaveBeenCalledWith('Error')
        fixture.destroy()
    })

    it('should keep the review text when posting fails', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({}))
        productReviewService.create.mockReturnValue(throwError(() => ({ status: 401 })))
        console.log = vi.fn()
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        expect(textArea.value).toBe('Great product!')
    })

    it('should log out and show an error when posting fails with 401', () => {
        component.data = { productData: { id: 42 } as Product }
        productReviewService.create.mockReturnValue(throwError(() => ({ status: 401 })))
        const snackBarHelper = TestBed.inject(SnackBarHelperService)
        vi.spyOn(snackBarHelper, 'open')
        localStorage.setItem('token', 'expired')
        console.log = vi.fn()
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        component.addReview(textArea)
        expect(localStorage.getItem('token')).toBeNull()
        expect(cookieService.remove).toHaveBeenCalledWith('token')
        expect(snackBarHelper.open).toHaveBeenCalledWith('UNAUTHORIZED_ACCESS_ERROR', 'errorBar')
        expect(snackBarHelper.open).not.toHaveBeenCalledWith('CONFIRM_REVIEW_SAVED')
    })

    it('should show the server error message when posting fails otherwise', () => {
        component.data = { productData: { id: 42 } as Product }
        productReviewService.create.mockReturnValue(throwError(() => ({ status: 429, error: { message: 'Too many reviews, please try again later' } })))
        const snackBarHelper = TestBed.inject(SnackBarHelperService)
        vi.spyOn(snackBarHelper, 'open')
        console.log = vi.fn()
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        component.addReview(textArea)
        expect(snackBarHelper.open).toHaveBeenCalledWith('Too many reviews, please try again later', 'errorBar')
        expect(textArea.value).toBe('Great product!')
    })

    it('should clear the review text after posting succeeds', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({}))
        productReviewService.create.mockReturnValue(of({}))
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        expect(textArea.value).toBe('')
    })

    it('should refresh reviews after posting a review', () => {
        component.data = { productData: { id: 42 } as Product }
        productReviewService.create.mockReturnValue(of({}))
        productReviewService.get.mockReturnValue(of([{ id: '42', message: 'Review 1', author: 'Anonymous' }]))
        userService.whoAmI.mockReturnValue(of({}))
        component.ngOnInit()
        const textArea: HTMLTextAreaElement = fixture.debugElement.query(By.css('textarea')).nativeElement
        textArea.value = 'Great product!'
        const buttonDe = fixture.debugElement.query(By.css('#submitButton'))
        buttonDe.triggerEventHandler('click', null)
        expect(productReviewService.create).toHaveBeenCalled()
        expect(productReviewService.get).toHaveBeenCalled()
    })

    it('should open a modal dialog with review editor', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({ email: 'horst@juice-sh.op' }))
        productReviewService.get.mockReturnValue(of([{ id: '42', message: 'Great product!', author: 'horst@juice-sh.op' }]))
        component.ngOnInit()
        fixture.detectChanges()
        const buttonDe = fixture.debugElement.query(By.css('div.review-text'))
        buttonDe.triggerEventHandler('click', null)
        expect(vi.mocked(dialog.open).mock.calls.length).toBe(1)
        expect(vi.mocked(dialog.open).mock.calls[0][0]).toBe(ProductReviewEditComponent)
        expect(vi.mocked(dialog.open).mock.calls[0][1].data).toEqual({ reviewData: { id: '42', message: 'Great product!', author: 'horst@juice-sh.op' } })
    })

    it('should refresh reviews of product after editing a review', () => {
        component.data = { productData: { id: 42 } as Product }
        userService.whoAmI.mockReturnValue(of({ email: 'horst@juice-sh.op' }))
        productReviewService.get.mockReturnValue(of([{ id: '42', message: 'Great product!', author: 'horst@juice-sh.op' }]))
        component.ngOnInit()
        fixture.detectChanges()
        const buttonDe = fixture.debugElement.query(By.css('div.review-text'))
        buttonDe.triggerEventHandler('click', null)
        expect(productReviewService.get).toHaveBeenCalledWith(42)
    })
})
