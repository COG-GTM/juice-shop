/*!
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, inject, input } from '@angular/core'
import { BasketService } from '../Services/basket.service'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { Product, ProductTableEntry } from '../Models/product.model'
import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'
import { MatTooltip } from '@angular/material/tooltip'
import { MatButton } from '@angular/material/button'
import { MatIcon } from '@angular/material/icon'
import { ProductDetailsComponent } from '../product-details/product-details.component'
import { MatDialog } from '@angular/material/dialog'

@Component({
  selector: 'app-product',
  imports: [TranslateModule, MatCardModule, MatTooltip, MatButton, MatIcon],
  templateUrl: './product.component.html',
  styleUrl: './product.component.scss'
})
export class ProductComponent {
  private readonly basketService = inject(BasketService)
  private readonly translateService = inject(TranslateService)
  private readonly snackBarHelperService = inject(SnackBarHelperService)
  private readonly dialog = inject(MatDialog)


  item = input.required<ProductTableEntry>()
  isLoggedIn = input.required<boolean>()
  isDeluxe = input.required<boolean>()

  addToBasket() {
    const { id, name: productName } = this.item()
    if (id == null) {
      return
    }

    if (!this.isLoggedIn()) {
      this.basketService.addToGuestBasket(id)
      this.confirm('BASKET_ADD_PRODUCT', productName, false)
      return
    }

    this.basketService.find(Number(sessionStorage.getItem('bid'))).subscribe({
      next: (basket) => {
        const productsInBasket: any = basket.Products
        const existingBasketItem = productsInBasket.find((product) => product.id === id)?.BasketItem
        if (existingBasketItem) {
          this.basketService
            .put(existingBasketItem.id, { quantity: existingBasketItem.quantity + 1 })
            .subscribe({
              next: () => {
                this.confirm('BASKET_ADD_SAME_PRODUCT', productName, true)
              },
              error: (err) => {
                this.snackBarHelperService.open(err.error?.error, 'errorBar')
                console.log(err)
              }
            })
        } else {
          this.basketService
            .save({
              ProductId: id,
              BasketId: sessionStorage.getItem('bid'),
              quantity: 1
            })
            .subscribe({
              next: () => {
                this.confirm('BASKET_ADD_PRODUCT', productName, true)
              },
              error: (err) => {
                this.snackBarHelperService.open(err.error?.error, 'errorBar')
                console.log(err)
              }
            })
        }
      },
      error: (err) => {
        console.log(err)
      }
    })
  }

  private confirm(translationKey: string, productName: string, updateCartItems: boolean) {
    this.translateService
      .get(translationKey, { product: productName })
      .subscribe({
        next: (message) => {
          this.snackBarHelperService.open(message, 'confirmBar')
          if (updateCartItems) this.basketService.updateNumberOfCartItems()
        },
        error: (translationId) => {
          this.snackBarHelperService.open(translationId, 'confirmBar')
          if (updateCartItems) this.basketService.updateNumberOfCartItems()
        }
      })
  }

  showDetail(product: Product) {
    this.dialog.open(ProductDetailsComponent, {
      width: '500px',
      height: 'max-content',
      data: {
        productData: product
      }
    })
  }
}
