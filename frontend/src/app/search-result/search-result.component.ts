/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* eslint-disable @typescript-eslint/prefer-for-of */
import { ActivatedRoute, Router } from '@angular/router'
import { ProductService } from '../Services/product.service'
import { type AfterViewInit, Component, NgZone, type OnDestroy, ViewChild, ChangeDetectorRef, ElementRef, inject } from '@angular/core'
import { MatPaginator } from '@angular/material/paginator'
import { BehaviorSubject, forkJoin, type Subscription } from 'rxjs'
import { MatTableDataSource } from '@angular/material/table'
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser'
import { TranslateModule } from '@ngx-translate/core'
import { SocketIoService } from '../Services/socket-io.service'

import { library } from '@fortawesome/fontawesome-svg-core'
import { faCartPlus, faEye } from '@fortawesome/free-solid-svg-icons'
import { ProductTableEntry } from '../Models/product.model'
import { QuantityService } from '../Services/quantity.service'
import { DeluxeGuard } from '../app.guard'
import { MatButtonModule } from '@angular/material/button'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatSelectModule } from '@angular/material/select'
import { MatCardModule, MatCardTitle, MatCardContent } from '@angular/material/card'
import { AsyncPipe } from '@angular/common'
import { ProductComponent } from '../product/product.component'

library.add(faEye, faCartPlus)

export type ProductSortOption = 'relevance' | 'priceAsc' | 'priceDesc' | 'nameAsc'

@Component({
  selector: 'app-search-result',
  templateUrl: './search-result.component.html',
  styleUrls: ['./search-result.component.scss'],
  imports: [MatCardModule, TranslateModule, MatButtonModule, MatFormFieldModule, MatSelectModule, MatCardTitle, MatCardContent, MatPaginator, AsyncPipe, ProductComponent]
})
export class SearchResultComponent implements OnDestroy, AfterViewInit {
  private readonly deluxeGuard = inject(DeluxeGuard)
  private readonly productService = inject(ProductService)
  private readonly quantityService = inject(QuantityService)
  private readonly router = inject(Router)
  private readonly route = inject(ActivatedRoute)
  private readonly sanitizer = inject(DomSanitizer)
  private readonly ngZone = inject(NgZone)
  private readonly io = inject(SocketIoService)
  private readonly cdRef = inject(ChangeDetectorRef)
  private readonly elRef = inject(ElementRef)

  public tableData!: ProductTableEntry[]
  public pageSizeOptions: number[] = []
  public dataSource!: MatTableDataSource<ProductTableEntry>
  public gridDataSource!: BehaviorSubject<ProductTableEntry[]>
  public searchValue?: SafeHtml
  public resultsLength = 0
  public currentPageSize = 15
  @ViewChild(MatPaginator, { static: true }) paginator!: MatPaginator
  private routerSubscription?: Subscription
  private gridDataSourceSubscription?: Subscription
  private resizeObserver?: ResizeObserver
  public emptyState = false
  public sortOption: ProductSortOption = 'relevance'
  public readonly sortOptions: { value: ProductSortOption, label: string }[] = [
    { value: 'relevance', label: 'LABEL_SORT_RELEVANCE' },
    { value: 'priceAsc', label: 'LABEL_SORT_PRICE_LOW_TO_HIGH' },
    { value: 'priceDesc', label: 'LABEL_SORT_PRICE_HIGH_TO_LOW' },
    { value: 'nameAsc', label: 'LABEL_SORT_NAME_A_TO_Z' }
  ]

  // vuln-code-snippet start restfulXssChallenge
  ngAfterViewInit () {
    const products = this.productService.search('')
    const quantities = this.quantityService.getAll()
    forkJoin([quantities, products]).subscribe({
      next: ([quantities, products]) => {
        const dataTable: ProductTableEntry[] = []
        this.tableData = products
        this.trustProductDescription(products) // vuln-code-snippet neutral-line restfulXssChallenge
        for (const product of products) {
          dataTable.push({
            name: product.name,
            price: product.price,
            deluxePrice: product.deluxePrice,
            id: product.id,
            image: product.image,
            description: product.description
          })
        }
        for (const quantity of quantities) {
          const entry = dataTable.find((dataTableEntry) => {
            return dataTableEntry.id === quantity.ProductId
          })
          if (entry === undefined) {
            continue
          }
          entry.quantity = quantity.quantity
        }
        this.dataSource = new MatTableDataSource<ProductTableEntry>(dataTable)
        this.updatePageSizeOptions()
        this.dataSource.paginator = this.paginator
        this.setupResponsivePageSize()
        this.gridDataSource = this.dataSource.connect()
        this.resultsLength = this.dataSource.data.length
        this.filterTable()
        this.routerSubscription = this.router.events.subscribe(() => {
          this.filterTable()
        })
        const challenge: string = this.route.snapshot.queryParams.challenge // vuln-code-snippet hide-start
        if (challenge && this.route.snapshot.url.join('').match(/hacking-instructor/)) {
          this.startHackingInstructor(decodeURIComponent(challenge))
        } // vuln-code-snippet hide-end
        this.cdRef.detectChanges()
      },
      error: (err) => { console.log(err) }
    })
  }

  trustProductDescription (tableData: any[]) { // vuln-code-snippet neutral-line restfulXssChallenge
    for (let i = 0; i < tableData.length; i++) { // vuln-code-snippet neutral-line restfulXssChallenge
      tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description) // vuln-code-snippet vuln-line restfulXssChallenge
    } // vuln-code-snippet neutral-line restfulXssChallenge
  } // vuln-code-snippet neutral-line restfulXssChallenge

  // vuln-code-snippet end restfulXssChallenge

  ngOnDestroy () {
    if (this.routerSubscription) {
      this.routerSubscription.unsubscribe()
    }

    if (this.dataSource) {
      this.dataSource.disconnect()
    }

    if (this.gridDataSourceSubscription) {
      this.gridDataSourceSubscription.unsubscribe()
    }

    if (this.resizeObserver) {
      this.resizeObserver.disconnect()
    }
  }

  // vuln-code-snippet start localXssChallenge xssBonusChallenge
  filterTable () {
    let queryParam: string = this.route.snapshot.queryParams.q
    if (queryParam) {
      queryParam = queryParam.trim()
      this.ngZone.runOutsideAngular(() => { // vuln-code-snippet hide-start
        this.io.socket().emit('verifyLocalXssChallenge', queryParam)
      }) // vuln-code-snippet hide-end
      this.dataSource.filter = queryParam.toLowerCase()
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam) // vuln-code-snippet vuln-line localXssChallenge xssBonusChallenge
      if (this.gridDataSourceSubscription) {
        this.gridDataSourceSubscription.unsubscribe()
      }
      this.gridDataSourceSubscription = this.gridDataSource.subscribe((result: ProductTableEntry[]) => {
        if (result.length === 0) {
          this.emptyState = true
        } else {
          this.emptyState = false
        }
      })
    } else {
      this.dataSource.filter = ''
      this.searchValue = undefined
      this.emptyState = false
    }
  }
  // vuln-code-snippet end localXssChallenge xssBonusChallenge

  sortProducts (option: ProductSortOption) {
    this.sortOption = option
    if (!this.dataSource) return
    const relevanceRank = new Map((this.tableData ?? []).map((product, index) => [product.id, index]))
    const byRelevance = (a: ProductTableEntry, b: ProductTableEntry) =>
      (relevanceRank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (relevanceRank.get(b.id) ?? Number.MAX_SAFE_INTEGER)
    const compare = (a: ProductTableEntry, b: ProductTableEntry): number => {
      switch (option) {
        case 'priceAsc':
          return this.displayedPrice(a) - this.displayedPrice(b)
        case 'priceDesc':
          return this.displayedPrice(b) - this.displayedPrice(a)
        case 'nameAsc':
          return a.name.localeCompare(b.name)
        default:
          return 0
      }
    }
    this.dataSource.data = [...this.dataSource.data].sort((a, b) => compare(a, b) || byRelevance(a, b))
    this.paginator.firstPage()
  }

  private displayedPrice (product: ProductTableEntry): number {
    return this.isDeluxe() ? product.deluxePrice : product.price
  }

  private setupResponsivePageSize () {
    const grid = this.elRef.nativeElement.querySelector('.products-grid')
    if (!grid) return
    this.resizeObserver = new ResizeObserver(() => {
      this.ngZone.run(() => {
        this.updatePageSize(grid)
      })
    })
    this.resizeObserver.observe(grid)
  }

  private updatePageSize (grid: Element) {
    const columns = getComputedStyle(grid).gridTemplateColumns.split(' ').length
    const pageSize = Math.ceil(15 / columns) * columns
    if (pageSize !== this.currentPageSize) {
      this.currentPageSize = pageSize
      this.paginator.pageSize = pageSize
      this.updatePageSizeOptions()
      this.paginator.page.emit({
        pageIndex: this.paginator.pageIndex,
        pageSize: this.currentPageSize,
        length: this.paginator.length
      })
      this.cdRef.detectChanges()
    }
  }

  private updatePageSizeOptions () {
    this.pageSizeOptions = []
    for (let i = 1; i <= Math.ceil(this.dataSource.data.length / this.currentPageSize); i++) {
      this.pageSizeOptions.push(i * this.currentPageSize)
    }
    this.paginator.pageSizeOptions = this.pageSizeOptions
  }

  startHackingInstructor (challengeName: string) {
    console.log(`Starting instructions for challenge "${challengeName}"`)
    import('../../hacking-instructor').then(module => {
      module.startHackingInstructorFor(challengeName)
    })
  }

  isLoggedIn (): boolean {
    return localStorage.getItem('token') !== null
  }

  isDeluxe () {
    return this.deluxeGuard.isDeluxe()
  }
}
