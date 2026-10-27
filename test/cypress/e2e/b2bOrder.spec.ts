describe('/b2b/v2/order', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  const postOrder = (orderLinesData: string) => {
    return cy.window().then(async () => {
      return await fetch(`${Cypress.config('baseUrl')}/b2b/v2/orders/`, {
        method: 'POST',
        cache: 'no-cache',
        headers: {
          'Content-type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ cid: 'JS0815DE', orderLinesData })
      })
    })
  }

  it('should reject an infinite loop payload instead of evaluating it', () => {
    postOrder('(function dos() { while(true); })()').its('status').should('eq', 400)
  })

  it('should reject a recursive regular expression payload instead of evaluating it', () => {
    postOrder("/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')").its('status').should('eq', 400)
  })

  it('should accept JSON order lines as data', () => {
    postOrder('[{"productId": 12, "quantity": 10000, "customerReference": "PO0000001.2"}]').its('status').should('eq', 200)
  })
})
