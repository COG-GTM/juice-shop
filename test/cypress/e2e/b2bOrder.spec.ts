describe('/b2b/v2/order', () => {
  const postOrderLinesData = (orderLinesData: string) => cy.window().then(async () => {
    return await fetch(
      `${Cypress.config('baseUrl')}/b2b/v2/orders/`,
      {
        method: 'POST',
        cache: 'no-cache',
        headers: {
          'Content-type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ orderLinesData })
      }
    ).then(response => response.status)
  })

  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  it('should reject an infinite loop payload without executing it', () => {
    postOrderLinesData('(function dos() { while(true); })()').should('equal', 400)
  })

  it('should reject a recursive regular expression payload without executing it', () => {
    postOrderLinesData("/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')").should('equal', 400)
  })

  it('should accept order lines as documented in Swagger', () => {
    postOrderLinesData('[{"productId": 12,"quantity": 10000}]').should('equal', 200)
  })
})
