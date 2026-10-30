describe('/b2b/v2/order', () => {
  const payloads = [
    '(function dos() { while(true); })()',
    "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
    'this.constructor.constructor("return process")().exit()'
  ]

  payloads.forEach((orderLinesData) => {
    it(`should reject non-JSON orderLinesData without evaluating it: ${orderLinesData}`, () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then(async () => {
        const response = await fetch(
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
        )
        expect(response.status).to.equal(400)
      })
    })
  })
})
