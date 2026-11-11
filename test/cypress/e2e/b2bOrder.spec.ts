describe('/b2b/v2/order', () => {
  for (const orderLinesData of [
    '(function dos() { while(true); })()',
    "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
  ]) {
    it(`should reject non-JSON order lines data "${orderLinesData}" without evaluating it`, () => {
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
  }
})
