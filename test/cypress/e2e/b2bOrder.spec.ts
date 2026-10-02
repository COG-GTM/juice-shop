describe('/b2b/v2/order', () => {
  describe('code payloads in "orderLinesData"', () => {
    it('should be rejected without being evaluated', () => {
      cy.login({ email: 'admin', password: 'admin123' })

      cy.window().then(async () => {
        for (const orderLinesData of ['(function dos() { while(true); })()', "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"]) {
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
        }
      })
    })
  })
})
