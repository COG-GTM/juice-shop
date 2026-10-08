describe('/b2b/v2/order', () => {
  describe('challenge "rce"', () => {
    it('an infinite loop deserialization payload should be rejected without being evaluated', () => {
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
            body: JSON.stringify({
              orderLinesData: '(function dos() { while(true); })()'
            })
          }
        )
        expect(response.status).to.equal(400)
      })
    })
  })

  describe('challenge "rceOccupy"', () => {
    it('a recursive regular expression payload should be rejected without occupying the server', () => {
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
            body: JSON.stringify({
              orderLinesData:
                "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
            })
          }
        )
        expect(response.status).to.equal(400)
      })
    })
  })
})
