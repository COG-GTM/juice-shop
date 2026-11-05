describe('/b2b/v2/order', () => {
  it('should reject code in orderLinesData without executing it', () => {
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
