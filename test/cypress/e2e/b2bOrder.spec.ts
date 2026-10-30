describe('/b2b/v2/order', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })

  for (const orderLinesData of ['(function dos() { while(true); })()', "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"]) {
    it(`should reject "${orderLinesData}" as order lines data without evaluating it`, () => {
      cy.window().then((win) => {
        cy.request({
          method: 'POST',
          url: '/b2b/v2/orders/',
          headers: { Authorization: `Bearer ${win.localStorage.getItem('token')}` },
          body: { orderLinesData },
          failOnStatusCode: false,
          timeout: 1000
        }).its('status').should('eq', 400)
      })
    })
  }
})
