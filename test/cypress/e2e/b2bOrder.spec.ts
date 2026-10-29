describe('/b2b/v2/order', () => {
  const payloads = [
    '(function dos() { while(true); })()',
    "/((a+)+)b/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaa')"
  ]

  payloads.forEach((orderLinesData) => {
    it(`should reject non-JSON "orderLinesData" payload ${orderLinesData}`, () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then((win) => {
        cy.request({
          method: 'POST',
          url: '/b2b/v2/orders/',
          failOnStatusCode: false,
          headers: {
            'Content-type': 'application/json',
            Authorization: `Bearer ${win.localStorage.getItem('token')}`
          },
          body: { orderLinesData }
        }).its('status').should('eq', 400)
      })
    })
  })
})
