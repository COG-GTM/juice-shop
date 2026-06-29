describe('/b2b/v2/order', () => {
  describe('challenge "rce"', () => {
    it('rejects an infinite loop deserialization payload without bringing down the server', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
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

            expect(response.status).to.eq(400)

            const followUpResponse = await fetch(
              `${Cypress.config('baseUrl')}/b2b/v2/orders/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json',
                  Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                  orderLinesData: '[{"productId":12,"quantity":10000}]'
                })
              }
            )

            expect(followUpResponse.status).to.eq(200)
          })
        }
      })
    })
  })

  describe('challenge "rceOccupy"', () => {
    it('rejects a recursive regular expression payload without timing out the server', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
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

            expect(response.status).to.eq(400)

            const followUpResponse = await fetch(
              `${Cypress.config('baseUrl')}/b2b/v2/orders/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json',
                  Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                  orderLinesData: '[{"productId":12,"quantity":10000}]'
                })
              }
            )

            expect(followUpResponse.status).to.eq(200)
          })
        }
      })
    })
  })
})
