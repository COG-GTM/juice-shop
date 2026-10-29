describe('/api', () => {
  describe('product API', () => {
    it('should not be possible to create a new product even when logged in', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then(async () => {
        const response = await fetch(
          `${Cypress.config('baseUrl')}/api/Products`,
          {
            method: 'POST',
            cache: 'no-cache',
            headers: {
              'Content-type': 'application/json',
              Authorization: `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({
              name: 'RestXSS',
              description: '<iframe src="javascript:alert(`xss`)">',
              price: 47.11
            })
          }
        )
        assert.equal(response.status, 401)
      })
    })

    it('should not be possible to change a product via PUT request without being logged in', () => {
      cy.task<number>('GetTamperingProductId').then((tamperingProductId: number) => {
        cy.task<string>('GetOverwriteUrl').then((overwriteUrl: string) => {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/api/Products/${tamperingProductId}`,
              {
                method: 'PUT',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json'
                },
                body: JSON.stringify({
                  description: `<a href="${overwriteUrl}" target="_blank">More...</a>`
                })
              }
            )
            assert.equal(response.status, 401)
          })
        })
      })
    })
  })
})

describe('/rest/saveLoginIp', () => {
  describe('challenge "httpHeaderXss"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    it('should be possible to save log-in IP when logged in', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/rest/saveLoginIp`,
              {
                method: 'GET',
                cache: 'no-cache',
                headers: {
                  Authorization: `Bearer ${localStorage.getItem('token')}`,
                  'True-Client-IP': '<iframe src="javascript:alert(`xss`)">'
                }
              }
            )
            if (response.status === 200) {
              console.log('Success')
            }
          })
          cy.expectChallengeSolved({ challenge: 'HTTP-Header XSS' }) // TODO Add missing check for alert presence
        }
      })
    })
  })

  it('should not be possible to save log-in IP when not logged in', () => {
    cy.request({ url: '/rest/saveLoginIp', failOnStatusCode: false }).then(
      (response) => {
        console.log(response.body)
        expect(response.body).to.equal('Unauthorized')
      }
    )
  })
})
