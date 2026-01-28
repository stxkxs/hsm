/// <reference types="cypress" />

describe('Sign Operation', () => {
  let testKeyId: string

  beforeEach(() => {
    cy.setupAuth()

    // Intercept keys API for waiting
    cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

    // Create a test key for signing
    cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
      testKeyId = key.key_id
      cy.visit('/operations/sign')
      // Wait for keys to load in dropdown
      cy.wait('@getKeys')
    })
  })

  afterEach(() => {
    if (testKeyId) {
      cy.deleteKeyViaApi(testKeyId)
    }
  })

  describe('Page Display', () => {
    it('displays the sign page', () => {
      cy.url().should('include', '/operations/sign')
    })

    it('displays page title', () => {
      cy.contains('h1, h2', /sign/i).should('be.visible')
    })

    it('displays key selector', () => {
      cy.get('button[role="combobox"]').should('exist')
    })

    it('displays data input field', () => {
      cy.get('textarea#data').should('exist')
    })

    it('displays sign button', () => {
      cy.contains('button', /sign data/i).should('be.visible')
    })

    it('displays back to operations link', () => {
      cy.contains('Back to Operations').should('exist')
    })
  })

  describe('Key Selection', () => {
    it('shows available signing keys in dropdown', () => {
      cy.get('button[role="combobox"]').first().click()

      cy.get('[role="option"]').should('have.length.greaterThan', 0)
    })

    it('can select a key', () => {
      cy.get('button[role="combobox"]').first().click()

      cy.get('[role="option"]').first().click()

      cy.get('button[role="combobox"]').first()
        .should('not.contain.text', 'Select')
    })
  })

  describe('Data Input', () => {
    it('accepts text data input', () => {
      const testData = 'Hello, this is test data to sign'

      cy.get('textarea#data')
        .type(testData)
        .should('have.value', testData)
    })

    it('handles large data input', () => {
      const largeData = 'A'.repeat(1000)

      cy.get('textarea#data')
        .type(largeData, { delay: 0 })
        .should('have.value', largeData)
    })
  })

  describe('Sign Operation', () => {
    it('signs data successfully', () => {
      // Select the test key
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

      cy.get('textarea#data').type('Hello, HSM!')
      cy.contains('button', /sign data/i).click()

      // Should show result card with signature
      cy.contains(/signature result/i, { timeout: 10000 }).should('be.visible')
    })

    it('returns signature data', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()
      cy.get('textarea#data').type('Test message')
      cy.contains('button', /sign data/i).click()

      // Should show signature result
      cy.contains(/signature result/i, { timeout: 10000 }).should('be.visible')
    })
  })

  describe('Button States', () => {
    it('sign button is disabled without key and data', () => {
      cy.contains('button', /sign data/i).should('be.disabled')
    })

    it('sign button is disabled without key', () => {
      cy.get('textarea#data').type('Test data')
      cy.contains('button', /sign data/i).should('be.disabled')
    })

    it('sign button is disabled without data', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.contains('button', /sign data/i).should('be.disabled')
    })

    it('sign button is enabled with key and data', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#data').type('Test data')
      cy.contains('button', /sign data/i).should('not.be.disabled')
    })
  })

  describe('Loading State', () => {
    it('shows loading state during signing', () => {
      cy.intercept('POST', '**/api/hsm/keys/*/sign', (req) => {
        req.reply((res) => {
          res.delay = 1000
          res.send({
            signature: 'dGVzdHNpZ25hdHVyZQ==',
            algorithm: 'ED25519',
          })
        })
      }).as('signData')

      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#data').type('Test')
      cy.contains('button', /sign data/i).click()

      // Button should be disabled during loading
      cy.contains('button', /sign data/i).should('be.disabled')
    })
  })

  describe('Navigation', () => {
    it('navigates back to operations page', () => {
      cy.contains('Back to Operations').click()

      cy.url().should('include', '/operations')
      cy.url().should('not.include', '/sign')
    })
  })
})
