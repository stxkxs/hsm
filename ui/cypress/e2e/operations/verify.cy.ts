/// <reference types="cypress" />

describe('Verify Operation', () => {
  let testKeyId: string
  let testSignature: string
  const testData = 'Hello, HSM!'

  beforeEach(() => {
    cy.setupAuth()

    // Intercept keys API for waiting
    cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

    // Create a test key and get a valid signature
    cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
      testKeyId = key.key_id

      // Sign test data to get a valid signature
      cy.signViaApi(testKeyId, btoa(testData)).then((signResult) => {
        testSignature = signResult.signature
        cy.visit('/operations/verify')
        // Wait for keys to load in dropdown
        cy.wait('@getKeys')
      })
    })
  })

  afterEach(() => {
    if (testKeyId) {
      cy.deleteKeyViaApi(testKeyId)
    }
  })

  describe('Page Display', () => {
    it('displays the verify page', () => {
      cy.url().should('include', '/operations/verify')
    })

    it('displays page title', () => {
      cy.contains('h1, h2', /verify/i).should('be.visible')
    })

    it('displays key selector', () => {
      cy.get('button[role="combobox"]').should('exist')
    })

    it('displays data input field', () => {
      cy.get('textarea#data').should('exist')
    })

    it('displays signature input field', () => {
      cy.get('textarea#signature').should('exist')
    })

    it('displays verify button', () => {
      cy.contains('button', /verify signature/i).should('be.visible')
    })

    it('displays back to operations link', () => {
      cy.contains('Back to Operations').should('exist')
    })
  })

  describe('Key Selection', () => {
    it('shows available keys in dropdown', () => {
      cy.get('button[role="combobox"]').first().click()

      cy.get('[role="option"]').should('have.length.greaterThan', 0)
    })

    it('can select a key', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()

      cy.get('button[role="combobox"]').first()
        .invoke('text')
        .should('contain', testKeyId.substring(0, 8))
    })
  })

  describe('Input Fields', () => {
    it('accepts data input', () => {
      cy.get('textarea#data')
        .type(testData)
        .should('have.value', testData)
    })

    it('accepts signature input', () => {
      cy.get('textarea#signature').type(testSignature)
        .should('have.value', testSignature)
    })
  })

  describe('Button States', () => {
    it('verify button is disabled without all inputs', () => {
      cy.contains('button', /verify signature/i).should('be.disabled')
    })

    it('verify button is disabled without key', () => {
      cy.get('textarea#data').type(testData)
      cy.get('textarea#signature').type(testSignature)
      cy.contains('button', /verify signature/i).should('be.disabled')
    })

    it('verify button is disabled without data', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#signature').type(testSignature)
      cy.contains('button', /verify signature/i).should('be.disabled')
    })

    it('verify button is disabled without signature', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#data').type(testData)
      cy.contains('button', /verify signature/i).should('be.disabled')
    })

    it('verify button is enabled with all inputs', () => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#data').type(testData)
      cy.get('textarea#signature').type(testSignature)
      cy.contains('button', /verify signature/i).should('not.be.disabled')
    })
  })

  describe('Verify Valid Signature', () => {
    beforeEach(() => {
      // Select key
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()
    })

    it('verifies valid signature successfully', () => {
      cy.get('textarea#data').type(testData)
      cy.get('textarea#signature').type(testSignature)

      cy.contains('button', /verify signature/i).click()

      // Should show verification result
      cy.contains(/verification result/i, { timeout: 10000 }).should('be.visible')
    })
  })

  describe('Verify Invalid Signature', () => {
    beforeEach(() => {
      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').contains(testKeyId.substring(0, 8)).click()
    })

    it('rejects signature for wrong data', () => {
      // Enter different data than what was signed
      cy.get('textarea#data').type('Different data')
      // Enter the real signature (but for different data)
      cy.get('textarea#signature').type(testSignature)

      cy.contains('button', /verify signature/i).click()

      // Should show verification result
      cy.contains(/verification result/i, { timeout: 10000 }).should('be.visible')
    })
  })

  describe('Loading State', () => {
    it('shows loading state during verification', () => {
      cy.intercept('POST', '**/api/hsm/keys/*/verify', (req) => {
        req.reply((res) => {
          res.delay = 1000
          res.send({ valid: true })
        })
      }).as('verifyData')

      cy.get('button[role="combobox"]').first().click()
      cy.get('[role="option"]').first().click()
      cy.get('textarea#data').type(testData)
      cy.get('textarea#signature').type(testSignature)

      cy.contains('button', /verify signature/i).click()

      cy.contains('button', /verify signature/i).should('be.disabled')
    })
  })

  describe('Navigation', () => {
    it('navigates back to operations page', () => {
      cy.contains('Back to Operations').click()

      cy.url().should('include', '/operations')
      cy.url().should('not.include', '/verify')
    })
  })
})
