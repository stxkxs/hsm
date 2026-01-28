/// <reference types="cypress" />

describe('Key List Page', () => {
  beforeEach(() => {
    cy.setupAuth()
    cy.visit('/keys')
  })

  describe('Page Display', () => {
    it('displays the keys page header', () => {
      cy.contains('h1, h2', /keys/i).should('be.visible')
    })

    it('displays Create Key button', () => {
      cy.contains('button', /create key/i).should('be.visible')
    })

    it('displays the keys table', () => {
      cy.get('table').should('exist')
    })

    it('displays refresh button with icon', () => {
      cy.get('button').find('svg.lucide-refresh-cw').should('exist')
    })
  })

  describe('Table Headers', () => {
    it('displays expected column headers', () => {
      cy.get('table thead').within(() => {
        cy.contains('Key ID').should('exist')
        cy.contains('Algorithm').should('exist')
        cy.contains('Namespace').should('exist')
        cy.contains('Status').should('exist')
        cy.contains('Created').should('exist')
      })
    })
  })

  describe('Key Display', () => {
    let testKeyId: string

    beforeEach(() => {
      // Intercept the keys API call
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

      // Create a test key
      cy.createKeyViaApi({ algorithm: 'ED25519', purpose: 'SIGN' }).then((key) => {
        testKeyId = key.key_id
        // Visit keys page
        cy.visit('/keys')
        // Wait for keys API to complete
        cy.wait('@getKeys')
        // Click refresh to ensure we have latest data
        cy.get('button').find('svg.lucide-refresh-cw').parent().click()
        cy.wait('@getKeys')
        // Wait for key to appear (UI truncates key IDs, so use first 8 chars)
        cy.contains(testKeyId.substring(0, 8), { timeout: 10000 }).should('exist')
      })
    })

    afterEach(() => {
      if (testKeyId) {
        cy.deleteKeyViaApi(testKeyId)
      }
    })

    it('displays created key in the list', () => {
      cy.contains(testKeyId.substring(0, 8)).should('be.visible')
    })

    it('displays key algorithm', () => {
      cy.contains('Ed25519').should('be.visible')
    })

    it('displays key status badge', () => {
      cy.contains(testKeyId.substring(0, 8))
        .parents('tr')
        .within(() => {
          cy.contains(/Active/i).should('exist')
        })
    })

    it('shows key namespace', () => {
      cy.contains(testKeyId.substring(0, 8))
        .parents('tr')
        .within(() => {
          cy.contains('default').should('exist')
        })
    })
  })

  describe('Search and Filter', () => {
    let testKeyId: string

    beforeEach(() => {
      // Intercept the keys API call
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

      cy.createKeyViaApi({ algorithm: 'ED25519' }).then((key) => {
        testKeyId = key.key_id
        cy.visit('/keys')
        // Wait for keys API to complete
        cy.wait('@getKeys')
        // Click refresh to ensure we have latest data
        cy.get('button').find('svg.lucide-refresh-cw').parent().click()
        cy.wait('@getKeys')
        cy.contains(testKeyId.substring(0, 8), { timeout: 10000 }).should('exist')
      })
    })

    afterEach(() => {
      if (testKeyId) {
        cy.deleteKeyViaApi(testKeyId)
      }
    })

    it('filters keys by search input', () => {
      cy.get('input[placeholder*="Search keys"]')
        .first()
        .type(testKeyId.substring(0, 8))

      cy.contains(testKeyId.substring(0, 8)).should('be.visible')
    })

    it('shows empty state for non-matching search', () => {
      cy.get('input[placeholder*="Search keys"]')
        .first()
        .type('nonexistent-key-xyz')

      // Should show "No keys found" message
      cy.contains('No keys found').should('be.visible')
    })

    it('clears filter and shows keys', () => {
      cy.get('input[placeholder*="Search keys"]')
        .first()
        .type('xyz')

      cy.contains('No keys found').should('be.visible')

      cy.get('input[placeholder*="Search keys"]')
        .first()
        .clear()

      // Key should be visible again
      cy.contains(testKeyId.substring(0, 8)).should('be.visible')
    })
  })

  describe('Refresh Functionality', () => {
    it('refreshes the key list when refresh button is clicked', () => {
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

      cy.get('button').find('svg.lucide-refresh-cw').parent().click()

      cy.wait('@getKeys')
    })
  })

  describe('Navigation', () => {
    let testKeyId: string

    beforeEach(() => {
      // Intercept the keys API call
      cy.intercept('GET', '**/api/hsm/keys*').as('getKeys')

      cy.createKeyViaApi().then((key) => {
        testKeyId = key.key_id
        cy.visit('/keys')
        // Wait for keys API to complete
        cy.wait('@getKeys')
        // Click refresh to ensure we have latest data
        cy.get('button').find('svg.lucide-refresh-cw').parent().click()
        cy.wait('@getKeys')
        cy.contains(testKeyId.substring(0, 8), { timeout: 10000 }).should('exist')
      })
    })

    afterEach(() => {
      if (testKeyId) {
        cy.deleteKeyViaApi(testKeyId)
      }
    })

    it('navigates to key detail page via View Details menu', () => {
      // Find the row with our key and click the actions menu
      cy.contains(testKeyId.substring(0, 8))
        .parents('tr')
        .within(() => {
          cy.get('button').find('svg.lucide-more-horizontal').parent().click()
        })

      // Click View Details in the dropdown
      cy.get('[role="menuitem"]').contains('View Details').click()

      cy.url().should('include', `/keys/${testKeyId}`)
    })
  })

  describe('Empty State', () => {
    it('displays table structure', () => {
      cy.get('table').should('exist')
    })
  })
})
