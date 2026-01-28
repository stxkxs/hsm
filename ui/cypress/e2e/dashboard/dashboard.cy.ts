/// <reference types="cypress" />

describe('Dashboard', () => {
  beforeEach(() => {
    cy.setupAuth()
    cy.visit('/')
  })

  describe('Page Display', () => {
    it('displays the dashboard after login', () => {
      cy.url().should('eq', Cypress.config().baseUrl + '/')
    })

    it('displays dashboard title', () => {
      cy.contains('Dashboard').should('be.visible')
    })

    it('displays the sidebar navigation', () => {
      cy.get('aside').should('be.visible')
    })

    it('displays overview description', () => {
      cy.contains('Overview of your HSM').should('exist')
    })
  })

  describe('Statistics Cards', () => {
    it('displays Total Keys stat', () => {
      cy.contains('Total Keys').should('exist')
    })

    it('displays Active Keys stat', () => {
      cy.contains('Active Keys').should('exist')
    })

    it('displays Operations Today stat', () => {
      cy.contains('Operations Today').should('exist')
    })

    it('displays Namespaces stat', () => {
      cy.contains('Namespaces').should('exist')
    })

    it('stat cards are clickable links', () => {
      cy.contains('Total Keys').closest('a').should('have.attr', 'href', '/keys')
    })
  })

  describe('Quick Actions', () => {
    it('displays Quick Actions section', () => {
      cy.contains('Quick Actions').should('be.visible')
    })

    it('displays Create Key action', () => {
      cy.contains('Create Key').should('exist')
    })

    it('displays Sign Data action', () => {
      cy.contains('Sign Data').should('exist')
    })

    it('displays View Audit Log action', () => {
      cy.contains('View Audit Log').should('exist')
    })

    it('Create Key navigates to keys page', () => {
      // Find Create Key in the Quick Actions card and click it
      cy.contains('a', 'Create Key').click()

      cy.url().should('include', '/keys')
    })
  })

  describe('Recent Activity', () => {
    it('displays Recent Activity section', () => {
      cy.contains('Recent Activity').should('exist')
    })

    it('has View All button for audit', () => {
      // View All is a button that navigates to audit
      cy.contains('button', 'View All').should('exist')
    })
  })

  describe('Navigation', () => {
    it('navigates to Keys page', () => {
      cy.get('aside').contains('Keys').click({ force: true })
      cy.url().should('include', '/keys')
    })

    it('navigates to Operations page', () => {
      cy.get('aside a[href="/operations"]').click({ force: true })
      cy.url().should('include', '/operations')
    })

    it('navigates to Audit page', () => {
      cy.get('aside a[href="/audit"]').click({ force: true })
      cy.url().should('include', '/audit')
    })

    it('navigates to Webhooks page', () => {
      cy.get('aside a[href="/webhooks"]').click({ force: true })
      cy.url().should('include', '/webhooks')
    })

    it('navigates to Policies page', () => {
      cy.get('aside a[href="/policies"]').click({ force: true })
      cy.url().should('include', '/policies')
    })

    it('navigates to Namespaces page', () => {
      cy.get('aside a[href="/namespaces"]').click({ force: true })
      cy.url().should('include', '/namespaces')
    })

    it('navigates to Blockchain page', () => {
      cy.get('aside a[href="/blockchain"]').click({ force: true })
      cy.url().should('include', '/blockchain')
    })

    it('navigates to Settings page', () => {
      cy.get('aside a[href="/settings"]').click({ force: true })
      cy.url().should('include', '/settings')
    })

    it('highlights current navigation item with active class', () => {
      // Dashboard link should have active styling (bg-primary)
      cy.get('aside a[href="/"]').should('have.class', 'bg-primary')
    })
  })

  describe('Responsive Layout', () => {
    it('displays properly on desktop', () => {
      cy.viewport(1280, 720)

      cy.get('aside').should('be.visible')
      cy.contains('Dashboard').should('be.visible')
    })

    it('displays properly on tablet', () => {
      cy.viewport(768, 1024)

      cy.contains('Dashboard').should('be.visible')
    })

    it('displays properly on mobile', () => {
      cy.viewport(375, 667)

      cy.contains('Dashboard').should('be.visible')
    })
  })

  describe('User Menu', () => {
    it('displays user menu avatar button', () => {
      cy.get('button.rounded-full').should('exist')
    })

    it('opens user menu on click', () => {
      cy.get('button.rounded-full').first().click()

      cy.get('[role="menu"]').should('be.visible')
    })

    it('shows logout option in user menu', () => {
      cy.get('button.rounded-full').first().click()

      cy.get('[role="menuitem"]').contains('Logout').should('be.visible')
    })

    it('shows Profile option in user menu', () => {
      cy.get('button.rounded-full').first().click()

      cy.get('[role="menuitem"]').contains('Profile').should('be.visible')
    })

    it('shows Settings option in user menu', () => {
      cy.get('button.rounded-full').first().click()

      cy.get('[role="menuitem"]').contains('Settings').should('be.visible')
    })
  })

  describe('Data Loading', () => {
    it('displays stats after loading', () => {
      // Stats should show numeric values (not loading state)
      cy.contains('Total Keys').parent().find('.text-2xl').should('exist')
    })
  })

  describe('Error States', () => {
    it('handles API errors gracefully', () => {
      cy.intercept('GET', '**/api/hsm/keys*', {
        statusCode: 500,
        body: { error: 'Server error' },
      }).as('keysError')

      cy.visit('/')

      // Should not crash, dashboard should still display
      cy.contains('Dashboard').should('be.visible')
    })
  })
})
