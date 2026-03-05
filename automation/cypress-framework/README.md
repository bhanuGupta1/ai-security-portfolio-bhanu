# Cypress E2E Automation — Sauce Demo

End-to-end test automation framework built against [Sauce Demo](https://www.saucedemo.com), a practice e-commerce site with login, product catalogue, cart, and checkout flows.

## Framework Features

- **Page Object Model** — `LoginPage`, `InventoryPage`, `CartPage`, `CheckoutPage`
- **Custom Commands** — `cy.login()`, `cy.loginAs()`, `cy.addToCart()`, `cy.verifyCartCount()`
- **Data-Driven Testing** — Fixtures for user credentials (6 user types) and product data
- **Screenshot on Failure** — Configured via `cypress.config.js`
- **CI/CD** — GitHub Actions pipeline runs all tests on every push

## Test Coverage (24 Test Cases)

| Spec | Tests | What it covers |
|------|-------|---------------|
| `login.cy.js` | TC-01 to TC-05 | Valid login, locked out user, invalid creds, empty fields |
| `inventory.cy.js` | TC-06 to TC-08 | Product count, names/prices, logout |
| `cart.cy.js` | TC-09 to TC-14 | Add/remove items, cart page verification, continue shopping |
| `checkout.cy.js` | TC-15 to TC-20 | Happy path checkout, missing fields, cancel, back to products |
| `sorting.cy.js` | TC-21 to TC-24 | Sort by name A-Z/Z-A, price low-high/high-low |

## How to Run

From `automation/cypress-framework/`:

```bash
# Install dependencies
npm install

# Open Cypress UI (interactive)
npm run cy:open

# Run headless (CLI)
npm test

# Run in Chrome specifically
npm run cy:run:chrome
```

## Project Structure

```
automation/cypress-framework/
├── cypress.config.js
├── package.json
├── cypress/
│   ├── e2e/
│   │   ├── login.cy.js
│   │   ├── inventory.cy.js
│   │   ├── cart.cy.js
│   │   ├── checkout.cy.js
│   │   ├── sorting.cy.js
│   │   └── old-demo/              # Early learning tests (example.cypress.io)
│   │       ├── basic-navigation.cy.js
│   │       └── content-check.cy.js
│   ├── pages/                     # Page Object Model
│   │   ├── LoginPage.js
│   │   ├── InventoryPage.js
│   │   ├── CartPage.js
│   │   └── CheckoutPage.js
│   ├── fixtures/                  # Test data
│   │   ├── users.json
│   │   └── products.json
│   ├── support/
│   │   ├── commands.js            # Custom commands
│   │   └── e2e.js
│   └── evidence/                  # Screenshots and recordings
├── test-plan.md
├── test-cases.md
└── test-summary.md
```

## Learning Progression

The `old-demo/` folder contains my first Cypress tests written against `example.cypress.io` — basic navigation and content checks. These are excluded from the main test run but kept to show how I progressed from simple smoke tests to a full POM framework with data-driven testing and CI/CD.

## Evidence

See: `cypress/evidence/`
