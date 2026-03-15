# Playwright E2E Testing Framework — Sauce Demo

Playwright + TypeScript E2E testing framework built against [Sauce Demo](https://www.saucedemo.com), the same app tested with Cypress in this portfolio. This project demonstrates the same testing patterns (POM, data-driven, CI/CD) implemented in a different framework, showing tool flexibility.

## Why Both Cypress and Playwright?

Different teams use different tools. Building the same test coverage in both proves the testing patterns are mine, not just copied from a tutorial. It also lets me compare the two frameworks from real experience.

**Key differences I found:**
- Playwright runs multi-browser out of the box (Chromium, Firefox, WebKit)
- TypeScript-first with better type safety
- Built-in auto-wait (no explicit waits needed)
- Parallel execution by default
- Trace viewer for debugging failed tests

## Test Coverage

**29 test cases** across 5 spec files:

| Spec | Tests | Coverage |
|------|-------|----------|
| `login.spec.ts` | 7 | Valid login, locked user, invalid creds, empty fields, error dismissal |
| `inventory.spec.ts` | 4 | Product count, names/prices, logout, direct access protection |
| `cart.spec.ts` | 7 | Add/remove items, cart verification, continue shopping, persistence |
| `checkout.spec.ts` | 7 | Happy path, missing fields, cancel, total verification, post-purchase |
| `sorting.spec.ts` | 4 | Name A-Z/Z-A, price low-high/high-low |

## Framework Features

- **Page Object Model** — `LoginPage`, `InventoryPage`, `CartPage`, `CheckoutPage`
- **TypeScript** — Typed page objects, fixtures, and assertions
- **Data-driven fixtures** — User types, product data, checkout info, sort expectations
- **Multi-browser** — Chromium, Firefox, WebKit configs
- **CI/CD** — GitHub Actions pipeline (Chromium)
- **Auto-wait** — No manual waits, Playwright handles timing
- **Screenshots on failure** — Automatic capture
- **Trace on retry** — Full trace viewer for debugging

## How to Run

```bash
# Install dependencies
npm install

# Install browsers
npx playwright install

# Run all tests (all browsers)
npm test

# Run Chromium only
npm run test:chromium

# Run in headed mode (see the browser)
npm run test:headed

# Debug mode (step through)
npm run test:debug

# View HTML report
npm run report
```

## Project Structure

```
playwright-framework/
├── tests/
│   ├── login.spec.ts          # 7 login tests
│   ├── inventory.spec.ts      # 4 product/inventory tests
│   ├── cart.spec.ts           # 7 cart operation tests
│   ├── checkout.spec.ts       # 7 checkout flow tests
│   └── sorting.spec.ts        # 4 sort verification tests
├── pages/
│   ├── LoginPage.ts           # Login page object
│   ├── InventoryPage.ts       # Inventory/products page object
│   ├── CartPage.ts            # Cart page object
│   └── CheckoutPage.ts        # Checkout page object
├── fixtures/
│   └── testData.json          # All test data (users, products, checkout)
├── playwright.config.ts       # Multi-browser config
├── tsconfig.json              # TypeScript config
└── package.json               # Scripts and dependencies
```

## Tools

- **Playwright** 1.58+
- **TypeScript** 5.x
- **Node.js** 20+
- **GitHub Actions** for CI/CD
