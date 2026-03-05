import InventoryPage from '../pages/InventoryPage';

describe('Product Sorting', () => {
  beforeEach(() => {
    cy.loginAs('standardUser');
    InventoryPage.verifyPageLoaded();
  });

  it('TC-21: should sort products by name A to Z', () => {
    InventoryPage.sortBy('az');

    cy.fixture('products').then((products) => {
      InventoryPage.getItemNames().each(($el, index) => {
        cy.wrap($el).should('have.text', products.sortedByNameAZ[index]);
      });
    });
  });

  it('TC-22: should sort products by name Z to A', () => {
    InventoryPage.sortBy('za');

    cy.fixture('products').then((products) => {
      InventoryPage.getItemNames().each(($el, index) => {
        cy.wrap($el).should('have.text', products.sortedByNameZA[index]);
      });
    });
  });

  it('TC-23: should sort products by price low to high', () => {
    InventoryPage.sortBy('lohi');

    InventoryPage.getItemPrices().then(($prices) => {
      const prices = [...$prices].map((el) =>
        parseFloat(el.textContent.replace('$', ''))
      );
      const sorted = [...prices].sort((a, b) => a - b);
      expect(prices).to.deep.equal(sorted);
    });
  });

  it('TC-24: should sort products by price high to low', () => {
    InventoryPage.sortBy('hilo');

    InventoryPage.getItemPrices().then(($prices) => {
      const prices = [...$prices].map((el) =>
        parseFloat(el.textContent.replace('$', ''))
      );
      const sorted = [...prices].sort((a, b) => b - a);
      expect(prices).to.deep.equal(sorted);
    });
  });
});
