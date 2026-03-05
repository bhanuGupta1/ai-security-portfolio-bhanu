import InventoryPage from '../pages/InventoryPage';
import CartPage from '../pages/CartPage';
import CheckoutPage from '../pages/CheckoutPage';

describe('Checkout Flow', () => {
  beforeEach(() => {
    cy.loginAs('standardUser');
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.goToCart();
    CartPage.proceedToCheckout();
  });

  it('TC-15: should complete full checkout successfully (happy path)', () => {
    CheckoutPage.verifyStepOneLoaded();
    CheckoutPage.fillCheckoutInfo('Bhanu', 'Gupta', '9016');
    CheckoutPage.clickContinue();

    CheckoutPage.verifyStepTwoLoaded();
    CheckoutPage.verifySummaryItemCount(1);
    CheckoutPage.verifyTotalExists();
    CheckoutPage.clickFinish();

    CheckoutPage.verifyCompleteLoaded();
  });

  it('TC-16: should show error when first name is missing', () => {
    CheckoutPage.fillCheckoutInfo(null, 'Gupta', '9016');
    CheckoutPage.clickContinue();
    CheckoutPage.verifyErrorMessage('First Name is required');
  });

  it('TC-17: should show error when last name is missing', () => {
    CheckoutPage.fillCheckoutInfo('Bhanu', null, '9016');
    CheckoutPage.clickContinue();
    CheckoutPage.verifyErrorMessage('Last Name is required');
  });

  it('TC-18: should show error when postal code is missing', () => {
    CheckoutPage.fillCheckoutInfo('Bhanu', 'Gupta', null);
    CheckoutPage.clickContinue();
    CheckoutPage.verifyErrorMessage('Postal Code is required');
  });

  it('TC-19: should return to cart when cancel is clicked on checkout', () => {
    CheckoutPage.clickCancel();
    CartPage.verifyPageLoaded();
  });

  it('TC-20: should return to inventory after completing purchase', () => {
    CheckoutPage.fillCheckoutInfo('Bhanu', 'Gupta', '9016');
    CheckoutPage.clickContinue();
    CheckoutPage.clickFinish();
    CheckoutPage.verifyCompleteLoaded();
    CheckoutPage.clickBackHome();
    InventoryPage.verifyPageLoaded();
  });
});
