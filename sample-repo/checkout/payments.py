class PaymentMethod:
    def __init__(self, method_id, brand):
        self.id = method_id
        self.brand = brand


class Customer:
    def __init__(self, customer_id, payment_method=None):
        self.customer_id = customer_id
        self.payment_method = payment_method  # legacy customers may have None here


def process_payment(customer):
    """Charge the customer's default payment method."""
    if customer.payment_method is None:
        raise ValueError(
            f"Customer {customer.customer_id} does not have a payment method"
        )

    return {"status": "charged", "payment_method_id": customer.payment_method.id}
