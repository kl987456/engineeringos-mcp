from checkout.payments import Customer, PaymentMethod, process_payment


def test_process_payment_normal_customer():
    pm = PaymentMethod("pm_123", "visa")
    customer = Customer("cust_1", payment_method=pm)
    result = process_payment(customer)
    assert result["status"] == "charged"


def test_process_payment_legacy_customer_without_payment_method():
    legacy_customer = Customer("cust_legacy_9", payment_method=None)
    # Legacy customers should get a clear error, not a crash
    try:
        process_payment(legacy_customer)
        assert False, "expected ValueError for legacy customer"
    except ValueError:
        pass
