"""A toy checkout flow with a statement we want to switch off in an emergency."""


def send_receipt(order):
    print(f"receipt emailed for order {order}")


def notify_partner_api(order):
    # Imagine this third-party API is down and every call hangs for 30s.
    print(f"notified partner about order {order}")


def checkout(order):
    print(f"charging order {order}")
    notify_partner_api(order)
    send_receipt(order)
    return "ok"


if __name__ == "__main__":
    print(checkout(1001))
