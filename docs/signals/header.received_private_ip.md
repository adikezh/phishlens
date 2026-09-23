# header.received_private_ip (H-05)

Detects a private, loopback, or link-local address in `Received`. Internal
mail relays can legitimately contain such hops, so the signal is deliberately
low-weight and is evidence for route review rather than a phishing verdict.
