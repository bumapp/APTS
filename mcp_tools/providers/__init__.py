"""Providers: the layer controllers call.

A provider composes services into one complete operation and owns the order
they run in. It holds no rules of its own — authorisation, scope, and guardrail
decisions all live in ``services/`` — but it decides which are consulted, in
what sequence, and what happens when one objects.

Controllers call providers. Providers call services. Services call
repositories. Nothing calls back up.
"""
