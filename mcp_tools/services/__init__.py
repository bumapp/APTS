"""Services: the individual decisions and units of work.

Each service answers one question or performs one job — may this caller use
this tool, is this call in scope, what is this engagement's boundary, what does
this tool return — without knowing what else happens around it. Composing them
into a whole operation is the provider's job.

Services reach downward to ``repositories/`` for data and to ``utils/`` for
pure helpers, and never upward. The decision services (``policy_service``,
``guardrails_service``) touch no I/O at all, which is what lets the security
rules be tested without a database or a running app.
"""
