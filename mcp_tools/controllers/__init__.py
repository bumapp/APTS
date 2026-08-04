"""Controllers: the HTTP surface.

Routing, authentication, and status-code mapping only. Controllers hold no
business logic — they translate a request into a service call and a service
outcome into a response — which is what keeps the same rules reusable when the
MCP transport is mounted alongside these REST routes.
"""
