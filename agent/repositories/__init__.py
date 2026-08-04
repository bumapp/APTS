"""Repositories: database access, and nothing else.

An agent touches exactly one table — it writes its artifact to
``agent_results`` — plus the shared audit log. Keeping both statements in one
package makes the agent's full database footprint reviewable against the
per-component access rules in PRD §3.2 by reading one folder.
"""
