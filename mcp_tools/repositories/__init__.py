"""Repositories: database access, and nothing else.

Split out from ``providers/`` deliberately. Providers adapt *other systems* —
the sandbox container today, real scanners and third-party APIs tomorrow.
Repositories own the SQL: which tables this container reads, which it writes,
and what happens when Postgres will not answer.

Keeping them apart matters here more than it usually would. PRD §3.2 pins down
which component may write which table, and a single package holding every
statement this container issues makes that reviewable — you can read one folder
and know the container's full database footprint, rather than grepping for
``get_conn`` across three layers.

Services depend on the protocols defined here, never on ``psycopg``.
"""
