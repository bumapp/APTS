"""Providers: the layer controllers call.

A provider composes services into one complete operation and owns the order
they run in. Controllers call providers, providers call services, services call
repositories. Nothing calls back up.
"""
