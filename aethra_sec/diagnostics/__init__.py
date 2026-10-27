"""Opt-in diagnostics that observe a running application without changing it.

Nothing in this package runs unless it is explicitly armed, and nothing in it
writes to the application's own data. It exists so a fault reported as "it
froze" can be turned into a measurement.
"""
