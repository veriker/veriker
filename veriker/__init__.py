"""Veriker — re-derivable verification of attested artifacts.

Recompute the answer; do not trust the claim. The offline bundle verifier is
exposed as the ``veriker`` console command, as ``python -m veriker``, and as a
library entry point::

    from veriker import main          # argv-driven; returns the ADR-D8 exit code

Internals live under ``veriker.cli`` (the command-line surface) and the
``audit_bundle`` package (the verifier substrate)."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("veriker")
except PackageNotFoundError:  # running from a source tree without metadata
    __version__ = "0.0.0+unknown"

__all__ = ["main", "__version__"]


def __getattr__(name):
    # PEP 562 lazy attribute: importing ``veriker`` should not eagerly pull the
    # whole verifier (and its crypto deps) until ``main`` is actually used.
    if name == "main":
        from veriker.cli.verify import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
