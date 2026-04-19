"""
This file is intentionally left minimal.

The top-level `src/` directory is used as a source root for packaging
and should NOT be importable as a runtime package. Keeping an
empty/benign __init__ prevents accidental `import src` usage which
can cause confusing import paths.  Do not populate this file.
"""

__all__ = []
