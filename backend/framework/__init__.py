"""ST-AI Framework — semantic-versioned package.

Versioning policy (SemVer 2.0):
    MAJOR — incompatible schema or rule-engine output changes that would
            re-score existing deployments.
    MINOR — additive features that preserve backwards compatibility (new
            optional fields, new gate conditions that only tighten rather
            than loosen, new standards crosswalks).
    PATCH — bug fixes and cosmetic updates that cannot change any score.

Every DerivedTerms instance is stamped with __version__ at compute time,
so deployments scored under v1.0.0 will always be re-scoreable identically
under v1.0.x patches.
"""
__version__      = "1.0.0"
__version_info__ = (1, 0, 0)
__spec_url__     = "https://github.com/yourorg/st-ai-framework"
__doi__          = ""   # populate when the spec PDF is published with a DOI
__license__      = "MIT"
