# py-authz

A lightweight, extensible authorization library for Python.


py-authz/
├── py_authz/                     # Main package
│
│   ├── __init__.py
│   ├── api.py                   # Public API (Authz class)
│
│   ├── core/                    # Core domain logic (framework-agnostic)
│   │   ├── __init__.py
│   │   ├── types.py             # Identity, Resource, AuthzRequest
│   │   ├── enforcement.py       # AuthzEngine
│   │   ├── exceptions.py        # Custom exceptions
│   │
│   ├── clients/                 # External service integrations
│   │   ├── __init__.py
│   │   ├── openfga.py           # OpenFGA client
│   │   ├── keycloak.py          # Keycloak integration (later)
│   │
│   ├── cache/                   # Caching layer
│   │   ├── __init__.py
│   │   ├── base.py              # BaseCache (ABC)
│   │   ├── memory.py            # InMemoryCache
│   │   ├── redis.py             # RedisCache (later)
│   │
│   ├── config/                  # Configuration management
│   │   ├── __init__.py
│   │   ├── settings.py          # Settings class
│   │
│   ├── utils/                   # Helpers (keep small!)
│   │   ├── __init__.py
│   │   ├── logging.py
│   │   ├── retry.py
│
│   ├── adapters/                # Framework integrations (later)
│   │   ├── __init__.py
│   │   ├── django/
│   │   ├── fastapi/
│   │   ├── flask/
│
│   ├── cli/                     # CLI tooling (later)
│   │   ├── __init__.py
│   │   ├── main.py
│
├── tests/                       # Tests (mirrors structure)
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_enforcement.py
│   │   ├── test_cache.py
│   │
│   ├── integration/
│   │   ├── test_openfga_client.py
│
├── examples/                    # Example usage (VERY valuable)
│   ├── basic_usage.py
│
├── docs/                        # Documentation (future-proofing)
│   ├── getting_started.md
│   ├── architecture.md
│
├── pyproject.toml               # Packaging (modern Python)
├── README.md
├── .gitignore
├── LICENSE