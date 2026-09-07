"""
`python -m py_authz.control_plane` — run the control-plane API with
uvicorn, reading configuration from the environment
(`ControlPlaneSettings.from_env()`). For anything beyond local/dev use
(TLS termination, multiple workers, graceful reload), run uvicorn (or
gunicorn+uvicorn workers) against `py_authz.control_plane.app:create_app`
directly instead of this module.
"""

import os


def main() -> None:
    import uvicorn

    uvicorn.run(
        "py_authz.control_plane.app:create_app",
        factory=True,
        host=os.environ.get("CONTROL_PLANE_HOST", "127.0.0.1"),
        port=int(os.environ.get("CONTROL_PLANE_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
