"""Run the WAF on the local loopback interface."""

from app import app, run_local


if __name__ == "__main__":
    run_local(app)
