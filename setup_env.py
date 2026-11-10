"""Create or complete the local WAF configuration."""

import os
from pathlib import Path
from secrets import token_urlsafe

from dotenv import dotenv_values, set_key


def main():
    root = Path(__file__).resolve().parent
    env_path = root / ".env"
    sample_path = root / ".env.sample"
    sample = sample_path.read_text(encoding="utf-8")

    try:
        with open(
            env_path, "x", encoding="utf-8",
            opener=lambda path, flags: os.open(path, flags, 0o600),
        ) as env_file:
            env_file.write(sample)
    except FileExistsError:
        pass

    encoding = "utf-8"
    with env_path.open("rb") as env_file:
        if env_file.read(3) == b"\xef\xbb\xbf":
            encoding = "utf-8-sig"

    current = dotenv_values(env_path, encoding=encoding, interpolate=False)
    defaults = dotenv_values(sample_path, interpolate=False)
    for key in ("SECRET_KEY", "WAF_ADMIN_TOKEN"):
        value = current.get(key) or ""
        if not value.strip() or value == defaults[key]:
            set_key(env_path, key, token_urlsafe(48), encoding=encoding)

    print("Local .env is ready. Start or restart the WAF to load it.")


if __name__ == "__main__":
    main()
