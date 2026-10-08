import json
from pathlib import Path

from windows_events import generate_events


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_FILE = DATA_DIR / "events.json"


def main():
    DATA_DIR.mkdir(exist_ok=True)

    events = generate_events()

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            events,
            file,
            indent=4
        )

    print()
    print("LateralTrace event dataset generated.")
    print(f"Events: {len(events)}")
    print(f"Output: {OUTPUT_FILE}")
    print()


if __name__ == "__main__":
    main()