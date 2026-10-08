import time

from collector.windows_security import collect_events

from detection.live_detection import (
    analyze_events
)

from detection.correlation import (
    correlate_events
)


INTERVAL = 10


def run():

    print()
    print(
        "LateralTrace Continuous SOC Pipeline"
    )
    print(
        "===================================="
    )
    print()

    print(
        f"Polling interval: {INTERVAL} seconds"
    )

    print(
        "Press CTRL+C to stop."
    )

    print()

    while True:

        try:

            total, inserted, events = (
                collect_events(
                    max_events=100
                )
            )

            print(
                f"[*] Read {total} events | "
                f"New: {inserted}"
            )

            if events:

                detections = analyze_events(
                    events
                )

                new_alerts = [
                    detection
                    for detection in detections
                    if detection["alert_created"]
                ]

                if new_alerts:

                    print(
                        f"[!] New event alerts: "
                        f"{len(new_alerts)}"
                    )

                    for detection in new_alerts:

                        finding = (
                            detection["finding"]
                        )

                        event = (
                            detection["event"]
                        )

                        print(
                            f"    "
                            f"[{finding['severity']}] "
                            f"{finding['type']} | "
                            f"{event['account'] or '-'} | "
                            f"{event['computer']}"
                        )

                correlations = (
                    correlate_events()
                )

                new_correlations = [
                    result
                    for result in correlations
                    if result["alert_created"]
                ]

                for result in new_correlations:

                    print()

                    print(
                        "[!!!] CORRELATED SECURITY ALERT"
                    )

                    print(
                        f"      Severity: "
                        f"{result['severity']}"
                    )

                    print(
                        f"      Account: "
                        f"{result['account']}"
                    )

                    print(
                        f"      Score: "
                        f"{result['score']}"
                    )

                    print(
                        f"      Computers: "
                        f"{', '.join(result['computers'])}"
                    )

                    print(
                        f"      Events: "
                        f"{len(result['related_event_ids'])}"
                    )

                    print()

            time.sleep(
                INTERVAL
            )

        except KeyboardInterrupt:

            print()

            print(
                "LateralTrace collector stopped."
            )

            break

        except Exception as error:

            print(
                f"[!] Collector error: {error}"
            )

            time.sleep(
                INTERVAL
            )


if __name__ == "__main__":

    run()