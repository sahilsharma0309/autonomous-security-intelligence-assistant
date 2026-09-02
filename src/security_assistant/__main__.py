import logging

from security_assistant.orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO)


def main() -> None:
    orchestrator = Orchestrator()
    orchestrator.run_assessment("example.com")


if __name__ == "__main__":
    main()
