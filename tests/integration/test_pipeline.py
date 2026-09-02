from security_assistant.orchestrator import Orchestrator


def test_full_pipeline_smoke():
    """End-to-end smoke test wiring all engines through the orchestrator."""
    orchestrator = Orchestrator()

    result = orchestrator.run_assessment("192.0.2.1")

    assert result["osint"]["target"] == "192.0.2.1"
    assert result["iot_recon"]["target"] == "192.0.2.1"
    assert result["threats"]["target"] == "192.0.2.1"
