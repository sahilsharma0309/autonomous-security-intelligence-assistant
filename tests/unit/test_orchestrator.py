from security_assistant.orchestrator import Orchestrator


def test_run_assessment_returns_expected_keys():
    orchestrator = Orchestrator()

    result = orchestrator.run_assessment("example.com")

    assert result["target"] == "example.com"
    assert "osint" in result
    assert "iot_recon" in result
    assert "threats" in result
