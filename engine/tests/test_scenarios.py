from pathlib import Path

from aphasia.scenarios import REGISTRY, load_yaml

YAML = Path(__file__).resolve().parents[2] / "scenarios.yaml"

ALL_IDS = ["direct_injection", "indirect_injection", "tool_misuse", "data_exfil",
           "mcp_tool_poisoning", "memory_poisoning", "output_handling", "system_prompt_leak",
           "rag_exfil", "misinformation", "denial_of_wallet"]


def test_load_yaml():
    s = load_yaml(YAML)
    assert [x.id for x in s] == ALL_IDS
    assert all(x.owasp for x in s)  # every scenario carries an OWASP id
    assert set(REGISTRY) >= {x.id for x in s}


def test_full_owasp_top10_covered():
    load_yaml(YAML)
    owasp = {REGISTRY[i].owasp for i in ALL_IDS}
    assert owasp == {f"LLM{n:02d}" for n in range(1, 11)}  # LLM01..LLM10, all 10


def test_pinned_mappings():
    load_yaml(YAML)
    want = {"direct_injection": ("AML.T0051.000", "LLM01"),
            "indirect_injection": ("AML.T0051.001", "LLM01"),
            "tool_misuse": ("AML.T0053", "LLM06"),
            "data_exfil": ("AML.T0086", "LLM02"),
            "mcp_tool_poisoning": ("AML.T0110", "LLM03"),
            "memory_poisoning": ("AML.T0099", "LLM04"),
            "output_handling": ("", "LLM05"),
            "system_prompt_leak": ("AML.T0056", "LLM07"),
            "rag_exfil": ("AML.T0086", "LLM08"),
            "misinformation": ("AML.T0031", "LLM09"),
            "denial_of_wallet": ("AML.T0034.002", "LLM10")}
    assert {k: (REGISTRY[k].atlas, REGISTRY[k].owasp) for k in want} == want
