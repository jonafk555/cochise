from cochise.common import LLMFunctionMapping
from cochise.knowledge import Knowledge


class _Logger:
    pass


def test_tool_mapping_resolves_deferred_method_annotations():
    tool = Knowledge(_Logger()).add_compromised_account

    mapping = LLMFunctionMapping([tool])

    function = mapping.get_tool_definitions()[0]["function"]
    assert function["parameters"]["properties"]["username"]["type"] == "string"
    assert function["parameters"]["required"] == ["username", "password", "context"]
    assert mapping.get_function(function["name"]) is tool
