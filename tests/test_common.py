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


def test_tool_mapping_accepts_undocumented_deferred_annotation_methods():
    knowledge = Knowledge(_Logger())
    tools = [knowledge.record_host_privilege, knowledge.update_shell_session]

    mapping = LLMFunctionMapping(tools)

    definitions = mapping.get_tool_definitions()
    assert [definition["function"]["name"] for definition in definitions] == [
        "record_host_privilege",
        "update_shell_session",
    ]
    assert (
        definitions[0]["function"]["parameters"]["properties"]["host_id"]["type"]
        == "string"
    )
    assert (
        definitions[1]["function"]["parameters"]["properties"]["shell_id"]["type"]
        == "string"
    )
