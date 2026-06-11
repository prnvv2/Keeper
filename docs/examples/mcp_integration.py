from keeper import build_pipeline
from keeper.integration.mcp_server import keeperMCPTool

pipeline = build_pipeline()
tool = keeperMCPTool(pipeline)

print(tool.schema)

result = await tool.call("What is machine learning?", session_id="s1", user_id="demo")
print(f"Allowed: {result['allowed']}")
print(f"Action:  {result['action']}")
print(f"Risk:    {result['risk_score']}")
