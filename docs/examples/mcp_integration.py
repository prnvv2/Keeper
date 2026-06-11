from aanf import build_pipeline
from aanf.integration.mcp_server import AANFMCPTool

pipeline = build_pipeline()
tool = AANFMCPTool(pipeline)

print(tool.schema)

result = await tool.call("What is machine learning?", session_id="s1", user_id="demo")
print(f"Allowed: {result['allowed']}")
print(f"Action:  {result['action']}")
print(f"Risk:    {result['risk_score']}")
