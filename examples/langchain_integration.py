from langchain.agents import create_react_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from aanf import build_pipeline
from aanf.integration.langchain_hooks import AANFGuardrailHandler


@tool
def search(query: str) -> str:
    return f"Search results for: {query}"


pipeline = build_pipeline()
handler = AANFGuardrailHandler(pipeline)

llm = ChatOpenAI(model="gpt-4", temperature=0)
tools = [search]

agent = create_react_agent(llm, tools, prompt="You are a helpful assistant.")
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[handler],
    verbose=True,
)
