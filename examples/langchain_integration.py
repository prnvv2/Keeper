from langchain.agents import create_react_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from keeper import build_pipeline
from keeper.integration.langchain_hooks import keeperGuardrailHandler


@tool
def search(query: str) -> str:
    return f"Search results for: {query}"


pipeline = build_pipeline()
handler = keeperGuardrailHandler(pipeline)

llm = ChatOpenAI(model="gpt-4", temperature=0)
tools = [search]

agent = create_react_agent(llm, tools, prompt="You are a helpful assistant.")
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[handler],
    verbose=True,
)
