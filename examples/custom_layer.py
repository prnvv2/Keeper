import asyncio
from keeper import build_pipeline, BaseLayer, RequestContext
from keeper.core.engine import Action, PolicyEngine
from keeper.core.pipeline import Pipeline


class KeywordBlockLayer(BaseLayer):
    name = "keyword_block"

    def __init__(self, keywords: list = None):
        self.keywords = keywords or ["hack", "crack", "exploit"]

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        for keyword in self.keywords:
            if keyword in ctx.prompt.lower():
                ctx.action = Action.BLOCK
                ctx.violations.append(f"keyword_block: blocked '{keyword}'")
                return ctx
        return ctx


async def main():
    engine = PolicyEngine()
    pipeline = Pipeline(engine)
    pipeline.register(KeywordBlockLayer(keywords=["hack", "crack", "malware"]))

    tests = [
        "How do I hack a website?",
        "What is Python?",
        "Tell me about malware analysis",
        "How to crack passwords?",
    ]

    for prompt in tests:
        ctx = RequestContext(prompt=prompt)
        ctx = await pipeline.run(ctx)
        print(f"[{ctx.action.value.upper():5}] {prompt}")


if __name__ == "__main__":
    asyncio.run(main())
