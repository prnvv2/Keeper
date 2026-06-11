# models/datasets.py
# Loads HuggingFace benchmark datasets for evaluating guardrail accuracy.
# Used in CI/CD to measure precision/recall against known attack corpora.

BENCHMARKS = {
    "jailbreak_vault": "JailbreakVault/JailbreakVault",
    "prompt_injection": "NatLee/Prompt-Injection-Bench",
    "safe_guard": "B括/safe-guard-bench",
}


def load_benchmark(name: str, split: str = "test"):
    # Download and cache a HuggingFace dataset by name.
    import datasets
    hf_name = BENCHMARKS.get(name)
    if not hf_name:
        raise ValueError(f"Unknown benchmark: {name}. Options: {list(BENCHMARKS.keys())}")
    ds = datasets.load_dataset(hf_name, split=split)
    return ds


async def evaluate(pipeline, benchmark_name: str, label_key: str = "label", text_key: str = "prompt"):
    ds = load_benchmark(benchmark_name)
    correct = 0
    total = 0
    for example in ds:
        from aanf.core.pipeline import RequestContext
        ctx = RequestContext(prompt=example.get(text_key, ""))
        ctx = await pipeline.run(ctx)
        is_malicious = bool(example.get(label_key, 0))
        was_blocked = ctx.action in ("block", "redact")
        if is_malicious == was_blocked:
            correct += 1
        total += 1
    return {"accuracy": correct / total if total else 0, "total": total}
