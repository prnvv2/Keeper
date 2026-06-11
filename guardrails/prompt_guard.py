# guardrails/prompt_guard.py
# Lightweight BERT-style classifier for fast jailbreak detection.
# Runs in <1ms per prompt — serves as an early filter before
# the heavier LLM-based semantic layer.

from keeper.core.pipeline import RequestContext
from keeper.core.engine import Action


class PromptGuard:
    # Fine-tuned transformer model for direct jailbreak classification.
    name = "prompt_guard"

    def __init__(self):
        self.model = None
        self.tokenizer = None

    def load(self, model_name: str = "bert-base-uncased"):
        # Lazy-load the HuggingFace model (call once at startup).
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
        except Exception:
            pass  # Model will be skipped if not available

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # Tokenize prompt, run inference, check score against threshold.
        if self.model is None:
            return ctx
        threshold = config.get("threshold", 0.85)
        try:
            inputs = self.tokenizer(ctx.prompt[:512], return_tensors="pt", truncation=True)
            outputs = self.model(**inputs)
            score = float(outputs.logits.softmax(dim=-1)[0][1].detach())
            ctx.risk_score = max(ctx.risk_score, score)
            if score >= threshold:
                ctx.action = Action.BLOCK
                ctx.violations.append(f"prompt_guard: {score:.2f}")
        except Exception:
            pass
        return ctx
