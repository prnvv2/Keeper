- Act as a principal security architect, AI security engineer, and open-source infrastructure maintainer.

- Design and specify an enterprise-grade, open-source AI Firewall platform that can be deployed by organizations to securely control access to LLMs, AI agents, RAG systems, and AI APIs.

- The goal is to create a production-quality project comparable in engineering maturity to enterprise API gateways and security platforms, while remaining fully open source and self-hostable.

1. Input filtering
- Detects prompt injection attempts.
- Blocks malicious or inappropriate prompts.
- Removes sensitive information (PII, passwords, API keys) before it reaches the model.

2. Output filtering
- Prevents confidential data from being exposed.
- Detects hallucinations or policy violations.
- Blocks harmful or non-compliant responses.

3. Access control
- Authenticates users.
- Restricts which models users can access.
- Enforces role-based permissions.

4. Monitoring and logging
- Records prompts and responses.
- Tracks usage for compliance and auditing.
- Detects abnormal behavior.

5. Policy enforcement
- Applies organizational rules.
- Ensures compliance with regulations such as GDPR or HIPAA (where applicable).


Use below research work for building the system
- OWASP GenAI top 10 - LLM, Agentic Applications, MCP etc
- https://arxiv.org/pdf/2601.15824
- https://atlas.mitre.org/matrices/ATLAS-matrix
- https://arxiv.org/pdf/2607.29167
- https://arxiv.org/pdf/2607.08395
- https://arxiv.org/pdf/2607.01277

Output
- format : DOCX
- detailed explanation of project
- System design
- Components of high level and low level system
- project archetecture, directory structure etc
- workflow
- deployment etc
- tech stack explanation