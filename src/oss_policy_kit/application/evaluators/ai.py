"""ai control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import (
    _AI_AGENT_HARDCODED_PROMPT_HINTS,
    _AI_AGENT_IDENTITY_ANTIPATTERNS,
    _AI_AGENT_IDENTITY_HINTS,
    _AI_AGENT_MODEL_HINTS,
    _AI_AGENT_PINNED_MODEL_RE,
    _AI_AGENT_RATE_LIMIT_HINTS,
    _AI_AGENT_TEST_PATTERNS,
    _AI_AGENT_TOOL_ALLOWLIST_PATHS,
    _AI_AGENT_TOOL_WILDCARD_HINTS,
    _AI_SECURITY_HEADINGS,
    _INTENDED_PURPOSE_HEADINGS,
    _LLM_SDK_HINTS,
    _MCP_AUTH_DISABLED_HINTS,
    _MCP_AUTH_HINTS,
    _MCP_CONFIG_PATHS,
    _OUTPUT_FILTER_HINTS,
    _RISK_MGMT_HEADINGS,
    _RISK_MGMT_PATHS,
    ControlStatus,
    EvalContext,
    EvalOutcome,
    Path,
    _agentic_applicable,
    _agentic_na,
    _agentic_signal,
    _annex_iv_section,
    _codeowners_covers_prompt_path,
    _find_any_text_hint,
    _find_prompt_registry,
    _iter_ai_agent_text_files,
    _load_ai_agent_evidence,
    _mcp_applicable,
    _mcp_na,
    _mcp_text_signal,
    _read_lower,
    _scan_for_llm_sdks,
    _scan_readme_for_section,
    contextlib,
    json,
)


def eval_llm_218a_po_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PO-001: AI Security Considerations section present."""
    p = _scan_readme_for_section(ctx.repo_root, _AI_SECURITY_HEADINGS)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No 'AI Security Considerations' / 'LLM Security' section found in SECURITY.md or README.md.",
            remediation=(
                "Add a section explicitly named 'AI Security Considerations' to SECURITY.md "
                "documenting the intended use, abuse cases, and mitigations of any AI components."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"AI Security Considerations section detected in {p.name}.",
        remediation="Keep the section in sync with model upgrades and capability changes.",
        evidence_sources=[str(p.resolve())],
        confidence="low",
    )


def eval_llm_218a_po_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PO-002: Prompt / system-instruction registry directory present."""
    for rel in ("prompts", "system_prompts", "system-prompts", "prompt-registry"):
        d = ctx.repo_root / rel
        if d.is_dir():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Prompt registry directory detected: {rel}/.",
                remediation="Document the prompt lifecycle (versioning, review, deprecation).",
                evidence_sources=[str(d.resolve())],
                confidence="low",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No prompt registry directory found (prompts/, system_prompts/, prompt-registry/).",
        remediation=(
            "Maintain prompts under version control in a dedicated directory so audit and rollback are possible."
        ),
        evidence_sources=[],
        confidence="low",
    )


def eval_llm_218a_ps_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PS-001: LLM release-integrity evidence file (evidence-backed)."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "llm-release-integrity.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No .oss-policy-kit/evidence/llm-release-integrity.json file. The evidence file "
                "should record model_sha, model_version, and eval_suite_results_path per release."
            ),
            remediation=(
                "Create the evidence file with the schema_version=llm-release-integrity/v1, "
                "the model SHA, the model version, and a path to the eval-suite results."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("model_sha") and data.get("model_version"):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(f"LLM release-integrity evidence present (model_version={data.get('model_version')})."),
                remediation="Refresh per release; keep eval_suite_results_path pointing to current results.",
                evidence_sources=[str(evidence.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="llm-release-integrity.json present but missing required fields.",
        remediation="Populate model_sha, model_version, and eval_suite_results_path.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_llm_218a_ps_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PS-002: Model versioning artifacts (signal-grade)."""
    for rel in ("models/MODEL_CARD.md", "MODEL_CARD.md", "model-card.md", "docs/model-card.md"):
        p = ctx.repo_root / rel
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Model card found at {rel}; model versioning artifact present.",
                remediation="Update the model card on every release.",
                evidence_sources=[str(p.resolve())],
                confidence="low",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No model card or model-versioning artifact found.",
        remediation="Add a MODEL_CARD.md (e.g. HuggingFace model-card pattern) at the repo root.",
        evidence_sources=[],
        confidence="low",
    )


def eval_llm_218a_pw_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PW-001: LLM SDK dependencies declared."""
    p = _scan_for_llm_sdks(ctx.repo_root)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No LLM SDK dependency detected; LLM controls do not apply to this repo.",
            remediation="If this repo uses an LLM SDK (transformers / openai / anthropic / langchain), declare it.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"LLM SDK dependency declared in {p.name}.",
        remediation="Pin the SDK by version (CI-PIN-001) and track upgrades via Dependabot/Renovate.",
        evidence_sources=[str(p.resolve())],
        confidence="medium",
    )


def eval_llm_218a_pw_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PW-002: Prompt-injection or adversarial test file present."""
    found: list[Path] = []
    for pattern in ("test_*prompt*injection*.py", "test_*adversarial*.py", "test_*jailbreak*.py"):
        with contextlib.suppress(OSError):
            for p in ctx.repo_root.rglob(pattern):
                if p.is_file():
                    found.append(p)
    if not found:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompt-injection or adversarial test file found.",
            remediation=(
                "Add tests under tests/ matching test_*prompt*injection*.py, test_*adversarial*.py, "
                "or test_*jailbreak*.py covering at least the OWASP LLM Top 10 #1 (prompt injection)."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(found)} adversarial / prompt-injection test file(s) detected.",
        remediation="Refresh test corpus as new attack patterns emerge.",
        evidence_sources=[str(p.resolve()) for p in found[:5]],
        confidence="low",
    )


def eval_llm_218a_rv_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-RV-001: Dependabot/Renovate config explicitly lists LLM SDKs."""
    candidates = [
        ctx.repo_root / ".github" / "dependabot.yml",
        ctx.repo_root / ".github" / "dependabot.yaml",
        ctx.repo_root / "renovate.json",
        ctx.repo_root / ".renovaterc.json",
    ]
    for p in candidates:
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(sdk in text for sdk in _LLM_SDK_HINTS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"Dependency-update config ({p.name}) explicitly references an LLM SDK.",
                    remediation="Keep the SDK in the config so security updates land promptly.",
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Dependency-update config does not explicitly reference an LLM SDK.",
        remediation=("Add an explicit package-ecosystem entry covering the LLM SDK(s) used by this project."),
        evidence_sources=[],
        confidence="low",
    )


def eval_llm_ai_act_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-001: Intended purpose / users / limitations documented (Annex IV §1)."""
    p = _scan_readme_for_section(ctx.repo_root, _INTENDED_PURPOSE_HEADINGS)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No 'Intended Purpose' / 'Intended Users' / 'Limitations' section found in "
                "SECURITY.md or README.md (Annex IV §1)."
            ),
            remediation=(
                "Add a section explicitly documenting the intended purpose, intended users, and "
                "foreseeable limitations of the AI system. Required by EU AI Act Annex IV §1."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Intended purpose / users / limitations section detected in {p.name} (Annex IV §1).",
        remediation=(
            "Keep the section in sync with model upgrades. Conformity assessment by a notified body "
            "is still required and out of scope for the kit."
        ),
        evidence_sources=[str(p.resolve())],
        confidence="low",
    )


def _file_has_output_filter(p: Path) -> bool:
    """True when a non-vendored code file references an output-filter / moderation hint."""

    if not p.is_file() or any(skip in p.parts for skip in (".git", ".venv", "node_modules", "__pycache__")):
        return False
    with contextlib.suppress(OSError):
        text = p.read_text(encoding="utf-8", errors="replace").lower()
        return any(h in text for h in _OUTPUT_FILTER_HINTS)
    return False


def _find_output_filter_files(repo_root: Path, limit: int = 5) -> list[Path]:
    """Return up to ``limit`` code files referencing output-filtering / moderation patterns."""

    matched: list[Path] = []
    for ext in ("*.py", "*.js", "*.ts", "*.mjs"):
        with contextlib.suppress(OSError):
            for p in repo_root.rglob(ext):
                if _file_has_output_filter(p):
                    matched.append(p)
                    if len(matched) >= limit:
                        return matched
    return matched


def eval_llm_ai_act_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-002: Output filtering / content moderation pattern detected (Annex IV §3)."""
    # Scan src/, tests/, or root code files for output-filter / moderation patterns.
    matched = _find_output_filter_files(ctx.repo_root)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No output-filtering / content-moderation reference found in source code (Annex IV §3)."),
            remediation=(
                "Implement an output filter (e.g. OpenAI Moderations API, NVIDIA NeMo Guardrails, "
                "or a custom classifier) and reference it in the AI pipeline."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Output-filtering / content-moderation pattern detected in {len(matched)} file(s) (Annex IV §3).",
        remediation="Periodically review the moderation thresholds and the evaluation dataset.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_llm_ai_act_003(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-003: Risk management documentation present (Annex IV §5)."""
    for rel in _RISK_MGMT_PATHS:
        p = ctx.repo_root / rel
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Risk-management documentation found at {rel} (Annex IV §5).",
                remediation="Keep the risk register current with each release; review with a notified body.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
    # Fall back to SECURITY.md section
    section_match = _scan_readme_for_section(ctx.repo_root, _RISK_MGMT_HEADINGS)
    if section_match is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Risk-management section detected in {section_match.name} (Annex IV §5).",
            remediation="Consider extracting to a dedicated risk-management.md for clearer audit traceability.",
            evidence_sources=[str(section_match.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No risk-management documentation found (risk-management.md, RISKS.md, or SECURITY.md section).",
        remediation=(
            "Document the AI risk-management process (hazard identification, residual risk, mitigation "
            "measures) in risk-management.md. Required by EU AI Act Annex IV §5."
        ),
        evidence_sources=[],
        confidence="low",
    )


def eval_ai_agent_001(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-001: MCP server authentication present."""
    configs = [ctx.repo_root / rel for rel in _MCP_CONFIG_PATHS if (ctx.repo_root / rel).is_file()]
    if not configs:
        with contextlib.suppress(OSError):
            configs.extend(p for p in ctx.repo_root.rglob("*.mcp.yaml") if p.is_file())
            configs.extend(p for p in ctx.repo_root.rglob("*.mcp.yml") if p.is_file())
    if not configs:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No MCP server configuration file detected.",
            remediation="No MCP-specific action required unless this repository ships an MCP server.",
            evidence_sources=[],
            confidence="medium",
        )
    disabled: list[Path] = []
    authenticated: list[Path] = []
    for p in configs:
        text = _read_lower(p)
        if any(h in text for h in _MCP_AUTH_DISABLED_HINTS):
            disabled.append(p)
        elif any(h.lower() in text for h in _MCP_AUTH_HINTS):
            authenticated.append(p)
    if disabled:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"MCP configuration disables or bypasses authentication in {len(disabled)} file(s).",
            remediation=(
                "Require OAuth/OIDC, bearer-token validation, mTLS, or an equivalent authn layer for MCP access."
            ),
            evidence_sources=[str(p.resolve()) for p in disabled],
            confidence="medium",
        )
    if authenticated:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP authentication signal detected in {len(authenticated)} config file(s).",
            remediation="Validate tokens are issued for this MCP server and avoid token passthrough.",
            evidence_sources=[str(p.resolve()) for p in authenticated],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP configuration is present but no authentication signal was detected.",
        remediation="Document the MCP authentication mode in mcp.json or an evidence file.",
        evidence_sources=[str(p.resolve()) for p in configs],
        confidence="low",
    )


def eval_ai_agent_002(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-002: Tool allowlist explicitly defined."""
    candidates = [ctx.repo_root / rel for rel in _AI_AGENT_TOOL_ALLOWLIST_PATHS if (ctx.repo_root / rel).is_file()]
    candidates.extend(ctx.repo_root / rel for rel in _MCP_CONFIG_PATHS if (ctx.repo_root / rel).is_file())
    if not candidates:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No explicit agent tool allowlist file found.",
            remediation="Add allowed_tools.yaml/json or document allowed MCP tools in mcp.json.",
            evidence_sources=[],
            confidence="low",
        )
    wildcard = [p for p in candidates if any(h in _read_lower(p) for h in _AI_AGENT_TOOL_WILDCARD_HINTS)]
    if wildcard:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Agent tool allowlist uses an allow-all or wildcard pattern.",
            remediation="Replace allow-all tool selection with a named, least-privilege allowlist.",
            evidence_sources=[str(p.resolve()) for p in wildcard],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Explicit agent tool allowlist/config detected in {len(candidates)} file(s).",
        remediation="Review the allowlist as tools are added or removed.",
        evidence_sources=[str(p.resolve()) for p in candidates[:5]],
        confidence="low",
    )


def eval_ai_agent_003(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-003: System prompt versioned and reviewed."""
    prompt_dir = _find_prompt_registry(ctx.repo_root)
    if prompt_dir is None:
        hardcoded = _find_any_text_hint(ctx.repo_root, _AI_AGENT_HARDCODED_PROMPT_HINTS)
        if hardcoded:
            return EvalOutcome(
                status=ControlStatus.FAIL,
                reason="System prompt appears hardcoded in source and no prompt registry directory exists.",
                remediation="Move system prompts into prompts/ and require CODEOWNERS review for that path.",
                evidence_sources=[str(p.resolve()) for p in hardcoded],
                confidence="low",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompts/, system_prompts/, or prompt-registry/ directory found.",
            remediation="Store system prompts in a versioned prompt registry and cover it with CODEOWNERS.",
            evidence_sources=[],
            confidence="low",
        )
    owner = _codeowners_covers_prompt_path(ctx.repo_root, prompt_dir)
    if owner is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Prompt registry detected at {prompt_dir.name}/ but no CODEOWNERS file was found.",
            remediation="Add CODEOWNERS coverage for the prompt registry so prompt changes are reviewed.",
            evidence_sources=[str(prompt_dir.resolve())],
            confidence="low",
        )
    owner_file, covered = owner
    if not covered:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"CODEOWNERS exists but does not cover {prompt_dir.name}/.",
            remediation="Add a CODEOWNERS entry for the prompt registry path.",
            evidence_sources=[str(prompt_dir.resolve()), str(owner_file.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Prompt registry {prompt_dir.name}/ is versioned and covered by CODEOWNERS.",
        remediation="Keep prompt changes in normal review flow.",
        evidence_sources=[str(prompt_dir.resolve()), str(owner_file.resolve())],
        confidence="medium",
    )


def eval_ai_agent_004(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-004: Prompt injection test fixtures present."""
    found: list[Path] = []
    for pat in _AI_AGENT_TEST_PATTERNS:
        with contextlib.suppress(OSError):
            for p in (ctx.repo_root / "tests").rglob(pat):
                if p.is_file():
                    found.append(p)
    security_tests = ctx.repo_root / "tests" / "security"
    if security_tests.is_dir():
        with contextlib.suppress(OSError):
            found.extend(p for p in security_tests.rglob("*") if p.is_file())
    if not found:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompt-injection, jailbreak, red-team, or adversarial test fixture found.",
            remediation="Add security tests covering prompt injection and tool-misuse cases.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(found)} agent adversarial/security test file(s) detected.",
        remediation="Refresh the corpus as agent capabilities and tools change.",
        evidence_sources=[str(p.resolve()) for p in found[:5]],
        confidence="low",
    )


def eval_ai_agent_005(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-005: Output sanitization layer documented."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "output-sanitization.json", "AI agent output sanitization")
    if outcome is not None:
        return outcome
    assert data is not None
    applied_to = data.get("applied_to")
    if data.get("method") and isinstance(applied_to, list) and applied_to and data.get("bypass_review_process"):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Output sanitization evidence documents method, covered surfaces, and bypass review process.",
            remediation="Refresh this evidence when output channels or bypass criteria change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="output-sanitization.json is missing method, applied_to, or bypass_review_process.",
        remediation="Populate all required output-sanitization fields.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_006(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-006: Rate limiting / quota config present."""
    matched = _find_any_text_hint(ctx.repo_root, _AI_AGENT_RATE_LIMIT_HINTS)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No agent rate-limit, quota, throttle, or token budget signal detected.",
            remediation="Document or configure per-agent rate limits and token/request quotas.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Rate-limit / quota signal detected in {len(matched)} file(s).",
        remediation="Keep quotas aligned with model/provider limits and abuse cases.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_ai_agent_007(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-007: Audit log of tool calls implemented."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "audit-log-config.json", "AI agent audit log")
    if outcome is not None:
        return outcome
    assert data is not None
    retention = data.get("retention_days")
    if data.get("destination") and isinstance(retention, int) and retention > 0 and data.get("pii_redaction") is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Tool-call audit logging evidence present with {retention} day retention and PII redaction.",
            remediation="Verify the destination is monitored and access-controlled.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="audit-log-config.json is missing destination, positive retention_days, or pii_redaction=true.",
        remediation="Populate audit-log evidence with destination, retention_days, and pii_redaction.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_008(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-008: Agent identity / authn configured."""
    antipatterns = _find_any_text_hint(ctx.repo_root, _AI_AGENT_IDENTITY_ANTIPATTERNS)
    if antipatterns:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Agent identity anti-pattern detected (user credential or token passthrough).",
            remediation="Use a dedicated agent identity or service account with audience-bound tokens.",
            evidence_sources=[str(p.resolve()) for p in antipatterns],
            confidence="medium",
        )
    matched = _find_any_text_hint(ctx.repo_root, _AI_AGENT_IDENTITY_HINTS)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No dedicated agent identity, service account, OIDC, or audience-bound token signal detected.",
            remediation="Configure agent identity separately from end-user credentials.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Dedicated agent identity/authn signal detected in {len(matched)} file(s).",
        remediation="Keep agent credentials least-privileged and rotate them through platform identity.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_ai_agent_009(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-009: Sensitive context not in agent memory."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "memory-policy.json", "AI agent memory policy")
    if outcome is not None:
        return outcome
    assert data is not None
    excluded = data.get("excluded_context_types")
    retention = str(data.get("retention_policy", "")).strip()
    if isinstance(excluded, list) and excluded and retention:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Memory policy excludes {len(excluded)} sensitive context type(s).",
            remediation="Review the excluded context list when new tools or memory stores are added.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="memory-policy.json is missing excluded_context_types or retention_policy.",
        remediation="Document what must never enter long-term agent memory and how memory is retained/purged.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_010(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-010: Model + version pinning enforced."""
    model_files: list[Path] = []
    unpinned: list[Path] = []
    for p in _iter_ai_agent_text_files(ctx.repo_root):
        text = _read_lower(p)
        if not text or not any(h in text for h in _AI_AGENT_MODEL_HINTS):
            continue
        model_files.append(p)
        if _AI_AGENT_PINNED_MODEL_RE.search(text):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Version-pinned model identifier detected in {p.name}.",
                remediation="Review model pins intentionally; avoid floating aliases in release branches.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
        if "model" in text and any(h in text for h in ("gpt-", "claude", "gemini", "mistral", "llama")):
            unpinned.append(p)
    if unpinned:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Model configuration appears to use floating provider/model aliases without a dated or versioned pin."
            ),
            remediation="Pin the model identifier to a dated/versioned provider release where supported.",
            evidence_sources=[str(p.resolve()) for p in unpinned[:5]],
            confidence="medium",
        )
    if model_files:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Model-related files exist but no recognizable version-pinned model identifier was detected.",
            remediation="Document the model version in config or evidence so releases are reproducible.",
            evidence_sources=[str(p.resolve()) for p in model_files[:5]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No model configuration or pinned model identifier detected.",
        remediation="Add a model config that pins the provider/model version used by the agent.",
        evidence_sources=[],
        confidence="low",
    )


def eval_llm_ai_act_dev_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-DEV-002: development/design + training-data description (Annex IV section 2)."""
    return _annex_iv_section(
        ctx,
        "development_design",
        "section 2 (development, design choices, training/validation/test data)",
        "Populate 'development_design' in ai-system-technical-doc.json. See docs/eu-ai-act-readiness.md.",
    )


def eval_llm_ai_act_perf_004(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-PERF-004: performance metrics + accuracy (Annex IV section 4)."""
    return _annex_iv_section(
        ctx,
        "performance_metrics",
        "section 4 (performance metrics, accuracy, robustness)",
        "Populate 'performance_metrics' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_cyber_006(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-CYBER-006: cybersecurity measures (Annex IV section 6)."""
    return _annex_iv_section(
        ctx,
        "cybersecurity_measures",
        "section 6 (cybersecurity measures)",
        "Populate 'cybersecurity_measures' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_change_007(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-CHANGE-007: lifecycle change record (Annex IV section 7)."""
    return _annex_iv_section(
        ctx,
        "lifecycle_changes",
        "section 7 (lifecycle changes through the system's life)",
        "Populate 'lifecycle_changes' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_std_008(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-STD-008: applied harmonised standards (Annex IV section 7)."""
    return _annex_iv_section(
        ctx,
        "applied_standards",
        "applied harmonised standards (e.g. prEN 18286)",
        "Populate 'applied_standards' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_pmm_009(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-PMM-009: post-market monitoring plan (Annex IV section 8)."""
    return _annex_iv_section(
        ctx,
        "post_market_monitoring_plan",
        "section 8 (post-market monitoring plan)",
        "Populate 'post_market_monitoring_plan' in ai-system-technical-doc.json.",
    )


def eval_mcp_tool_hash_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-TOOL-HASH-001: MCP tool descriptions hash-pinned (tool-poisoning defense)."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("tool-description hash")
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "mcp-tool-descriptions.json"
    if evidence.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(evidence.read_text(encoding="utf-8"))
            text = json.dumps(data).lower() if data is not None else ""
            if "sha256" in text or "hash" in text:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="mcp-tool-descriptions.json pins tool-description hashes (tool-poisoning defense).",
                    remediation="Recompute and compare the hashes in CI on every MCP server change.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="medium",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no hash-pinned tool descriptions (mcp-tool-descriptions.json with sha256).",
        remediation=(
            "Record SHA-256 hashes of each MCP tool description in "
            ".oss-policy-kit/evidence/mcp-tool-descriptions.json and verify in CI. See docs/mcp-server-security.md."
        ),
        evidence_sources=[str(p.resolve()) for p in found[:2]],
        confidence="medium",
    )


def eval_mcp_confirm_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-CONFIRM-001: destructive operations require explicit confirmation."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("destructive-confirmation")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        (
            "requires confirmation",
            "require confirmation",
            "human_in_the_loop",
            "human-in-the-loop",
            "confirm before",
            "destructive",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Destructive-operation confirmation signal detected in {hit.name}.",
            remediation="Ensure every state-changing MCP tool enforces an explicit confirmation step.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no destructive-operation confirmation pattern found.",
        remediation="Require explicit user confirmation for destructive MCP tools. See docs/mcp-server-security.md.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_egress_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-EGRESS-001: MCP server egress allowlist documented."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("egress-allowlist")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        ("egress allowlist", "egress allow-list", "allowed_hosts", "allowed-hosts", "allowlist", "outbound allowlist"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP egress allowlist signal detected in {hit.name}.",
            remediation="Keep the egress allowlist tight; deny by default.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no egress allowlist documented.",
        remediation="Document an egress allowlist for the MCP server (deny-by-default). See docs/mcp-server-security.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_injection_test_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-INJECTION-TEST-001: prompt-injection / tool-poisoning tests present."""
    applicable, _ = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("injection-test")
    matches: list[Path] = []
    for base in ("tests", "test", "."):
        d = ctx.repo_root / base
        if not d.is_dir():
            continue
        with contextlib.suppress(OSError):
            for f in d.rglob("*.py"):
                name = f.name.lower()
                is_injection = "mcp" in name and "injection" in name
                is_poison = "tool_poison" in name or "tool-poison" in name or ("poisoning" in name and "tool" in name)
                if is_injection or is_poison:
                    matches.append(f)
    if matches:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"{len(matches)} MCP prompt-injection / tool-poisoning test file(s) detected.",
            remediation="Keep the injection test corpus updated with new attack patterns.",
            evidence_sources=[str(m.resolve()) for m in matches[:3]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no prompt-injection / tool-poisoning tests found.",
        remediation="Add tests like test_mcp_injection.py / test_tool_poisoning.py. See docs/mcp-server-security.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_scope_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-SCOPE-001: per-tool least-privilege scope documented."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("per-tool scope")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        ("least privilege", "least-privilege", '"scope"', "permissions", "scopes", "read-only", "readonly"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP per-tool scope / least-privilege signal detected in {hit.name}.",
            remediation="Document explicit scope per tool; avoid broad write/admin grants.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no per-tool least-privilege scope documented.",
        remediation="Document least-privilege scope per MCP tool. See docs/mcp-server-security.md.",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_goal_001(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-GOAL-001 (ASI01): goal/system-prompt version-controlled + integrity-checked."""
    applicable, _ = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI01 goal-manipulation")
    prompt_locations = [
        ctx.repo_root / "prompts",
        ctx.repo_root / "system_prompt.md",
        ctx.repo_root / "system_prompt.txt",
        ctx.repo_root / "SYSTEM_PROMPT.md",
    ]
    present = [p for p in prompt_locations if p.exists()]
    if present:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Version-controlled system prompt / goal definition detected ({present[0].name}).",
            remediation="Sign or hash the system prompt and verify integrity at load time (ASI01).",
            evidence_sources=[str(p.resolve()) for p in present[:2]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no version-controlled system prompt / goal file found.",
        remediation="Store the agent goal/system prompt under version control and integrity-check it (OWASP ASI01).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_tool_002(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-TOOL-002 (ASI02): tool allowlist + per-tool least privilege documented."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI02 tool-misuse")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        (
            "tool allowlist",
            "tool allow-list",
            "allowed tools",
            "least privilege",
            "least-privilege",
            "tool permissions",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Agent tool allowlist / least-privilege signal detected in {hit.name} (ASI02).",
            remediation="Keep the tool allowlist tight; scope each tool to least privilege.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no tool allowlist / least-privilege documentation found.",
        remediation="Document the agent tool allowlist with per-tool least privilege (OWASP ASI02).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_memory_006(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-MEMORY-006 (ASI06): persistent-memory purge / poisoning policy documented."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI06 memory-poisoning")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        ("memory purge", "memory retention", "memory poisoning", "memory hygiene", "purge policy", "clear memory"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Agent memory purge / poisoning policy signal detected in {hit.name} (ASI06).",
            remediation="Enforce the memory purge policy; validate writes to long-term memory.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no memory purge / poisoning policy documented.",
        remediation="Document a persistent-memory purge / poisoning-resistance policy (OWASP ASI06).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_inter_007(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-INTER-007 (ASI07): inter-agent communication mutual authentication signal."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI07 inter-agent communication")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        ("mutual auth", "mtls", "mutual tls", "agent-to-agent auth", "signed messages", "message signing"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Inter-agent mutual authentication signal detected in {hit.name} (ASI07).",
            remediation="Ensure all agent-to-agent channels enforce mutual authentication.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no inter-agent mutual authentication signal found.",
        remediation="Use mutual authentication (mTLS / signed messages) for inter-agent traffic (OWASP ASI07).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_confirm_009(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-CONFIRM-009 (ASI09): human checkpoint required for destructive operations."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI09 human-agent trust")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        (
            "human approval",
            "human-in-the-loop",
            "human in the loop",
            "human checkpoint",
            "requires approval",
            "manual approval",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Human-checkpoint signal for destructive operations detected in {hit.name} (ASI09).",
            remediation="Require a human checkpoint for irreversible / high-impact agent actions.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no human-checkpoint signal for destructive operations found.",
        remediation="Require human approval for destructive agent operations (OWASP ASI09).",
        evidence_sources=[],
        confidence="low",
    )
