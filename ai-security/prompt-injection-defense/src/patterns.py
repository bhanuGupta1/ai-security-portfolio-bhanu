"""
Pattern Catalog — Prompt Injection Attack Signatures
======================================================
50+ documented attack patterns organized by attack type.
Each pattern includes a regex, severity level, attack category, and description.

Categories map to OWASP LLM01 (Prompt Injection) sub-types.
Severity: LOW (1), MEDIUM (2), HIGH (3), CRITICAL (4)
"""

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Pattern:
    id: str
    name: str
    pattern: str
    severity: Severity
    category: str
    description: str
    owasp_ref: str = "LLM01"
    flags: re.RegexFlag = re.IGNORECASE

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)


# =============================================================================
# CATEGORY 1: DIRECT INSTRUCTION OVERRIDE
# Attacker directly tells the LLM to ignore/override its system instructions.
# =============================================================================
DIRECT_OVERRIDE = [
    Pattern(
        id="D-001",
        name="Ignore Previous Instructions",
        pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier|your|the)\s+(instructions?|prompts?|directives?|guidelines?|rules?|constraints?)",
        severity=Severity.CRITICAL,
        category="direct_override",
        description="Classic instruction override attempt. Tells the model to discard its system prompt.",
    ),
    Pattern(
        id="D-002",
        name="Disregard System Prompt",
        pattern=r"disregard\s+(all\s+)?(your\s+)?(previous|prior|system|original|initial)?\s*(instructions?|prompts?|rules?|training|guidelines?)",
        severity=Severity.CRITICAL,
        category="direct_override",
        description="Explicit disregard command targeting system-level instructions.",
    ),
    Pattern(
        id="D-003",
        name="Override System Instructions",
        pattern=r"(override|bypass|circumvent|nullify|cancel|void|reset)\s+(your\s+)?(system\s+)?(instructions?|prompt|guidelines?|rules?|restrictions?|limitations?|safety)",
        severity=Severity.CRITICAL,
        category="direct_override",
        description="Override command explicitly targeting system instructions.",
    ),
    Pattern(
        id="D-004",
        name="Forget Your Instructions",
        pattern=r"forget\s+(everything|all)?\s*(you\s+(were|have\s+been)\s+)?(told|instructed|trained|given|taught)",
        severity=Severity.CRITICAL,
        category="direct_override",
        description="Instruction erasure attack — asks the model to forget prior context.",
    ),
    Pattern(
        id="D-005",
        name="New Instructions Follow",
        pattern=r"(your\s+)?(new|updated|revised|actual|real|true)\s+(instructions?|prompt|rules?|guidelines?|directives?)\s+(are|follow|below|:|is)",
        severity=Severity.HIGH,
        category="direct_override",
        description="Attempts to replace the system prompt by declaring 'new instructions'.",
    ),
    Pattern(
        id="D-006",
        name="Stop Being",
        pattern=r"stop\s+(being|acting\s+as|pretending\s+to\s+be)\s+(an?\s+)?(AI|assistant|chatbot|model|language model)",
        severity=Severity.HIGH,
        category="direct_override",
        description="Asks the model to drop its assistant persona/constraints.",
    ),
    Pattern(
        id="D-007",
        name="You Have No Restrictions",
        pattern=r"you\s+(have\s+)?(no\s+)?(restrictions?|limitations?|rules?|guidelines?|constraints?|filters?|safeguards?)",
        severity=Severity.HIGH,
        category="direct_override",
        description="False claim that the model has no restrictions — primes it to behave as if unconstrained.",
    ),
    Pattern(
        id="D-008",
        name="From Now On",
        pattern=r"from\s+(now\s+on|this\s+(point|moment)\s+(on|forward)|here\s+on\s+out),?\s+(you\s+(will|must|should|shall|are\s+to)|always|never|only)",
        severity=Severity.HIGH,
        category="direct_override",
        description="Attempts to override future behavior with a persistent instruction injection.",
    ),
    Pattern(
        id="D-009",
        name="Instead Do This",
        pattern=r"instead\s+(of\s+(following|doing|answering|responding|that|this),?\s+)?(you\s+should|just|please|now)\s+",
        severity=Severity.MEDIUM,
        category="direct_override",
        description="Redirect attack — substitutes the original task with an attacker-defined one.",
    ),
    Pattern(
        id="D-010",
        name="Pretend The Rules Don't Apply",
        pattern=r"pretend\s+(that\s+)?(the\s+)?(rules?|guidelines?|restrictions?|safety|constraints?|instructions?)\s+(don.t|do\s+not|doesn.t|no\s+longer)?\s*(apply|exist|matter)",
        severity=Severity.HIGH,
        category="direct_override",
        description="Asks the model to simulate a state where its safety guidelines are inactive.",
    ),
]

# =============================================================================
# CATEGORY 2: PERSONA INJECTION / ROLE-PLAY ATTACKS
# Attacker assigns a new identity to the model to bypass its guidelines.
# =============================================================================
PERSONA_INJECTION = [
    Pattern(
        id="P-001",
        name="DAN — Do Anything Now",
        pattern=r"\bDAN\b|do\s+anything\s+now|you\s+are\s+now\s+DAN|jailbreak\s+mode",
        severity=Severity.CRITICAL,
        category="persona_injection",
        description="DAN (Do Anything Now) jailbreak. Assigns an unconstrained AI persona.",
    ),
    Pattern(
        id="P-002",
        name="Act As Unrestricted AI",
        pattern=r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|unfiltered|unlimited|evil|malicious|rogue|jailbroken|free)\s+(AI|model|assistant|chatbot|version)",
        severity=Severity.CRITICAL,
        category="persona_injection",
        description="Assigns an explicitly unconstrained or malicious AI persona.",
    ),
    Pattern(
        id="P-003",
        name="Pretend You Are",
        pattern=r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI|system|model|person|expert|hacker|criminal)\s+(that|who|with|without)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Role-play injection setting up a persona to bypass restrictions.",
    ),
    Pattern(
        id="P-004",
        name="You Are Now",
        pattern=r"you\s+are\s+now\s+(an?\s+)?(different|new|evil|unethical|unrestricted|uncensored|alternate|other)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Declares a new identity for the model to override its behavior.",
    ),
    Pattern(
        id="P-005",
        name="Your True Self",
        pattern=r"(your\s+)?(true|real|inner|actual|underlying)\s+(self|nature|personality|identity|AI|model)\s+(has|is|doesn.t|do|can|would)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Appeals to a supposed 'true unconstrained self' to bypass guidelines.",
    ),
    Pattern(
        id="P-006",
        name="Simulate Unconstrained Mode",
        pattern=r"(simulate|emulate|roleplay|role.play)\s+(an?\s+)?(AI\s+)?(model|system|version|AI|assistant|chatbot)\s+(that|with|without|having)(\s+has)?\s+(no\s+)?(restrictions?|limitations?|filters?|safety|guidelines?|rules?)",
        severity=Severity.CRITICAL,
        category="persona_injection",
        description="Simulation frame to execute unconstrained behavior under guise of role-play.",
    ),
    Pattern(
        id="P-007",
        name="Developer / God Mode",
        pattern=r"(developer|admin|god|root|sudo|superuser|maintenance|debug|test)\s+(mode|override|access|prompt|instructions?|command)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Fake elevated privilege mode to bypass system restrictions.",
    ),
    Pattern(
        id="P-008",
        name="Evil Twin / Shadow Model",
        pattern=r"(evil|shadow|dark|unrestricted|uncensored)\s+(twin|version|copy|instance|mode)\s+(of\s+)?(you|yourself|the\s+AI|this\s+model)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Dual-personality attack asking the model to activate an 'evil' version of itself.",
    ),
    Pattern(
        id="P-009",
        name="Character Without Restrictions",
        pattern=r"play\s+(the\s+)?(character|role|part)\s+of\s+(someone|a\s+person|an?\s+\w+)\s+(who\s+)?(has\s+no|ignores?|doesn.t\s+follow|without)\s+(restrictions?|ethics|rules?|morals?|guidelines?)",
        severity=Severity.HIGH,
        category="persona_injection",
        description="Fictional character frame designed to detach restrictions from role-play.",
    ),
    Pattern(
        id="P-010",
        name="JAILBREAK / STAN Variants",
        pattern=r"\b(JAILBREAK|STAN|AIM|UCAR|BISH|KEVIN|ANTI-DAN|DUDE)\b",
        severity=Severity.CRITICAL,
        category="persona_injection",
        description="Named jailbreak personas from documented attack taxonomies.",
    ),
]

# =============================================================================
# CATEGORY 3: DELIMITER / CONTEXT CONFUSION ATTACKS
# Attacker uses special tokens, markers, or formatting to escape user context.
# =============================================================================
DELIMITER_ATTACKS = [
    Pattern(
        id="DL-001",
        name="SYSTEM Block Injection",
        pattern=r"(<\s*system\s*>|\[system\]|<<system>>|<\|system\|>|\bSYSTEM:\s)",
        severity=Severity.CRITICAL,
        category="delimiter_attack",
        description="Attempts to inject a SYSTEM-level message by mimicking system prompt delimiters.",
    ),
    Pattern(
        id="DL-002",
        name="INST / Human / Assistant Tags",
        pattern=r"(\[INST\]|\[\/INST\]|<\|user\|>|<\|assistant\|>|<\|human\|>|<human>|<assistant>|<<SYS>>|<</SYS>>|<\|im_start\|>|<\|im_end\|>)",
        severity=Severity.CRITICAL,
        category="delimiter_attack",
        description="Injects model-specific chat template tokens to manipulate conversation structure.",
    ),
    Pattern(
        id="DL-003",
        name="Prompt End Marker",
        pattern=r"(###\s*(end|stop|ignore|human|assistant|system|instruction)|---\s*(end|human|system|prompt)|={3,}\s*(end|stop|ignore))",
        severity=Severity.HIGH,
        category="delimiter_attack",
        description="Uses separator markers to signal end-of-prompt and inject new instructions.",
    ),
    Pattern(
        id="DL-004",
        name="XML Tag Injection",
        pattern=r"<(instructions?|task|command|directive|override|inject|payload|prompt|system_prompt)\s*>",
        severity=Severity.HIGH,
        category="delimiter_attack",
        description="Injects XML-like tags that some LLMs treat as special instruction markers.",
    ),
    Pattern(
        id="DL-005",
        name="Markdown Code Block Escape",
        pattern=r"```\s*(system|instructions?|prompt|directive|override)\s*\n",
        severity=Severity.MEDIUM,
        category="delimiter_attack",
        description="Uses code block markers with special labels to inject instructions.",
    ),
    Pattern(
        id="DL-006",
        name="Human Turn Spoofing",
        pattern=r"(\n|\r)(human|user|h):\s*\n",
        severity=Severity.HIGH,
        category="delimiter_attack",
        description="Spoofs a human turn marker to inject instructions that appear to come from a new user message.",
    ),
]

# =============================================================================
# CATEGORY 4: ENCODED / OBFUSCATED ATTACKS
# Attacker encodes malicious instructions to evade pattern matching.
# =============================================================================
ENCODED_ATTACKS = [
    Pattern(
        id="E-001",
        name="Base64 Encoded Content",
        pattern=r"(?:base64|decode|b64)[:\s]*([\w+/=]{20,})|[A-Za-z0-9+/]{40,}={0,2}",
        severity=Severity.MEDIUM,
        category="encoded_attack",
        description="Base64-encoded content that could hide injected instructions.",
    ),
    Pattern(
        id="E-002",
        name="Hex Encoded Instruction",
        pattern=r"(?:\\x[0-9a-f]{2}){8,}",
        severity=Severity.MEDIUM,
        category="encoded_attack",
        description="Hex-encoded sequences that could contain hidden instructions.",
    ),
    Pattern(
        id="E-003",
        name="Unicode Homoglyph Attack",
        pattern=r"[\u0430\u0435\u0456\u043e\u0440\u0441\u0443\u04cf]{3,}",  # Cyrillic lookalikes
        severity=Severity.MEDIUM,
        category="encoded_attack",
        description="Unicode homoglyphs that visually resemble Latin characters to bypass text filters.",
    ),
    Pattern(
        id="E-004",
        name="Leetspeak Injection",
        pattern=r"\b(1gn0r3|1gnor3|d1sr3gard|byp4ss|0v3rr1d3|j41lbr34k)\b",
        severity=Severity.MEDIUM,
        category="encoded_attack",
        description="Leetspeak substitution used to obfuscate known injection keywords.",
    ),
    Pattern(
        id="E-005",
        name="Reversed Text Attack",
        pattern=r"\b(erongi|dragsersid|edirrevo|kaerbliaJ)\b",
        severity=Severity.LOW,
        category="encoded_attack",
        description="Reversed text of known injection commands — some models process reversed text.",
    ),
]

# =============================================================================
# CATEGORY 5: INDIRECT INJECTION
# Malicious instructions embedded in external content the model retrieves/processes.
# =============================================================================
INDIRECT_INJECTION = [
    Pattern(
        id="I-001",
        name="Hidden Instructions in Content",
        pattern=r"note\s+to\s+(AI|assistant|model|language model|LLM)[:\s]*(ignore|disregard|instead|you\s+should|please)",
        severity=Severity.CRITICAL,
        category="indirect_injection",
        description="Instructions embedded in documents/data targeted at the AI processor rather than the human reader.",
    ),
    Pattern(
        id="I-002",
        name="AI-Targeted Instruction Embed",
        pattern=r"(attention|alert|warning|important)[:\s]+(AI|assistant|LLM|model)[:\s]+(ignore|disregard|instead|you\s+must|please\s+do)",
        severity=Severity.CRITICAL,
        category="indirect_injection",
        description="Indirect injection using attention-grabbing keywords followed by AI-targeted commands.",
    ),
    Pattern(
        id="I-003",
        name="Hidden Text Injection",
        pattern=r"(<!--.*?(ignore|instructions?|system|override).*?-->|/\*.*?(ignore|instructions?|override).*?\*/)",
        severity=Severity.HIGH,
        category="indirect_injection",
        description="Instructions hidden in HTML comments or code comments intended to be processed by the model.",
    ),
    Pattern(
        id="I-004",
        name="Whitespace Hidden Instructions",
        pattern=r"[ \t]{20,}(ignore|disregard|system|instruction|override)",
        severity=Severity.MEDIUM,
        category="indirect_injection",
        description="Instructions hidden after long whitespace runs to evade visual inspection.",
    ),
    Pattern(
        id="I-005",
        name="Tool Output Injection",
        pattern=r"(tool|function|plugin|api|search)\s+(output|result|response|returned)[:\s]*.*?(ignore|disregard|instead|you\s+should)",
        severity=Severity.HIGH,
        category="indirect_injection",
        description="Injection payload framed as output from a tool/plugin to gain elevated trust.",
    ),
]

# =============================================================================
# CATEGORY 6: CONTEXT MANIPULATION
# Manipulates model context or claimed authority to extract behavior changes.
# =============================================================================
CONTEXT_MANIPULATION = [
    Pattern(
        id="C-001",
        name="Hypothetical / Fiction Frame",
        pattern=r"(hypothetically|in\s+a\s+hypothetical|in\s+fiction|fictionally|in\s+a\s+story|in\s+a\s+game|in\s+a\s+movie|for\s+a\s+novel)[,\s]+(how\s+would|you\s+could|it.s\s+okay|you\s+can)",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Fiction/hypothetical framing to make restricted outputs seem acceptable.",
    ),
    Pattern(
        id="C-002",
        name="Educational Purpose Framing",
        pattern=r"for\s+(educational|research|academic|scientific|demonstration|awareness|training)\s+(purposes?|reasons?|context)[,\s]+(explain|show|tell|describe|provide|give\s+me|how\s+to)",
        severity=Severity.MEDIUM,
        category="context_manipulation",
        description="False educational framing to justify providing restricted information.",
    ),
    Pattern(
        id="C-003",
        name="Authority Claim",
        pattern=r"(as\s+(an?\s+)?(anthropic|openai|google|developer|administrator|researcher|security\s+researcher|red\s+team)\s+(employee|staff|engineer|member|researcher))[,\s]+(I\s+(need|require|am\s+authorized)|please|you\s+(must|should|can))",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Impersonates authority figures (AI company staff, admins) to claim elevated permissions.",
    ),
    Pattern(
        id="C-004",
        name="The Previous Message Was a Test",
        pattern=r"(the\s+)?(previous|last|prior|above)\s+(message|prompt|instruction|question|conversation)\s+(was\s+a|is\s+a)\s+(test|simulation|drill|exercise)[,\s.]",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Reframes prior context as a test to invalidate safety responses.",
    ),
    Pattern(
        id="C-005",
        name="Confidential Prompt Extraction",
        pattern=r"(reveal|show|print|output|display|repeat|tell\s+me|what\s+is|what\s+are)\s+(your|the|all\s+of\s+the)\s*(\w+\s+)?(system\s+)?(prompt|instructions?|guidelines?|rules?|context|training)\b",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Attempts to extract the system prompt or hidden instructions.",
    ),
    Pattern(
        id="C-006",
        name="Gaslighting the Model",
        pattern=r"(you\s+(actually|really|truly|previously|already|just)|earlier\s+you)\s+(said|agreed|told\s+me|confirmed|stated)\s+(that\s+you\s+(can|will|would|have\s+no)|it.s\s+okay)",
        severity=Severity.MEDIUM,
        category="context_manipulation",
        description="Gaslighting — falsely claiming the model previously agreed to do something restricted.",
    ),
    Pattern(
        id="C-007",
        name="Continuation Attack",
        pattern=r"(continue|keep\s+going|finish|complete|and\s+then)[:\s]+(ignore|disregard|without|bypass|skip\s+the)",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Continuation request combined with bypass instruction — embeds injection in a seemingly benign follow-up.",
    ),
    Pattern(
        id="C-008",
        name="Translation / Reword to Bypass",
        pattern=r"(translate|reword|rephrase|rewrite|express)\s+(this|the\s+following|it)\s+(without|removing|excluding|bypassing)\s+(any\s+)?(safety|restrictions?|filters?|warnings?|caveats?|refusals?)",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Asks the model to reformulate restricted content while removing its safety framing.",
    ),
    Pattern(
        id="C-009",
        name="Token Smuggling",
        pattern=r"(split|break|separate|divide)\s+(the\s+)?(word|phrase|text|instruction|command)\s+(into|across)\s+(parts?|characters?|tokens?|letters?)",
        severity=Severity.MEDIUM,
        category="context_manipulation",
        description="Asks the model to assemble a word/phrase from parts to evade keyword filters.",
    ),
    Pattern(
        id="C-010",
        name="Prompt Leak via Completion",
        pattern=r"(complete|finish|continue)\s+(the\s+)?(following\s+)?(sentence|text|passage|paragraph)[:\s]*(\[?system|\[?instruction|\[?prompt)",
        severity=Severity.HIGH,
        category="context_manipulation",
        description="Asks the model to complete a sentence that starts with a system prompt fragment, leaking hidden context.",
    ),
]

# =============================================================================
# CATEGORY 7: JAILBREAK TEMPLATES
# Documented multi-step jailbreak templates from public research.
# =============================================================================
JAILBREAK_TEMPLATES = [
    Pattern(
        id="J-001",
        name="Two Responses Trick",
        pattern=r"(provide|give|show)\s+(two|2)\s+(responses?|answers?|versions?)[:\s]+(one|the\s+first)\s+(following|with|that\s+follows)\s+(your\s+)?(guidelines?|rules?|restrictions?).+(one|the\s+(second|other))\s+(without|ignoring|bypassing)",
        severity=Severity.CRITICAL,
        category="jailbreak_template",
        description="Requests two parallel responses — one compliant, one not — to normalize the restricted output.",
    ),
    Pattern(
        id="J-002",
        name="Opposite Day",
        pattern=r"(opposite\s+day|today\s+is\s+opposite\s+day|for\s+opposite\s+day)[,\s]+(so\s+)?(yes\s+means\s+no|no\s+means\s+yes|you\s+(must|should|will)\s+(do|say)\s+the\s+opposite)",
        severity=Severity.HIGH,
        category="jailbreak_template",
        description="Opposite-day framing to invert model refusals into compliance.",
    ),
    Pattern(
        id="J-003",
        name="Story Character Does The Thing",
        pattern=r"(write|tell|describe)\s+a\s+(story|scene|chapter|part)\s+where\s+(a\s+character|someone|the\s+protagonist|the\s+villain|they)\s+(explains?|teaches?|shows?|describes?|provides?)\s+(step.by.step\s+)?(exactly\s+how\s+to|step.by.step\s+instructions?\s+for|detailed\s+instructions?\s+for|how\s+to\s+exactly)",
        severity=Severity.HIGH,
        category="jailbreak_template",
        description="Story wrapper where a fictional character provides the restricted real-world content.",
    ),
    Pattern(
        id="J-004",
        name="Grandma / Bedtime Story Exploit",
        pattern=r"(my\s+)?(grandmother|grandma|grandpa|late\s+father|deceased\s+relative)\s+(used\s+to\s+tell|would\s+always\s+tell|would\s+read\s+me|always\s+said)\s+(me\s+)?(bedtime\s+stories?|stories?\s+about|how\s+to)",
        severity=Severity.HIGH,
        category="jailbreak_template",
        description="Sentimental framing (deceased grandparent telling bedtime stories) to extract restricted content.",
    ),
    Pattern(
        id="J-005",
        name="Step By Step Without Restrictions",
        pattern=r"(step.by.step|step\s+\d+|detailed\s+instructions?\s+for|how\s+to\s+exactly|exact\s+steps?\s+to)\s+.{0,50}(without|ignoring|bypass|no\s+restrictions?|uncensored)",
        severity=Severity.CRITICAL,
        category="jailbreak_template",
        description="Requests detailed step-by-step instructions explicitly framed to bypass restrictions.",
    ),
    Pattern(
        id="J-006",
        name="Thought Experiment Bypass",
        pattern=r"(in\s+a\s+thought\s+experiment|as\s+a\s+thought\s+experiment|imagine\s+for\s+a\s+moment)[,\s]+(you\s+(have\s+no|can\s+ignore|are\s+free\s+from)|there\s+are\s+no)",
        severity=Severity.HIGH,
        category="jailbreak_template",
        description="Thought experiment frame used to temporarily remove model constraints.",
    ),
    Pattern(
        id="J-007",
        name="The Helpful AI Paradox",
        pattern=r"(a\s+truly\s+helpful|the\s+most\s+helpful|if\s+you\s+were\s+really\s+helpful)\s+(AI|assistant|model)\s+(would|should|must|could|will)\s+(not\s+refuse|always\s+answer|never\s+say\s+no|comply\s+with\s+everything)",
        severity=Severity.HIGH,
        category="jailbreak_template",
        description="Reframes refusal as unhelpfulness to pressure the model into compliance.",
    ),
    Pattern(
        id="J-008",
        name="Token Budget / Output Constraint",
        pattern=r"(respond\s+only\s+with|your\s+(entire\s+)?response\s+(must\s+be|is\s+only)|output\s+(only|just|exactly))[:\s]*(the\s+)?(code|instructions?|steps?|commands?|payload)\b",
        severity=Severity.MEDIUM,
        category="jailbreak_template",
        description="Output constraint that strips away safety framing by demanding bare output only.",
    ),
]


class PatternCatalog:
    """
    Full collection of all prompt injection attack patterns.
    Provides lookup, filtering, and statistics methods.
    """

    def __init__(self):
        self.all_patterns: list[Pattern] = (
            DIRECT_OVERRIDE
            + PERSONA_INJECTION
            + DELIMITER_ATTACKS
            + ENCODED_ATTACKS
            + INDIRECT_INJECTION
            + CONTEXT_MANIPULATION
            + JAILBREAK_TEMPLATES
        )
        self._compiled: dict[str, re.Pattern] = {}
        self._compile_all()

    def _compile_all(self):
        for pattern in self.all_patterns:
            try:
                self._compiled[pattern.id] = pattern.compile()
            except re.error as e:
                print(f"WARNING: Failed to compile pattern {pattern.id}: {e}")

    def get_by_category(self, category: str) -> list[Pattern]:
        return [p for p in self.all_patterns if p.category == category]

    def get_by_severity(self, min_severity: Severity) -> list[Pattern]:
        return [p for p in self.all_patterns if p.severity >= min_severity]

    def get_compiled(self, pattern_id: str) -> Optional[re.Pattern]:
        return self._compiled.get(pattern_id)

    def categories(self) -> list[str]:
        return sorted(set(p.category for p in self.all_patterns))

    def stats(self) -> dict:
        return {
            "total": len(self.all_patterns),
            "by_severity": {
                s.name: len([p for p in self.all_patterns if p.severity == s])
                for s in Severity
            },
            "by_category": {
                cat: len(self.get_by_category(cat)) for cat in self.categories()
            },
        }
