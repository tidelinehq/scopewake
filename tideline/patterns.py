"""Pattern tables. Values of secrets are NEVER stored; only kind and location."""
import re

NAME_RE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|passwd|credential|private[_-]?key|access[_-]?key|auth|bearer|dsn|connection[_-]?string)")

# (kind, regex, severity 1-10) matched against VALUES; the match itself is discarded.
VALUE_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 9),
    ("github-token", re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{36})\b"), 7),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"), 7),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 4),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b"), 4),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 5),
    ("stripe-live-key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{16,}\b"), 9),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 5),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 8),
    ("db-url-with-password", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^/\s:@]+:[^@\s]+@"), 8),
]

# Files that hold credentials by convention: (relative-to-home glob, kind, severity)
HOME_CRED_FILES = [
    (".aws/credentials", "aws-credentials-file", 9),
    (".aws/config", "aws-config", 3),
    (".config/gcloud/application_default_credentials.json", "gcp-adc", 9),
    (".azure/accessTokens.json", "azure-token-cache", 9),
    (".azure/msal_token_cache.json", "azure-token-cache", 9),
    (".kube/config", "kubeconfig", 9),
    (".ssh/id_rsa", "ssh-private-key", 8),
    (".ssh/id_ed25519", "ssh-private-key", 8),
    (".ssh/id_ecdsa", "ssh-private-key", 8),
    (".npmrc", "npm-config", 6),
    (".pypirc", "pypi-config", 6),
    (".docker/config.json", "docker-auth", 5),
    (".netrc", "netrc", 7),
    (".config/gh/hosts.yml", "github-cli-auth", 7),
    (".git-credentials", "git-credentials", 7),
]

# MCP server classification by name/command/args keywords -> (capability, severity, untrusted_input)
MCP_CLASSES = [
    (("filesystem", "server-filesystem"), "filesystem", 6, False),
    (("shell", "terminal", "exec", "bash"), "shell-execution", 9, False),
    (("github",), "github", 7, True),
    (("gitlab",), "gitlab", 7, True),
    (("puppeteer", "playwright", "browser", "chrome"), "browser-control", 7, True),
    (("fetch", "web", "search", "brave", "tavily", "firecrawl"), "web-content", 4, True),
    (("slack",), "slack", 5, True),
    (("gmail", "email", "mail", "outlook"), "email", 7, True),
    (("postgres", "postgresql", "mysql", "mariadb", "sqlite", "mongo", "mongodb", "supabase", "database", "redis", "dynamodb", "duckdb"), "database", 8, False),
    (("aws", "s3", "lambda"), "aws", 9, False),
    (("gcp", "gcloud", "bigquery"), "gcp", 9, False),
    (("azure",), "azure", 9, False),
    (("kubernetes", "k8s", "kubectl"), "kubernetes", 9, False),
    (("stripe", "payment", "paypal"), "payments", 9, False),
    (("notion", "confluence", "jira", "linear", "asana"), "workspace-docs", 4, True),
    (("docker",), "docker", 7, False),
    (("memory", "knowledge"), "memory-store", 2, False),
]
