"""Rule-based request inspection with bounded decoding and nested payload support."""
import html
import re
from urllib.parse import unquote


class WAFEngine:
    def __init__(self):
        self.rules = {
            "sql_injection": self.detect_sql_injection,
            "xss": self.detect_xss,
            "path_traversal": self.detect_path_traversal,
            "command_injection": self.detect_command_injection,
        }
        self.sql_pattern = re.compile(
            r"(?:\bselect\b[\s\S]{0,120}\bfrom\b|\bunion\b\s+(?:all\s+)?\bselect\b|"
            r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|"
            r"alter\s+table|truncate\s+table|exec(?:ute)?\s*\()|"
            r"(?:--|/\*|\*/|;\s*(?:select|insert|update|delete|drop)\b)|"
            r"(?:['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+))",
            re.IGNORECASE,
        )
        self.xss_pattern = re.compile(
            r"<\s*(?:script|iframe|object|embed|svg|math)\b|"
            r"javascript\s*:|vbscript\s*:|data\s*:\s*text/html|"
            r"\bon[a-z]{3,}\s*=|<\s*img\b[^>]*\bonerror\s*=",
            re.IGNORECASE,
        )
        self.path_traversal_pattern = re.compile(
            r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c|/|\\)|\.\.%2f|\.\.%5c)",
            re.IGNORECASE,
        )
        self.command_injection_pattern = re.compile(
            r"(?:\$\(|\x60[^\x60]+\x60|(?:;|&&?|\|\|?|\n)\s*(?:bash|sh|zsh|curl|wget|nc|netcat|"
            r"python\b|perl\b|ruby\b|php\b|powershell\b|cmd\.exe|chmod\b|rm\b|"
            r"grep\b|cat\b|ls\b|whoami\b|id\b)|>\s*/(?:dev|etc|tmp)/)",
            re.IGNORECASE,
        )

    def _extract_strings(self, data):
        """Yield scalar text from nested JSON-like structures, including object keys."""
        if isinstance(data, str):
            yield data
        elif isinstance(data, dict):
            for key, value in data.items():
                yield from self._extract_strings(str(key))
                yield from self._extract_strings(value)
        elif isinstance(data, (list, tuple)):
            for item in data:
                yield from self._extract_strings(item)
        elif data is not None and isinstance(data, (int, float, bool)):
            yield str(data)

    @staticmethod
    def _normalise(value):
        current = html.unescape(value)
        for _ in range(3):
            decoded = unquote(current)
            if decoded == current:
                break
            current = html.unescape(decoded)
        return current

    def _matches(self, request, pattern):
        for value in self._extract_strings(request):
            if pattern.search(self._normalise(value)):
                return True
        return False

    def detect_sql_injection(self, request):
        return self._matches(request, self.sql_pattern)

    def detect_xss(self, request):
        return self._matches(request, self.xss_pattern)

    def detect_path_traversal(self, request):
        return self._matches(request, self.path_traversal_pattern)

    def detect_command_injection(self, request):
        return self._matches(request, self.command_injection_pattern)

    def analyze_request(self, request):
        return [name for name, rule in self.rules.items() if rule(request)]
