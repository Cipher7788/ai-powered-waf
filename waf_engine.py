import re


class WAFEngine:
    def __init__(self):
        self.rules = {
            'sql_injection': self.detect_sql_injection,
            'xss': self.detect_xss,
            'path_traversal': self.detect_path_traversal,
            'command_injection': self.detect_command_injection
        }

        self.sql_pattern = re.compile(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|UNION|EXEC|EXECUTE)\b'
            r'|(--)|(;)|(\bOR\b\s+\d+=\d+)|(\bAND\b\s+\d+=\d+)',
            re.IGNORECASE
        )

        self.xss_pattern = re.compile(
            r'<\s*script[^>]*>|javascript\s*:|on\w+\s*=|<\s*iframe[^>]*>|<\s*img[^>]+onerror',
            re.IGNORECASE
        )

        self.path_traversal_pattern = re.compile(
            r'\.\.[/\\]|%2e%2e[%2f%5c]|\.\.%2f|\.\.%5c',
            re.IGNORECASE
        )

        self.command_injection_pattern = re.compile(
            r'[;&|`$]|\$\(|\bwget\b|\bcurl\b|\bchmod\b|\brm\s+-',
            re.IGNORECASE
        )

    def _extract_strings(self, data, visited=None):
        """Recursively extract all string values from a dict, list, or string."""
        if visited is None:
            visited = set()
        obj_id = id(data)
        if obj_id in visited:
            return []
        visited.add(obj_id)

        if isinstance(data, str):
            return [data]
        if isinstance(data, dict):
            values = []
            for v in data.values():
                values.extend(self._extract_strings(v, visited))
            return values
        if isinstance(data, (list, tuple)):
            values = []
            for item in data:
                values.extend(self._extract_strings(item, visited))
            return values
        return [str(data)]

    def detect_sql_injection(self, request):
        # SQL Injection detection logic
        # Check for keywords like 'SELECT', 'INSERT', 'DROP', etc.
        for value in self._extract_strings(request):
            if self.sql_pattern.search(value):
                return True
        return False

    def detect_xss(self, request):
        # XSS detection logic
        # Check for '<script>', 'javascript:', etc.
        for value in self._extract_strings(request):
            if self.xss_pattern.search(value):
                return True
        return False

    def detect_path_traversal(self, request):
        # Path Traversal detection logic
        # Check for patterns like '../' or URL encoded characters
        for value in self._extract_strings(request):
            if self.path_traversal_pattern.search(value):
                return True
        return False

    def detect_command_injection(self, request):
        # Command Injection detection logic
        # Check for shell commands or unexpected input
        for value in self._extract_strings(request):
            if self.command_injection_pattern.search(value):
                return True
        return False

    def analyze_request(self, request):
        detected = []
        for rule_name, rule_func in self.rules.items():
            if rule_func(request):
                print(f'{rule_name} detected!')
                detected.append(rule_name)
        return detected
