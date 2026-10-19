#!/usr/bin/env python3
"""Replace only NovaProtect's BaoTa Nginx server blocks with the PHP-FPM app.

The parser is deliberately small but token-aware: braces inside comments and
quoted strings do not affect block matching. Unknown server directives are not
copied into the managed block, because stale rewrite/PHP/cache rules can change
the application behavior. Listen, server names, logs, and direct TLS settings
are retained verbatim.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


DOMAIN = "nova.fbi.plus"


@dataclass(frozen=True)
class Token:
    value: str
    raw: str
    start: int
    end: int


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "#":
            newline = source.find("\n", i)
            i = n if newline < 0 else newline + 1
            continue
        start = i
        if ch in "{};":
            i += 1
            tokens.append(Token(ch, ch, start, i))
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            value: list[str] = []
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    value.append(source[i + 1])
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                value.append(source[i])
                i += 1
            else:
                raise ValueError("Nginx 配置包含未闭合的引号。")
            raw = source[start:i]
            tokens.append(Token("".join(value), raw, start, i))
            continue

        value = []
        while i < n and not source[i].isspace() and source[i] not in "{};#\"'":
            if source[i] == "\\" and i + 1 < n:
                value.extend((source[i], source[i + 1]))
                i += 2
            else:
                value.append(source[i])
                i += 1
        if i == start:
            raise ValueError(f"无法解析 Nginx 配置字符位置 {i}。")
        raw = source[start:i]
        tokens.append(Token("".join(value), raw, start, i))
    return tokens


def matching_braces(tokens: list[Token]) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.value == "{":
            stack.append(index)
        elif token.value == "}":
            if not stack:
                raise ValueError("Nginx 配置存在多余的右花括号。")
            opening = stack.pop()
            pairs[opening] = index
    if stack:
        raise ValueError("Nginx 配置存在未闭合的花括号。")
    return pairs


def direct_statements(tokens: list[Token], opening: int, closing: int,
                      pairs: dict[int, int]) -> list[list[Token]]:
    statements: list[list[Token]] = []
    cursor = opening + 1
    while cursor < closing:
        start = cursor
        while cursor < closing:
            if tokens[cursor].value == "{":
                nested_close = pairs.get(cursor)
                if nested_close is None or nested_close >= closing:
                    raise ValueError("Nginx server block 的嵌套结构无效。")
                cursor = nested_close + 1
                break
            if tokens[cursor].value == ";":
                cursor += 1
                break
            if tokens[cursor].value == "}":
                raise ValueError("Nginx server block 的指令缺少分号。")
            cursor += 1
        if cursor <= start:
            raise ValueError("Nginx server block 中存在空指令。")
        statements.append(tokens[start:cursor])
    return statements


def statement_parts(statement: list[Token]) -> list[str]:
    return [token.value for token in statement if token.value not in {";", "{", "}"}]


def _has_target_name(statements: list[list[Token]]) -> bool:
    for statement in statements:
        parts = statement_parts(statement)
        if parts and parts[0] == "server_name":
            return any(name.lower() == DOMAIN for name in parts[1:])
    return False


def _preserved_directives(statements: list[list[Token]]) -> list[str]:
    keep: list[str] = []
    saw_server_name = False
    saw_listen = False
    tls = False
    has_certificate = False
    has_private_key = False
    for statement in statements:
        parts = statement_parts(statement)
        if not parts:
            continue
        name = parts[0]
        preserve = name in {
            "listen", "server_name", "access_log", "error_log", "charset",
            "server_tokens", "client_max_body_size", "client_body_timeout",
            "client_header_timeout", "send_timeout", "keepalive_timeout",
        } or name.startswith("ssl_")
        if not preserve:
            continue
        if name == "server_name":
            saw_server_name = True
        if name == "listen":
            saw_listen = True
            lowered = {part.lower() for part in parts[1:]}
            tls = tls or "ssl" in lowered or any(part == "443" or part.endswith(":443") for part in parts[1:])
        if name == "ssl_certificate" and len(parts) > 1:
            has_certificate = True
        if name == "ssl_certificate_key" and len(parts) > 1:
            has_private_key = True
        keep.append(" ".join(token.raw for token in statement).rstrip("; ") + ";")

    if tls and (not has_certificate or not has_private_key):
        raise ValueError(
            "nova.fbi.plus 的 TLS server block 未直接声明 ssl_certificate 和 "
            "ssl_certificate_key；为避免覆盖或猜测证书配置，已停止。"
        )
    if not saw_server_name:
        raise ValueError("目标 server block 缺少直接 server_name，已停止。")
    if not saw_listen:
        keep.insert(0, "listen 80;")
    return keep


def _render_block(directives: list[str], location_template: str, indent: str) -> str:
    inner = indent + "    "
    rows = [indent + "server {"]
    rows.extend(inner + directive for directive in directives)
    rows.extend(inner + line if line else "" for line in location_template.rstrip().splitlines())
    rows.append(indent + "}")
    return "\n".join(rows)


def configure(original: str, location_template: str, php_socket: str | None = None,
              document_root: str | None = None) -> str:
    if php_socket is not None:
        if not re.fullmatch(r"(?:unix:/[A-Za-z0-9_./-]+|[A-Za-z0-9_.-]+:[0-9]{1,5})", php_socket):
            raise ValueError("PHP-FPM socket/upstream 格式无效。")
        location_template = location_template.replace("@@PHP_SOCKET@@", php_socket)
    if document_root is not None:
        if not document_root.startswith("/") or re.search(r"[\s;{}'\"$]", document_root):
            raise ValueError("document root 必须是无空格、无 Nginx 特殊字符的绝对路径。")
        location_template = location_template.replace("@@DOCUMENT_ROOT@@", document_root.rstrip("/"))
    if "@@PHP_SOCKET@@" in location_template or "@@DOCUMENT_ROOT@@" in location_template:
        raise ValueError("Nginx 模板中仍有未替换的 PHP-FPM 参数。")

    tokens = tokenize(original)
    pairs = matching_braces(tokens)
    targets: list[tuple[int, int, list[list[Token]]]] = []
    for opening, closing in pairs.items():
        if opening == 0 or tokens[opening - 1].value.lower() != "server":
            continue
        statements = direct_statements(tokens, opening, closing, pairs)
        if _has_target_name(statements):
            targets.append((opening, closing, statements))

    if not targets:
        if original.strip():
            raise ValueError(f"未找到 server_name 精确包含 {DOMAIN} 的 Nginx server block。")
        base = ["listen 80;", f"server_name {DOMAIN};"]
        return _render_block(base, location_template, "") + "\n"

    replacements: list[tuple[int, int, str]] = []
    for opening, closing, statements in targets:
        start = tokens[opening - 1].start
        end = tokens[closing].end
        line_start = original.rfind("\n", 0, start) + 1
        indent_match = re.match(r"[ \t]*", original[line_start:start])
        indent = indent_match.group(0) if indent_match else ""
        directives = _preserved_directives(statements)
        replacements.append((start, end, _render_block(directives, location_template, indent)))

    result = original
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    if not result.endswith("\n"):
        result += "\n"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="existing Nginx vhost; a missing/empty file creates an HTTP vhost")
    parser.add_argument("--output", required=True, help="write the transformed config here")
    parser.add_argument("--php-socket", required=True, help="unix:/path/to/php-fpm.sock or 127.0.0.1:9000")
    parser.add_argument("--document-root", required=True, help="absolute path to the website public/ directory")
    parser.add_argument("--template", help="location template; defaults to nginx-location.conf next to this script")
    args = parser.parse_args(argv)
    try:
        source_path = Path(args.input)
        original = source_path.read_text(encoding="utf-8") if source_path.is_file() else ""
        template_path = Path(args.template) if args.template else Path(__file__).with_name("nginx-location.conf")
        template = template_path.read_text(encoding="utf-8")
        result = configure(original, template, args.php_socket, args.document_root)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(result)
        print(f"NGINX-CONFIG-READY ({len(result)} bytes; PHP-FPM; existing listen/TLS preserved)")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"NGINX-CONFIG-ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
