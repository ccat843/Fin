"""Minimal Solidity frontend for the supported verification subset.

This is intentionally not a general Solidity parser. It lowers a small,
deterministic subset used by the end-to-end demo: contract declarations, state
variables, functions, ``require(...)`` guards, ``msg.sender``, and simple
arithmetic assignments.
"""

from __future__ import annotations

import re

from contract_verifier.frontends.base import ContractFrontend
from contract_verifier.ir.schema import (
    ContractIR,
    Effect,
    ExprKind,
    Expression,
    Guard,
    Resource,
    SourceSpan,
    Transition,
)


class SolidityFrontend(ContractFrontend):
    def parse(self, source: str, *, file_name: str) -> ContractIR:
        stripped_source = self._strip_comments(source)
        contract_name, contract_body, contract_start = self._contract_body(stripped_source)
        resources = self._state_variables(contract_body, file_name, contract_start)
        resource_ids = {resource.id for resource in resources}
        transitions = self._functions(contract_body, file_name, contract_start, resource_ids)
        return ContractIR(
            id=contract_name or file_name,
            chain="evm",
            resources=tuple(resources),
            transitions=tuple(transitions),
            metadata={"frontend": "solidity", "source_file": file_name},
        )

    def _strip_comments(self, source: str) -> str:
        without_block_comments = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
        return re.sub(r"//.*", "", without_block_comments)

    def _contract_body(self, source: str) -> tuple[str | None, str, int]:
        match = re.search(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", source)
        if match is None:
            return None, source, 1
        open_brace = source.find("{", match.start())
        close_brace = self._matching_brace(source, open_brace)
        start_line = self._line_number(source, match.start())
        return match.group(1), source[open_brace + 1 : close_brace], start_line

    def _state_variables(self, body: str, file_name: str, base_line: int) -> list[Resource]:
        body_without_functions = self._blank_functions(body)
        resources: list[Resource] = []
        for match in re.finditer(
            r"\b(?P<type>u?int(?:\d+)?|address|bool)\s+"
            r"(?:(?:public|private|internal|external|immutable|constant)\s+)*"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;",
            body_without_functions,
        ):
            resources.append(
                Resource(
                    id=match.group("name"),
                    kind="state_variable",
                    type_name=match.group("type"),
                    source=self._span(body, file_name, base_line, match.start(), match.end()),
                )
            )
        return resources

    def _functions(
        self,
        body: str,
        file_name: str,
        base_line: int,
        resource_ids: set[str],
    ) -> list[Transition]:
        transitions: list[Transition] = []
        pattern = re.compile(
            r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
            r"\((?P<params>[^)]*)\)[^{;]*\{",
            flags=re.MULTILINE,
        )
        search_from = 0
        while match := pattern.search(body, search_from):
            open_brace = body.find("{", match.start())
            close_brace = self._matching_brace(body, open_brace)
            function_body = body[open_brace + 1 : close_brace]
            name = match.group("name")
            inputs = tuple(self._parameters(match.group("params"), body, file_name, base_line, match.start()))
            guards = tuple(self._guards(function_body, body, file_name, base_line, open_brace + 1, resource_ids))
            effects = tuple(self._effects(function_body, body, file_name, base_line, open_brace + 1, resource_ids))
            transitions.append(
                Transition(
                    id=name,
                    name=name,
                    chain="evm",
                    inputs=inputs,
                    guards=guards,
                    effects=effects,
                    source=self._span(body, file_name, base_line, match.start(), close_brace + 1),
                )
            )
            search_from = close_brace + 1
        return transitions

    def _parameters(
        self,
        parameters: str,
        body: str,
        file_name: str,
        base_line: int,
        function_start: int,
    ) -> list[Resource]:
        inputs: list[Resource] = []
        for raw_parameter in parameters.split(","):
            parts = raw_parameter.strip().split()
            if len(parts) < 2:
                continue
            type_name, name = parts[0], parts[-1]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                inputs.append(
                    Resource(
                        id=name,
                        kind="state_variable",
                        type_name=type_name,
                        mutable=False,
                        source=self._span(body, file_name, base_line, function_start, function_start),
                    )
                )
        return inputs

    def _guards(
        self,
        function_body: str,
        full_body: str,
        file_name: str,
        base_line: int,
        offset: int,
        resource_ids: set[str],
    ) -> list[Guard]:
        guards: list[Guard] = []
        for index, match in enumerate(re.finditer(r"\brequire\s*\((?P<args>.*?)\)\s*;", function_body), start=1):
            predicate_source = self._first_argument(match.group("args"))
            guards.append(
                Guard(
                    id=f"require_{index}",
                    predicate=self._expression(predicate_source, resource_ids),
                    description=f"require({predicate_source})",
                    source=self._span(full_body, file_name, base_line, offset + match.start(), offset + match.end()),
                )
            )
        return guards

    def _effects(
        self,
        function_body: str,
        full_body: str,
        file_name: str,
        base_line: int,
        offset: int,
        resource_ids: set[str],
    ) -> list[Effect]:
        effects: list[Effect] = []
        for match in re.finditer(
            r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^;]+);",
            function_body,
        ):
            target = match.group("target")
            if target not in resource_ids:
                continue
            value_source = match.group("value").strip()
            operation, value = self._assignment_effect(target, value_source, resource_ids)
            effects.append(
                Effect(
                    id=f"{target}_{operation}_{len(effects) + 1}",
                    resource_id=target,
                    operation=operation,
                    value=value,
                    source=self._span(full_body, file_name, base_line, offset + match.start(), offset + match.end()),
                )
            )
        return effects

    def _assignment_effect(
        self, target: str, value_source: str, resource_ids: set[str]
    ) -> tuple[str, Expression]:
        decrement_match = re.fullmatch(rf"{re.escape(target)}\s*-\s*(.+)", value_source)
        if decrement_match:
            return "decrement", self._expression(decrement_match.group(1), resource_ids)
        increment_match = re.fullmatch(rf"{re.escape(target)}\s*\+\s*(.+)", value_source)
        if increment_match:
            return "increment", self._expression(increment_match.group(1), resource_ids)
        return "assign", self._expression(value_source, resource_ids)

    def _expression(self, source: str, resource_ids: set[str]) -> Expression:
        text = self._strip_outer_parentheses(source.strip())
        for operator, kind in (
            ("==", ExprKind.EQ),
            ("!=", ExprKind.NEQ),
            (">=", ExprKind.GTE),
            ("<=", ExprKind.LTE),
            (">", ExprKind.GT),
            ("<", ExprKind.LT),
        ):
            split = self._split_top_level(text, operator)
            if split is not None:
                left, right = split
                return Expression(
                    kind=kind,
                    args=(self._expression(left, resource_ids), self._expression(right, resource_ids)),
                )
        for operator, kind in (("+", ExprKind.ADD), ("-", ExprKind.SUB)):
            split = self._split_top_level(text, operator)
            if split is not None:
                left, right = split
                return Expression(
                    kind=kind,
                    args=(self._expression(left, resource_ids), self._expression(right, resource_ids)),
                )
        if re.fullmatch(r"-?\d+", text):
            return Expression(kind=ExprKind.LITERAL, value=int(text))
        if text in {"true", "false"}:
            return Expression(kind=ExprKind.LITERAL, value=text == "true")
        if text == "msg.sender":
            return Expression(kind=ExprKind.CALLER)
        if text in resource_ids:
            return Expression(kind=ExprKind.READ, value=text)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
            return Expression(kind=ExprKind.SYMBOL, value=text)
        return Expression(kind=ExprKind.SYMBOL, value=text)

    def _first_argument(self, arguments: str) -> str:
        depth = 0
        for index, char in enumerate(arguments):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "," and depth == 0:
                return arguments[:index].strip()
        return arguments.strip()

    def _split_top_level(self, text: str, operator: str) -> tuple[str, str] | None:
        depth = 0
        index = len(text) - len(operator)
        while index >= 0:
            char = text[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
            if depth == 0 and text[index : index + len(operator)] == operator:
                if operator == "-" and index == 0:
                    index -= 1
                    continue
                return text[:index].strip(), text[index + len(operator) :].strip()
            index -= 1
        return None

    def _strip_outer_parentheses(self, text: str) -> str:
        while text.startswith("(") and text.endswith(")"):
            try_close = self._matching_brace(text, 0, open_char="(", close_char=")")
            if try_close != len(text) - 1:
                break
            text = text[1:-1].strip()
        return text

    def _blank_functions(self, body: str) -> str:
        blanked = list(body)
        pattern = re.compile(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)[^{;]*\{")
        search_from = 0
        while match := pattern.search(body, search_from):
            open_brace = body.find("{", match.start())
            close_brace = self._matching_brace(body, open_brace)
            for index in range(match.start(), close_brace + 1):
                if blanked[index] != "\n":
                    blanked[index] = " "
            search_from = close_brace + 1
        return "".join(blanked)

    def _matching_brace(
        self,
        text: str,
        open_index: int,
        *,
        open_char: str = "{",
        close_char: str = "}",
    ) -> int:
        depth = 0
        for index in range(open_index, len(text)):
            char = text[index]
            if char == open_char:
                depth += 1
            elif char == close_char:
                depth -= 1
                if depth == 0:
                    return index
        raise ValueError("Unmatched Solidity block delimiter")

    def _span(self, text: str, file_name: str, base_line: int, start: int, end: int) -> SourceSpan:
        return SourceSpan(
            file=file_name,
            start_line=base_line + self._line_number(text, start) - 1,
            end_line=base_line + self._line_number(text, end) - 1,
        )

    def _line_number(self, text: str, offset: int) -> int:
        return text.count("\n", 0, offset) + 1
