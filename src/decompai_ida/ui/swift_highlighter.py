import typing as ty
from dataclasses import dataclass
from enum import Enum
from pygments.lexers import SwiftLexer
from pygments.token import Token, _TokenType

from decompai_ida import logger


class SwiftTokenType(Enum):
    """Token types for Swift syntax highlighting."""

    KEYWORD = "keyword"
    STRING = "string"
    COMMENT = "comment"
    NUMBER = "number"
    IDENTIFIER = "identifier"
    FUNCTION = "function"
    TYPE = "type"
    OPERATOR = "operator"
    PUNCTUATION = "punctuation"
    ATTRIBUTE = "attribute"
    DEFAULT = "default"


@dataclass
class HighlightedToken:
    """A token with its type and position information."""

    start_byte: int
    end_byte: int
    token_type: SwiftTokenType
    text: str


class SwiftHighlighter:
    """Pygments-based Swift syntax highlighter."""

    def __init__(self):
        self._lexer = SwiftLexer()

    def highlight(self, code: str) -> ty.Iterable[HighlightedToken]:
        """
        Highlight Swift code and return a list of tokens with their types.

        Args:
            code: Swift source code to highlight

        Returns:
            List of highlighted tokens with position and type information
        """
        try:
            for offset, token_type, text in self._lexer.get_tokens_unprocessed(
                code
            ):
                swift_token_type = self._map_pygments_token_to_swift_type(
                    token_type
                )

                # Find the actual position of this token in the code
                sub_token_start = offset
                sub_token_parts = text.split("\n")
                for part_index, sub_token_part in enumerate(sub_token_parts):
                    sub_token_end = sub_token_start + len(sub_token_part)
                    # If there are newlines, include it in the end_byte index
                    if (
                        len(sub_token_parts) > 1
                        and part_index != len(sub_token_parts) - 1
                    ):
                        sub_token_end += 1
                    yield HighlightedToken(
                        start_byte=sub_token_start,
                        end_byte=sub_token_end,
                        token_type=swift_token_type,
                        text=sub_token_part,
                    )
                    sub_token_start = sub_token_end
        except Exception as e:
            logger.error(f"Error highlighting Swift code: {e}")

    def _map_pygments_token_to_swift_type(
        self, pygments_token
    ) -> SwiftTokenType:
        """Map Pygments token types to our Swift token types."""

        # Map Pygments token types to our enum
        if token_is_any(
            pygments_token,
            (
                Token.Name.Class,
                Token.Name.Type,
                Token.Keyword.Type,
            ),
        ):
            return SwiftTokenType.TYPE
        elif pygments_token in Token.String:
            return SwiftTokenType.STRING
        elif pygments_token in Token.Comment:
            return SwiftTokenType.COMMENT
        elif pygments_token in Token.Number:
            return SwiftTokenType.NUMBER
        elif token_is_any(
            pygments_token, (Token.Name.Function, Token.Name.Method)
        ):
            return SwiftTokenType.FUNCTION
        elif pygments_token in Token.Operator:
            return SwiftTokenType.OPERATOR
        elif pygments_token in Token.Punctuation:
            return SwiftTokenType.PUNCTUATION
        elif token_is_any(
            pygments_token, (Token.Name.Decorator, Token.Name.Attribute)
        ):
            return SwiftTokenType.ATTRIBUTE
        elif pygments_token in Token.Keyword:
            return SwiftTokenType.KEYWORD
        elif pygments_token in Token.Name:
            return SwiftTokenType.IDENTIFIER
        else:
            return SwiftTokenType.DEFAULT


def token_is_any(token: _TokenType, any_of: tuple[_TokenType, ...]) -> bool:
    """Checks in a given token is any of the given types"""
    return any(token in token_type for token_type in any_of)
