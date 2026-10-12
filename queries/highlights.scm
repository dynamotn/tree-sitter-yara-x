; Keywords

[
  "rule"
  "meta"
  "strings"
  "condition"
  "with"
] @keyword

[
  "import"
  "include"
] @keyword.import

(rule_modifier) @keyword.modifier

"for" @keyword.repeat

[
  "and"
  "or"
  "not"
  "defined"
  "of"
  "in"
  "at"
  "contains"
  "icontains"
  "startswith"
  "istartswith"
  "endswith"
  "iendswith"
  "iequals"
  "matches"
] @keyword.operator

[
  "all"
  "any"
  "none"
  "them"
] @keyword

(string_modifier) @attribute

; Names

(rule
  name: (identifier) @function)

(tag) @label

(meta_definition
  key: (identifier) @property)

[
  (string_identifier)
  (string_wildcard)
  (string_count_identifier)
  (string_offset_identifier)
  (string_length_identifier)
] @variable

(rule_set
  [
    (identifier)
    (rule_wildcard)
  ] @function)

(with_declaration
  name: (identifier) @variable)

(member_expression
  object: (identifier) @module)

(member_expression
  property: (identifier) @variable.member)

(call_expression
  function: (identifier) @function.builtin)

(call_expression
  function: (member_expression
    property: (identifier) @function.call))

[
  (filesize)
  (entrypoint)
] @constant.builtin

; Literals

(text_string) @string

(escape_sequence) @string.escape

(regex) @string.regexp

(regex_flags) @character.special

(hex_byte) @string.special

[
  (integer)
  (percentage)
] @number

(float) @number.float

(boolean) @boolean

(comment) @comment @spell

; Punctuation

[
  "=="
  "!="
  "<"
  "<="
  ">"
  ">="
  "+"
  "-"
  "*"
  "\\"
  "%"
  "|"
  "^"
  "&"
  "~"
  "<<"
  ">>"
  "="
  ".."
] @operator

[
  "("
  ")"
  "["
  "]"
  "{"
  "}"
] @punctuation.bracket

[
  ","
  "."
  ":"
] @punctuation.delimiter
