/**
 * @file Tree-sitter grammar for YARA rules: YARA 4.5 and YARA-X
 * @author Tran Duc Nam <dynamo.foss@gmail.com>
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

// Lowest binds loosest, as in YARA's own parser
const PREC = {
  or: 1,
  and: 2,
  not: 3,
  compare: 4,
  bit_or: 5,
  bit_xor: 6,
  bit_and: 7,
  shift: 8,
  add: 9,
  mul: 10,
  unary: 11,
  of: 12,
  postfix: 13,
};

const STRING_OPERATORS = [
  'contains',
  'icontains',
  'startswith',
  'istartswith',
  'endswith',
  'iendswith',
  'iequals',
  'matches',
];

/**
 * One or more `rule`, separated by `sep`
 * @param {RuleOrLiteral} rule
 * @param {string} sep
 */
const sepBy1 = (rule, sep) => seq(rule, repeat(seq(sep, rule)));

module.exports = grammar({
  name: 'yara',

  extras: ($) => [/\s/, $.comment],

  word: ($) => $.identifier,

  conflicts: (_) => [],

  rules: {
    source_file: ($) => repeat(choice($.import, $.include, $.rule)),

    import: ($) => seq('import', field('module', $.text_string)),

    include: ($) => seq('include', field('path', $.text_string)),

    rule: ($) =>
      seq(
        repeat(field('modifier', $.rule_modifier)),
        'rule',
        field('name', $.identifier),
        optional(seq(':', field('tags', $.tag_list))),
        '{',
        optional($.meta_section),
        optional($.strings_section),
        $.condition_section,
        '}',
      ),

    rule_modifier: (_) => choice('private', 'global'),

    tag_list: ($) => repeat1(alias($.identifier, $.tag)),

    meta_section: ($) => seq('meta', ':', repeat($.meta_definition)),

    meta_definition: ($) =>
      seq(
        field('key', $.identifier),
        '=',
        field(
          'value',
          choice(
            $.text_string,
            seq(optional('-'), choice($.integer, $.float)),
            $.boolean,
          ),
        ),
      ),

    strings_section: ($) => seq('strings', ':', repeat($.string_definition)),

    string_definition: ($) =>
      seq(
        field('name', $.string_identifier),
        '=',
        choice(
          seq(field('value', $.text_string), repeat($.string_modifier)),
          seq(field('value', $.hex_string), repeat($.string_modifier)),
          seq(field('value', $.regex), repeat($.string_modifier)),
        ),
      ),

    string_modifier: ($) =>
      choice(
        'nocase',
        'wide',
        'ascii',
        'fullword',
        'private',
        seq(
          'xor',
          optional(
            seq('(', $.integer, optional(seq('-', $.integer)), ')'),
          ),
        ),
        seq(
          choice('base64', 'base64wide'),
          optional(seq('(', $.text_string, ')')),
        ),
      ),

    condition_section: ($) => seq('condition', ':', $._expression),

    // Hex strings ---------------------------------------------------------

    hex_string: ($) => seq('{', repeat1($._hex_token), '}'),

    _hex_token: ($) => choice($.hex_byte, $.hex_jump, $.hex_alternative),

    // `4D`, `?A`, `??`, and `~4D` for any byte but that one
    hex_byte: (_) => token(/~?[0-9A-Fa-f?][0-9A-Fa-f?]/),

    // `[4]`, `[2-4]`, `[2-]`, `[-]`
    hex_jump: ($) =>
      seq(
        '[',
        optional(field('min', $.integer)),
        optional(seq('-', optional(field('max', $.integer)))),
        ']',
      ),

    hex_alternative: ($) =>
      seq('(', sepBy1(repeat1($._hex_token), '|'), ')'),

    // Conditions ----------------------------------------------------------

    _expression: ($) =>
      choice(
        $.binary_expression,
        $.unary_expression,
        $.of_expression,
        $.for_expression,
        $.with_expression,
        $.string_match,
        $.string_count,
        $._primary_expression,
      ),

    _primary_expression: ($) =>
      choice(
        $.boolean,
        $.integer,
        $.float,
        $.text_string,
        $.regex,
        $.filesize,
        $.entrypoint,
        $.identifier,
        $.string_identifier,
        $.string_offset,
        $.string_length,
        $.member_expression,
        $.subscript_expression,
        $.call_expression,
        $.parenthesized_expression,
      ),

    binary_expression: ($) => {
      const table = [
        [PREC.or, 'or'],
        [PREC.and, 'and'],
        [PREC.compare, choice('==', '!=', '<', '<=', '>', '>=')],
        [PREC.compare, choice(...STRING_OPERATORS)],
        [PREC.bit_or, '|'],
        [PREC.bit_xor, '^'],
        [PREC.bit_and, '&'],
        [PREC.shift, choice('<<', '>>')],
        [PREC.add, choice('+', '-')],
        // `\` divides: `/` always opens a regular expression
        [PREC.mul, choice('*', '\\', '%')],
      ];
      return choice(
        ...table.map(([precedence, operator]) =>
          prec.left(
            /** @type {number} */ (precedence),
            seq(
              field('left', $._expression),
              field('operator', /** @type {RuleOrLiteral} */ (operator)),
              field('right', $._expression),
            ),
          ),
        ),
      );
    },

    unary_expression: ($) =>
      choice(
        prec(
          PREC.not,
          seq(field('operator', choice('not', 'defined')), $._expression),
        ),
        prec(PREC.unary, seq(field('operator', choice('-', '~')), $._expression)),
      ),

    // `$a`, `$a at 0`, `$a in (0..100)`
    string_match: ($) =>
      prec.right(
        PREC.postfix,
        seq(
          $.string_identifier,
          choice(
            seq('at', field('offset', $._expression)),
            seq('in', field('range', $.range)),
          ),
        ),
      ),

    // `#a`, `#a in (0..100)`
    string_count: ($) =>
      prec.right(
        PREC.postfix,
        seq(
          alias($._string_count_name, $.string_count_identifier),
          optional(seq('in', field('range', $.range))),
        ),
      ),

    // `@a`, `@a[1]`
    string_offset: ($) =>
      prec.right(
        seq(
          alias($._string_offset_name, $.string_offset_identifier),
          optional(seq('[', field('index', $._expression), ']')),
        ),
      ),

    // `!a`, `!a[1]`
    string_length: ($) =>
      prec.right(
        seq(
          alias($._string_length_name, $.string_length_identifier),
          optional(seq('[', field('index', $._expression), ']')),
        ),
      ),

    member_expression: ($) =>
      prec(
        PREC.postfix,
        seq(
          field('object', $._primary_expression),
          '.',
          field('property', $.identifier),
        ),
      ),

    subscript_expression: ($) =>
      prec(
        PREC.postfix,
        seq(
          field('object', $._primary_expression),
          '[',
          field('index', $._expression),
          ']',
        ),
      ),

    call_expression: ($) =>
      prec(
        PREC.postfix,
        seq(field('function', $._primary_expression), $.arguments),
      ),

    arguments: ($) => seq('(', optional(sepBy1($._expression, ',')), ')'),

    parenthesized_expression: ($) => seq('(', $._expression, ')'),

    // `all of them`, `2 of ($a*)`, `50% of ($a, $b) in (0..100)`,
    // `any of (Rule1, Rule2*)`
    of_expression: ($) =>
      prec.right(
        PREC.of,
        seq(
          field('quantifier', $.quantifier),
          'of',
          field('set', choice($.string_set, $.rule_set)),
          optional(
            choice(
              seq('in', field('range', $.range)),
              seq('at', field('offset', $._expression)),
            ),
          ),
        ),
      ),

    quantifier: ($) =>
      choice('all', 'any', 'none', $.percentage, $._primary_expression),

    percentage: (_) => token(/\d+%/),

    string_set: ($) =>
      choice(
        'them',
        seq(
          '(',
          sepBy1(choice($.string_identifier, $.string_wildcard), ','),
          ')',
        ),
      ),

    rule_set: ($) =>
      seq('(', sepBy1(choice($.identifier, $.rule_wildcard), ','), ')'),

    // `for any of ($a*) : ($ at 0)`,
    // `for all i in (1..#a) : (@a[i] < 100)`
    for_expression: ($) =>
      seq(
        'for',
        field('quantifier', $.quantifier),
        choice(
          seq('of', field('set', $.string_set)),
          seq(
            field('variables', sepBy1($.identifier, ',')),
            'in',
            field('iterable', $._iterable),
          ),
        ),
        ':',
        '(',
        field('body', $._expression),
        ')',
      ),

    _iterable: ($) => choice($.range, $.enumeration, $._primary_expression),

    range: ($) =>
      seq(
        '(',
        field('start', $._expression),
        '..',
        field('end', $._expression),
        ')',
      ),

    // Two values at least: `(1)` is a parenthesized one
    enumeration: ($) =>
      seq('(', $._expression, repeat1(seq(',', $._expression)), ')'),

    // `with a = expr, b = expr : (body)`
    with_expression: ($) =>
      seq(
        'with',
        sepBy1($.with_declaration, ','),
        ':',
        '(',
        field('body', $._expression),
        ')',
      ),

    with_declaration: ($) =>
      seq(field('name', $.identifier), '=', field('value', $._expression)),

    // Tokens --------------------------------------------------------------

    identifier: (_) => /[A-Za-z_][A-Za-z0-9_]*/,

    // `$` alone is the string of a `for ... of` loop
    string_identifier: (_) => token(/\$[A-Za-z0-9_]*/),
    string_wildcard: (_) => token(/\$[A-Za-z0-9_]*\*/),
    rule_wildcard: (_) => token(/[A-Za-z_][A-Za-z0-9_]*\*/),
    _string_count_name: (_) => token(/#[A-Za-z0-9_]*/),
    _string_offset_name: (_) => token(/@[A-Za-z0-9_]*/),
    _string_length_name: (_) => token(/![A-Za-z0-9_]*/),

    filesize: (_) => 'filesize',
    entrypoint: (_) => 'entrypoint',
    boolean: (_) => choice('true', 'false'),

    // `10`, `0x1F`, `0o17`, `2MB`
    integer: (_) =>
      token(choice(/0x[0-9A-Fa-f]+/, /0o[0-7]+/, /\d+(KB|MB)?/)),

    float: (_) => token(/\d+\.\d+/),

    text_string: ($) =>
      seq(
        '"',
        repeat(choice($._string_content, $.escape_sequence)),
        token.immediate('"'),
      ),

    _string_content: (_) => token.immediate(prec(1, /[^"\\\n]+/)),

    escape_sequence: (_) =>
      token.immediate(seq('\\', choice(/x[0-9A-Fa-f]{2}/, /./))),

    // `/abc/is`: `/` never divides in YARA, so this is never ambiguous
    regex: ($) =>
      seq(
        '/',
        field('pattern', $.regex_pattern),
        token.immediate('/'),
        optional(field('flags', $.regex_flags)),
      ),

    regex_pattern: (_) =>
      token.immediate(prec(-1, /(\\.|\[(\\.|[^\]\\\n])*\]|[^\\\/\[\n])+/)),

    regex_flags: (_) => token.immediate(/[a-z]+/),

    comment: (_) =>
      token(
        choice(seq('//', /[^\n]*/), seq('/*', /[^*]*\*+([^/*][^*]*\*+)*/, '/')),
      ),
  },
});
