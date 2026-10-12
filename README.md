# tree-sitter-yara

A [tree-sitter](https://tree-sitter.github.io) grammar for
[YARA](https://virustotal.github.io/yara/) rules, covering YARA 4.5 and
[YARA-X](https://virustotal.github.io/yara-x/): `include`, `with`,
`defined`, `iequals`, `base64wide`, `xor(1-255)`, rule sets in `of`, and
hex strings with `~` and open jumps.

`queries/` holds highlights, injections (`regex` patterns, `comment`) and
folds, with the capture names of nvim-treesitter.

## Neovim

```lua
vim.api.nvim_create_autocmd('User', {
  pattern = 'TSUpdate',
  callback = function()
    require('nvim-treesitter.parsers').yara = {
      install_info = {
        url = 'https://github.com/dynamotn/tree-sitter-yara',
        queries = 'queries',
      },
    }
  end,
})
```

## Development

```sh
tree-sitter generate
tree-sitter test
```

It parses every rule of
[signature-base](https://github.com/Neo23x0/signature-base) and
[Yara-Rules](https://github.com/Yara-Rules/rules) without an error.
