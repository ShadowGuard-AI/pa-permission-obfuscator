# pa-permission-obfuscator
Takes a permission structure (a JSON object mapping role names to lists of paths) and produces an obfuscated copy: role names are replaced with random names, every path string is replaced with a random opaque token, and the order of roles is shuffled. The original role names and path strings do not appear in the output, and the output order gives no clue to the original mapping. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-obfuscator`

## Usage
`python3 main.py --input FILE [options]`

## Parameters
- `-h`: Show help message and exit
- `--input`, `-i`: (required) Path to the input file containing the permission structure (JSON format: {role: [path1, path2, ...]})
- `--rename-roles`: Enable the obfuscation transform. Required for any output: renaming replaces role names with random names and path strings with opaque tokens.
- `--reorder-permissions`: Also shuffle each role's path list. On its own, without `--rename-roles`, this is refused with exit 1, because reordering alone hides nothing.
- `--role-prefix`: Prefix for the random role names (default: Role).
- `--output`, `-o`: Path to the output file for the obfuscated structure. If not specified, the result is printed to the console. It may not be the input file; an output path that resolves to the input is refused with exit 1.
- `--mapping-output`: Path to a file where the role and path mapping is saved as JSON.

## Behaviour notes
- Reversal: without a mapping file, the obfuscated output cannot be reversed. The mapping is written only when `--mapping-output` names a file, and that file holds the original role names and path strings, so it must be protected exactly like the input.
- Logs carry counts only. The original and replacement role name lists are never logged, and the original structure is never printed next to the obfuscated one.
- A run with neither transform flag writes no copy of the input and exits non-zero with a plain no obfuscation performed message. An empty input object does the same.
- One token is used per distinct path, so two roles that shared a path still share a token in the output. The token itself reveals nothing about the path.

## License
See LICENSE.
