# pa-permission-obfuscator
Analyzes and suggests minimal permission changes to make existing access control policies less easily understood by potential attackers, while maintaining functionality. Uses techniques like role renaming and permission reordering based on policy analysis. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-obfuscator`

## Usage
`./pa-permission-obfuscator [params]`

## Parameters
- `-h`: Show help message and exit
- `--input`: No description provided
- `--rename-roles`: Enable role renaming to obfuscate their purpose.
- `--reorder-permissions`: Enable permission reordering within each role
- `--role-prefix`: No description provided
- `--output`: No description provided

## License
Copyright (c) ShadowStrikeHQ
