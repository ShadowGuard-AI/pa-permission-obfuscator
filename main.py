import argparse
import json
import logging
import os
import random
import secrets
import sys
from typing import List, Dict

try:
    import pathspec
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
except ImportError as e:
    print(f"Error: Missing dependencies: {e}. Please install them using 'pip install pathspec rich'")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PermissionObfuscator:
    """
    Analyzes and suggests minimal permission changes to make existing access control policies less easily understood.
    """

    def __init__(self, permissions: Dict[str, List[str]]):
        """
        Initializes the PermissionObfuscator with a dictionary of permissions.
        Keys are roles, and values are lists of file paths.

        Args:
            permissions (Dict[str, List[str]]): A dictionary representing the current permission structure.
        """
        self.permissions = permissions
        self.console = Console()

    def rename_roles(self, prefix: str = "Role") -> Dict[str, List[str]]:
        """
        Renames roles in the permission dictionary to random names.

        Each new name is the prefix plus a random token. The names carry
        no sequence number and no relation to input order, so position in
        the output does not reveal which new name stands for which
        original role. The mapping is kept on the instance as
        role_mapping for the caller to persist only where the operator
        explicitly asks; it is never logged.

        Args:
            prefix (str): The prefix to use for the new role names. Defaults to "Role".

        Returns:
            Dict[str, List[str]]: A new permission dictionary with renamed roles.
        """
        new_permissions = {}
        self.role_mapping = {}
        used = set()
        for role in self.permissions.keys():
            new_role_name = f"{prefix}-{secrets.token_hex(4)}"
            # Eight hex characters is a small space when a file holds many roles, so the retry loop is not decoration. Without it a collision would silently merge two roles into one key and drop a whole permission list.
            while new_role_name in used:
                new_role_name = f"{prefix}-{secrets.token_hex(4)}"
            used.add(new_role_name)
            new_permissions[new_role_name] = self.permissions[role]
            self.role_mapping[role] = new_role_name
        # Counts only: the original and replacement name lists are the
        # mapping itself and are never written to the log.
        logging.info(f"Renamed {len(new_permissions)} roles with prefix '{prefix}'.")
        return new_permissions

    def obfuscate(self, prefix: str = "Role", reorder: bool = False):
        """
        Produces the obfuscated permission structure.

        Roles are renamed to random names, every path string is replaced
        with a random opaque token (one token per distinct path, used
        consistently), the role order in the result is shuffled, and
        each path list is shuffled when reorder is set. Nothing from the
        original role names or path strings appears in the result.

        Returns:
            A pair: the obfuscated dictionary, and the mapping dictionary
            with "roles" and "paths" entries. The mapping is the secret
            that reverses the transform; the caller persists it only to
            a file the operator explicitly names.
        """
        renamed = self.rename_roles(prefix)
        entries = list(renamed.items())
        # I use the system random source here, not the plain random module that reorder_permissions below uses. The role shuffle in the main transform should not be reproducible from a seed, while the standalone reorder helper predates that choice and still shuffles with random.
        rng = secrets.SystemRandom()
        rng.shuffle(entries)

        token_by_path: Dict[str, str] = {}
        result: Dict[str, List[str]] = {}
        for role, paths in entries:
            new_paths = []
            for path in paths:
                if path not in token_by_path:
                    token = f"path-{secrets.token_hex(8)}"
                    # Scanning the values on every new path makes this slower as the file grows, squarely so. I keep the simple form because the input is a policy file a person wrote, not a data set, and distinct tokens matter more here than speed.
                    while token in token_by_path.values():
                        token = f"path-{secrets.token_hex(8)}"
                    token_by_path[path] = token
                new_paths.append(token_by_path[path])
            if reorder:
                rng.shuffle(new_paths)
            result[role] = new_paths

        mapping = {"roles": dict(self.role_mapping), "paths": dict(token_by_path)}
        logging.info(f"Obfuscated {len(result)} roles and {len(token_by_path)} distinct paths.")
        return result, mapping

    def reorder_permissions(self) -> Dict[str, List[str]]:
        """
        Reorders the permissions within each role's list to obfuscate the order.

        Returns:
            Dict[str, List[str]]: A new permission dictionary with reordered permissions.
        """
        new_permissions = {}
        for role, paths in self.permissions.items():
            new_paths = paths[:]  # Create a copy to avoid modifying the original
            # The copy is the whole point of this helper being safe to call on the live structure. Shuffle works in place, and without the copy the callers original order would be gone.
            random.shuffle(new_paths)
            new_permissions[role] = new_paths
        logging.info("Reordered permissions within each role.")
        return new_permissions

    def apply_changes(self, renamed_roles: Dict[str, List[str]] = None, reordered_permissions: Dict[str, List[str]] = None) -> Dict[str, List[str]]:
        """
        Applies the renamed roles and reordered permissions to create a new permission dictionary.

        Args:
            renamed_roles (Dict[str, List[str]], optional): A dictionary with renamed roles. Defaults to None.
            reordered_permissions (Dict[str, List[str]], optional): A dictionary with reordered permissions. Defaults to None.

        Returns:
            Dict[str, List[str]]: The obfuscated permission dictionary.
        """
        new_permissions = self.permissions.copy()

        if renamed_roles:
            new_permissions = renamed_roles
            logging.info("Applied role renaming.")

        # Passing both arguments is a trap in this helper: the reorder result replaces the renamed result instead of combining with it. Main never calls this method at all, the live path is obfuscate above, so this stays as a library only wart.
        if reordered_permissions:
            new_permissions = reordered_permissions
            logging.info("Applied permission reordering.")

        return new_permissions

    def display_permissions(self, permissions: Dict[str, List[str]], title: str = "Permissions"):
          """
          Displays the given permissions in a Rich Panel.

          Args:
              permissions (Dict[str, List[str]]): The permissions dictionary to display.
              title (str, optional): The title of the panel. Defaults to "Permissions".
          """
          text = Text()
          for role, paths in permissions.items():
              text.append(f"[bold]{role}:[/bold]\n")
              for path in paths:
                  text.append(f"  - {path}\n")
              text.append("\n")
          self.console.print(Panel(text, title=title, border_style="blue"))


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes and suggests permission changes to make access control policies less easily understood."
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        required=True,
        help="Path to the input file containing the permission structure (JSON format: {role: [path1, path2, ...]})",
    )
    parser.add_argument(
        "--rename-roles",
        action="store_true",
        help="Enable role renaming to obfuscate their purpose.",
    )
    parser.add_argument(
        "--reorder-permissions",
        action="store_true",
        help="Enable permission reordering within each role's list.",
    )
    parser.add_argument(
        "--role-prefix",
        type=str,
        default="Role",
        help="Prefix for renamed roles (default: Role). Only applies if --rename-roles is used.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Path to the output file to save the obfuscated permission structure (JSON format). If not specified, the result is printed to the console.",
    )
    parser.add_argument(
        "--mapping-output",
        type=str,
        help="Path to a file where the role and path mapping is saved as JSON. This mapping is the secret that reverses the obfuscation; it is written only when this option names a file, and that file must be protected exactly like the input.",
    )

    return parser


def main():
    """
    Main function to execute the permission obfuscation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        if not os.path.exists(args.input):
            raise FileNotFoundError(f"Input file not found: {args.input}")

        # Load permissions from file
        with open(args.input, "r") as f:
            import json
            try:
                permissions = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON format in input file: {e}")

        if not isinstance(permissions, dict):
            raise ValueError("Input file must contain a JSON object (dictionary).")

        for role, paths in permissions.items():
            if not isinstance(role, str):
                raise ValueError("Role names must be strings.")
            if not isinstance(paths, list):
                raise ValueError("Permissions for each role must be a list.")
            for path in paths:
                if not isinstance(path, str):
                    raise ValueError("File paths must be strings.")

        # An empty object is valid JSON and passes every shape check above, so it needs its own refusal here. Without it the tool would write an empty result and report success for doing nothing.
        if not permissions:
            logging.error("Input holds no roles; no obfuscation was performed.")
            sys.exit(1)

        if not args.rename_roles and not args.reorder_permissions:
            logging.error("No obfuscation was requested: pass --rename-roles (optionally with --reorder-permissions). No output was written.")
            sys.exit(1)

        # Main refuses a reorder only run outright. Shuffled lists with real role and path names still in them hide nothing, and writing that out as an obfuscated file would give a false sense of cover.
        if args.reorder_permissions and not args.rename_roles:
            logging.error("Reordering alone does not hide role names or paths and is not an obfuscation. Pass --rename-roles, optionally with --reorder-permissions. No output was written.")
            sys.exit(1)

        # The output file, and the mapping file, may not replace the input.
        input_resolved = os.path.realpath(args.input)
        if args.output and os.path.realpath(args.output) == input_resolved:
            logging.error("Output path resolves to the input file itself; refusing to overwrite the input.")
            sys.exit(1)
        if args.mapping_output and os.path.realpath(args.mapping_output) == input_resolved:
            logging.error("Mapping output path resolves to the input file itself; refusing to overwrite the input.")
            sys.exit(1)
        if args.mapping_output and args.output and os.path.realpath(args.mapping_output) == os.path.realpath(args.output):
            logging.error("Mapping output path must differ from the obfuscated output path.")
            sys.exit(1)

        # Create PermissionObfuscator instance and run the transform.
        obfuscator = PermissionObfuscator(permissions)
        obfuscated_permissions, mapping = obfuscator.obfuscate(args.role_prefix, args.reorder_permissions)

        # The mapping is persisted only to a file the operator names here.
        if args.mapping_output:
            try:
                with open(args.mapping_output, "w") as f:
                    json.dump(mapping, f, indent=4)
                logging.info(f"Mapping saved to the operator named file: {args.mapping_output} ({len(mapping['roles'])} roles, {len(mapping['paths'])} paths). Protect this file exactly like the input.")
            except Exception as e:
                logging.error(f"Error writing to mapping output file: {e}")
                sys.exit(1)

        # Output the obfuscated permissions. Only the obfuscated result is
        # shown; the original is never printed beside it.
        if args.output:
            try:
                with open(args.output, "w") as f:
                    json.dump(obfuscated_permissions, f, indent=4)
                logging.info(f"Obfuscated permissions saved to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                sys.exit(1)
        else:
            obfuscator.display_permissions(permissions=obfuscated_permissions, title="Obfuscated Permissions")



    except FileNotFoundError as e:
        logging.error(str(e))
        sys.exit(1)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        sys.exit(1)

# Example Usage (add this within main() if you want this to run on every execution)
# permissions_data = {
#    "Administrators": ["/var/log/*", "/etc/shadow"],
#    "Users": ["/home/*/.bashrc", "/tmp/*"]
# }

# Rename roles
# obfuscator = PermissionObfuscator(permissions_data)
# renamed_roles = obfuscator.rename_roles(prefix="SecureGroup")
# obfuscator.display_permissions(renamed_roles, "Renamed Roles")

# Reorder permissions
# obfuscator = PermissionObfuscator(permissions_data)
# reordered_permissions = obfuscator.reorder_permissions()
# obfuscator.display_permissions(reordered_permissions, "Reordered Permissions")

# Both Rename roles and Reorder Permissions
# obfuscator = PermissionObfuscator(permissions_data)
# renamed_roles = obfuscator.rename_roles(prefix="SecureGroup")
# obfuscator = PermissionObfuscator(renamed_roles)
# reordered_permissions = obfuscator.reorder_permissions()
# obfuscator.display_permissions(reordered_permissions, "Renamed and Reordered Permissions")

if __name__ == "__main__":
    main()
