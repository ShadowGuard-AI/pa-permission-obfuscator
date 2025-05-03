import argparse
import logging
import os
import random
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
        Renames roles in the permission dictionary to obfuscate their purpose.

        Args:
            prefix (str): The prefix to use for the new role names. Defaults to "Role".

        Returns:
            Dict[str, List[str]]: A new permission dictionary with renamed roles.
        """
        new_permissions = {}
        for i, role in enumerate(self.permissions.keys()):
            new_role_name = f"{prefix}{i+1}"
            new_permissions[new_role_name] = self.permissions[role]
        logging.info(f"Renamed roles: {list(self.permissions.keys())} -> {list(new_permissions.keys())}")
        return new_permissions

    def reorder_permissions(self) -> Dict[str, List[str]]:
        """
        Reorders the permissions within each role's list to obfuscate the order.

        Returns:
            Dict[str, List[str]]: A new permission dictionary with reordered permissions.
        """
        new_permissions = {}
        for role, paths in self.permissions.items():
            new_paths = paths[:]  # Create a copy to avoid modifying the original
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

        # Create PermissionObfuscator instance
        obfuscator = PermissionObfuscator(permissions)
        obfuscated_permissions = permissions.copy() # Initialized to the original permissions to avoid errors if no obfuscation is applied

        # Apply obfuscation techniques based on arguments
        if args.rename_roles:
            renamed_roles = obfuscator.rename_roles(args.role_prefix)
            obfuscated_permissions = renamed_roles

        if args.reorder_permissions:
            reordered_permissions = obfuscator.reorder_permissions()
            obfuscated_permissions = reordered_permissions
        
        if args.rename_roles and args.reorder_permissions:
           obfuscator = PermissionObfuscator(permissions)
           renamed_roles = obfuscator.rename_roles(args.role_prefix)
           obfuscator = PermissionObfuscator(renamed_roles)
           reordered_permissions = obfuscator.reorder_permissions()
           obfuscated_permissions = reordered_permissions

        # Output the obfuscated permissions
        if args.output:
            try:
                with open(args.output, "w") as f:
                    import json
                    json.dump(obfuscated_permissions, f, indent=4)
                logging.info(f"Obfuscated permissions saved to: {args.output}")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")
                sys.exit(1)
        else:
            obfuscator.display_permissions(permissions=permissions, title="Original Permissions")
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