from __future__ import annotations

from enum import Enum, auto
from typing import Any


class CLIBuilder(object):
    class cli(Enum):
        """
        Command line parameter types.
        """

        PLAIN = auto()
        """
        Use plain parameter value without any modification.
        """

        VALUE = auto()
        """
        Use parameter value but enclose it in quotes in script mode.
        """

        SWITCH = auto()
        """
        Parameter is a switch which is enabled if value is True.
        """

        POSITIONAL = auto()
        """
        Parameter is a positional argument.
        """

    def __init__(self, powershell: bool = False) -> None:
        self.__prefix: str = '-' if powershell else '--'
        self.__powershell: bool = powershell

    def command(self, command: str, args: dict[str, tuple[cli, Any]]) -> str:
        return ' '.join(self.__build(command, args, quote_value=True))

    def argv(self, command: str, args: dict[str, tuple[cli, Any]]) -> list[str]:
        return self.__build(command, args, quote_value=False)

    def __build(self, command: str, args: dict[str, tuple[cli, Any]], quote_value: bool) -> list[str]:
        def _get_option(name: str) -> str:
            return self.__prefix + name

        def _get_value(value: Any) -> str:
            return str(value) if not quote_value else f"'{value}'"

        argv = [command]
        for key, item in args.items():
            if item is None:
                continue

            (type, value) = item
            if value is None:
                continue

            match type:
                case self.cli.POSITIONAL:
                    argv.append(_get_value(value))
                case self.cli.SWITCH:
                    if self.__powershell:
                        argv.append(f'{_get_option(key)}:{"$True" if value else "$False"}')
                    else:
                        argv.append(_get_option(key))
                case self.cli.VALUE:
                    argv.append(_get_option(key))
                    argv.append(_get_value(value))
                case self.cli.PLAIN:
                    argv.append(_get_option(key))
                    argv.append(str(value))
                case _:
                    raise ValueError(f'Unknown option type: {type}')

        return argv
