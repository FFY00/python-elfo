# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

from typing import Any, Dict, Tuple


class _Printable():
    """Generates a nice repr showing the object attributes with support for nested objects.

    Might break / look bad if non _Printable attributes have multiple lines in their repr.
    """

    def _pad(self, level: int) -> str:
        return '  ' * level

    def _repr(self, level: int) -> str:
        def value_repr(value: Any) -> str:
            if isinstance(value, _Printable):
                return value._repr(level + 1)
            elif isinstance(value, int) and not isinstance(value, _EnumItem):
                hex_repr = f'{value:x}'
                hex_repr = ('0' * (len(hex_repr) % 2)) + hex_repr
                return f'0x{hex_repr}'
            return repr(value)

        return '{}(\n{}{})'.format(self.__class__.__name__, ''.join(
            '{}{}={},\n'.format(self._pad(level + 1), key, value_repr(value))
            for key, value in vars(self).items()
        ), self._pad(level))

    def __repr__(self) -> str:
        return self._repr(0)


class _EnumItem(int):
    """Custom int that tracks the enum name."""

    name: str

    def __new__(cls, value: int, name: str) -> _EnumItem:
        obj = super().__new__(cls, value)
        obj.name = name
        return obj

    def __repr__(self) -> str:
        return f'<{self.name}: {int(self)}>'


class _EnumMeta(type):
    def __new__(mcs, name: str, bases: Tuple[Any], dict_: Dict[str, Any]):  # type: ignore
        return super().__new__(mcs, name, bases, {
            key: _EnumItem(value, f'{name}.{key}') if isinstance(value, int) else value
            for key, value in dict_.items()
        })

    @property
    def value_dict(self) -> Dict[int, _EnumItem]:
        return {
            int(value): value
            for value in vars(self).values()
            if isinstance(value, _EnumItem)
        }


class _Enum(metaclass=_EnumMeta):
    @classmethod
    def from_value(cls, value: int) -> _EnumItem:
        for item in vars(cls).values():
            if item == value:
                assert isinstance(item, _EnumItem)
                return item
        raise ValueError(f'Item not found for 0x{value:x} in {cls.__name__}')

    @classmethod
    def from_value_fallback(cls, value: int) -> int:
        """Like from_value, but falls back to value passed."""
        try:
            return cls.from_value(value)
        except ValueError:
            return value
