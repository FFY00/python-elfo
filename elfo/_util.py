# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import sys
import typing

from typing import Any, Dict, Sequence, Tuple, Type


if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


def even_hex_repr(value: int) -> str:
    hex_repr = f'{value:x}'
    hex_repr = ('0' * (len(hex_repr) % 2)) + hex_repr
    return f'0x{hex_repr}'


class _Printable():
    """Generates a nice repr showing the object attributes with support for nested objects.

    Might break / look bad if non _Printable attributes have multiple lines in their repr.
    """

    def _pad(self, level: int) -> str:
        return '  ' * level

    def _repr(self, level: int) -> str:
        def value_repr(value: Any) -> str:
            # custom printers
            if isinstance(value, list):
                value = _PrintableSequence(value)
            # print
            if isinstance(value, _Printable):
                return value._repr(level + 1)
            elif isinstance(value, bytes) and len(value) > 32:
                return f'<bytes: size={len(value)}>'
            elif isinstance(value, int) and not isinstance(value, _EnumItem):
                return even_hex_repr(value)
            return repr(value)

        return '{}(\n{}{})'.format(self._name, ''.join(
            '{}{}={},\n'.format(self._pad(level + 1), key, value_repr(value))
            for key, value in self._values.items()
        ), self._pad(level))

    @property
    def _name(self) -> str:
        return self.__class__.__name__

    @property
    def _values(self) -> Dict[Any, Any]:
        return {
            key: value
            for key, value in vars(self).items()
            if not key.startswith('_')
        }

    def __repr__(self) -> str:
        return self._repr(0)


class _PrintableSequence(_Printable):
    def __init__(self, sequence: Sequence[Any]) -> None:
        self.sequence = sequence

    @property
    def _name(self) -> str:
        return ''

    @property
    def _values(self) -> Dict[int, Any]:
        return dict(enumerate(self.sequence))


class _EnumItem(int):
    """Custom int that tracks the enum name."""

    name: str

    def __new__(cls, value: int, name: str) -> _EnumItem:
        obj = super().__new__(cls, value)
        obj.name = name
        return obj

    def __repr__(self) -> str:
        return f'<{self.name}: {int(self)}>'


class _EnumFlagItem(_EnumItem):
    """Like _EnumItem but holds flags."""

    def __repr__(self) -> str:
        return f'<{self.name}: {bin(self)}>'

    def __eq__(self, other: Any) -> bool:
        return bool(self & other)

    def __ne__(self, other: Any) -> bool:
        return not self == other


class _FlagMatch(int, _Printable):
    """Custom int tack tracks flags it matches."""

    flags: Sequence[_EnumFlagItem]

    def __new__(cls, value: int, flags: Sequence[_EnumFlagItem]) -> _FlagMatch:
        obj = super().__new__(cls, value)
        obj.flags = flags
        return obj

    @property
    def _values(self) -> Dict[str, Any]:
        return {
            flag.name: flag == self
            for flag in self.flags
        }


class _EnumRangeItem(typing.NamedTuple):
    """Inclusive range that tracks the enum name."""

    start: int
    stop: int
    name: str

    def __repr__(self) -> str:
        return f'<{self.name}: {even_hex_repr(self.start)}..{even_hex_repr(self.stop)}>'

    def __contains__(self, item: Any) -> bool:
        return isinstance(item, int) and item in range(self.start, self.stop+1)


DATA_TYPE_CLS = {
    'value': _EnumItem,
    'flag': _EnumFlagItem,
}


class _EnumMeta(type):
    def __new__(
        mcs,
        name: str,
        bases: Tuple[Any],
        dict_: Dict[str, Any],
        data_type: Literal['value', 'flag'] = 'value',
    ) -> _EnumMeta:
        item_cls = DATA_TYPE_CLS[data_type]

        def enum_item(value: Any, name: str) -> Any:
            if isinstance(value, int):
                return item_cls(value, name)
            elif isinstance(value, tuple):
                return _EnumRangeItem(value[0], value[1], name)
            return value

        new_dict = {
            key: enum_item(value, f'{name}.{key}')
            for key, value in dict_.items()
        }
        new_dict.update({'_item_cls': item_cls})
        return super().__new__(mcs, name, bases, new_dict)

    @property
    def value_dict(self) -> Dict[int, _EnumItem]:
        return {
            int(value): value
            for value in vars(self).values()
            if isinstance(value, _EnumItem)
        }


class _Enum(metaclass=_EnumMeta):
    _item_cls: Type[_EnumItem]

    @classmethod
    def from_value(cls, value: int) -> int:
        if cls._item_cls is _EnumFlagItem:
            return _FlagMatch(value, [
                value for value in vars(cls).values()
                if isinstance(value, _EnumFlagItem)
            ])

        for item in vars(cls).values():
            if isinstance(item, _EnumRangeItem) and value in item:
                return _EnumItem(value, item.name)
            elif item == value:
                assert isinstance(item, int)
                return item
        raise ValueError(f'Item not found for 0x{value:x} in {cls.__name__}')

    @classmethod
    def from_value_fallback(cls, value: int) -> int:
        """Like from_value, but falls back to value passed."""
        try:
            return cls.from_value(value)
        except ValueError:
            return value
