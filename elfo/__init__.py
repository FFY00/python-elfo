# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import contextlib
import dataclasses
import io
import struct
import sys

from typing import Any, Iterator, Tuple


if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


class _Printable():
    """Generates a nice repr showing the object attributes with support for nested objects.

    Might break / look bad if non _Printable attributes have multiple lines in their repr.
    """

    def _pad(self, level: int) -> str:
        return '  ' * level

    def _repr(self, level: int) -> str:
        return '{}(\n{}{})'.format(self.__class__.__name__, ''.join(
            '{}{}={},\n'.format(
                self._pad(level + 1),
                key,
                value._repr(level + 1) if isinstance(value, _Printable) else value,
            )
            for key, value in vars(self).items()
        ), self._pad(level))

    def __repr__(self) -> str:
        return self._repr(0)


class ELFException(Exception):
    pass


class NotAnELF(ELFException):
    """File is not an ELF file."""

    def __init__(self, file: io.RawIOBase) -> None:
        super().__init__()
        self._file = file

    def __repr__(self) -> str:
        return f'File is not an ELF file: {self._file}'


class EI:
    ## e_indent
    NIDENT = 0x0f  # size
    # indexes
    CLASS = 0x04
    DATA = 0x05
    VERSION = 0x06
    OSABI = 0x07
    ABIVERSION = 0x08
    PAD = 0x09


class ABI:
    SYSTEM_V = 0x00
    HP_UX = 0x01
    NETBSD = 0x02
    LINUX = 0x03
    GNU_HURD = 0x04
    SOLARIS = 0x06
    AIX = 0x07
    IRIX = 0x08
    FREEBSD = 0x09
    TRU64 = 0x0a
    NOVELL_MODESTO = 0x0b
    OPENBSD = 0x0c
    OPENVMS = 0x0d
    NONSTOP_KERNEL = 0x0e
    AROS = 0x0f
    FENIX_OS = 0x10
    CLOUDABI = 0x11
    STRATUS_OPENVOS = 0x12


def _unpack(description: str, size: int, fd: io.RawIOBase) -> Tuple[Any, ...]:
    data = fd.read(size)
    assert data
    return struct.unpack('BBBBB', data)


@dataclasses.dataclass(repr=False)
class ELFHeader(_Printable):
    """ELF file header."""

    class types:
        @dataclasses.dataclass(repr=False)
        class e_ident(_Printable):
            """ELF file header e_ident field."""

            file_identification: Literal[b'\x7fELF']
            file_class: int
            data_encoding: int
            file_version: int
            os_abi: int
            abi_version: int

            @classmethod
            def from_fd(cls, fd: io.RawIOBase) -> ELFHeader.types.e_ident:
                magic = fd.read(4)
                if magic != b'\x7fELF':
                    raise NotAnELF(fd)
                return cls(
                    b'\x7fELF',
                    *_unpack('BBBBB', 5, fd),
                )

            def __bytes__(self) -> bytes:
                return self.file_identification + struct.pack(
                    'BBBBB',
                    self.file_class,
                    self.data_encoding,
                    self.file_version,
                    self.os_abi,
                    self.abi_version,
                ) + b'\x00' * (EI.NIDENT - EI.PAD + 1)

    e_ident: types.e_ident

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELFHeader:
        return cls(cls.types.e_ident.from_fd(fd))

    def __bytes__(self) -> bytes:
        return bytes(self.e_ident)


@dataclasses.dataclass(repr=False)
class ELF(_Printable):
    """ELF file."""

    header: ELFHeader

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELF:
        return cls(ELFHeader.from_fd(fd))

    @classmethod
    @contextlib.contextmanager
    def from_path(cls, path: str) -> Iterator[ELF]:
        with open(path, 'rb', buffering=False) as fd:
            assert isinstance(fd, io.RawIOBase)  # oh silly typeshed
            yield cls.from_fd(fd)

    def __bytes__(self) -> bytes:
        return bytes(self.header)
