# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import contextlib
import dataclasses
import io
import struct
import sys

from typing import Any, Iterator, Tuple, Union

from elfo._data import EI, ELFCLASS, ELFDATA, EM, ET, EV, OSABI
from elfo._util import _Printable


if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


class ELFException(Exception):
    pass


class NotAnELF(ELFException):
    """File is not an ELF file."""

    def __init__(self, file: io.RawIOBase) -> None:
        super().__init__()
        self._file = file

    def __repr__(self) -> str:
        return f'File is not an ELF file: {self._file}'


def _unpack(description: Union[str, Tuple[str, ...]], fd: io.RawIOBase) -> Tuple[Any, ...]:
    if isinstance(description, tuple):
        unpack_format = ''.join(description)
    else:
        unpack_format = description
    data = fd.read(struct.calcsize(unpack_format))
    assert data
    return struct.unpack(unpack_format, data)


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

            def __post_init__(self) -> None:
                self.file_class = ELFCLASS.from_value(self.file_class)
                self.data_encoding = ELFDATA.from_value(self.data_encoding)
                self.os_abi = OSABI.from_value(self.os_abi)

            @classmethod
            def from_fd(cls, fd: io.RawIOBase) -> ELFHeader.types.e_ident:
                magic = fd.read(4)
                if magic != b'\x7fELF':
                    raise NotAnELF(fd)
                obj = cls(
                    b'\x7fELF',
                    *_unpack('BBBBB', fd),
                )
                fd.read(EI.NIDENT - EI.PAD + 1)
                return obj

            @property
            def endianess(self) -> str:
                """struct.unpack/pack character for the endianess."""
                if self.data_encoding == ELFDATA.LSB:
                    return '<'
                elif self.data_encoding == ELFDATA.LSB:
                    return '>'
                raise ValueError(f'Unkown endianess: {self.data_encoding}')

            @property
            def native(self) -> str:
                """struct.unpack/pack character for the native addresses.."""
                if self.file_class == ELFCLASS._32:
                    return 'I'
                elif self.file_class == ELFCLASS._64:
                    return 'Q'
                raise ValueError(f'Unkown class: {self.file_class}')

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
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phensize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    def __post_init__(self) -> None:
        self.e_type = ET.from_value(self.e_type)
        self.e_machine = EM.from_value(self.e_machine)
        self.e_version = EV.from_value_fallback(self.e_version)

    @staticmethod
    def _format(e_ident: ELFHeader.types.e_ident) -> str:
        return ''.join((
            e_ident.endianess,
            'HHI',
            e_ident.native,
            e_ident.native,
            e_ident.native,
            'IHHHHHH',
        ))

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELFHeader:
        e_ident = cls.types.e_ident.from_fd(fd)
        return cls(
            e_ident,
            *_unpack(cls._format(e_ident), fd),
        )

    def __bytes__(self) -> bytes:
        return bytes(self.e_ident) + struct.pack(
            self._format(self.e_ident),
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phensize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        )


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
