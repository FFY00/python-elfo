# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import abc
import copy
import dataclasses
import io
import struct
import sys
import typing

from typing import Any, List, Tuple, Type, Union

from elfo._data import EI, ELFCLASS, ELFDATA, EM, ET, EV, OSABI, SHF, SHT
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

            def __len__(self) -> int:
                return EI.NIDENT

            def __bytes__(self) -> bytes:
                return self.file_identification + struct.pack(
                    self.endianess + 'BBBBB',
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
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    def __post_init__(self) -> None:
        self.e_type = ET.from_value(self.e_type)
        self.e_machine = EM.from_value(self.e_machine)
        self.e_version = EV.from_value_fallback(self.e_version)

        if self.e_ehsize != len(self):
            raise ELFException(
                f'Invalid e_ehsize, got `{self.e_ehsize}` '
                f'but was expecting `{len(self)}`'
            )
        if self.e_shentsize != ELFSectionHeader.size(self.e_ident):
            raise ELFException(
                f'Invalid e_shentsize, got `{self.e_shentsize}` '
                f'but was expecting `{ELFSectionHeader.size(self.e_ident)}`'
            )

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

    def __len__(self) -> int:
        if self.e_ident.file_class == ELFCLASS._32:
            return 52
        elif self.e_ident.file_class == ELFCLASS._64:
            return 64
        raise ValueError(f'Unkown class: {self.e_ident.file_class}')

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
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        )


T = typing.TypeVar('T', bound='_DeriveSerialization')


class _DeriveSerialization(abc.ABC):
    """Helper class that derives the serialization methods from a use-given _format method."""

    _e_ident: ELFHeader.types.e_ident

    def __init__(self, _e_ident: ELFHeader.types.e_ident, *args: int) -> None:
        raise NotImplementedError('Must define a __init__ for _DeriveSerialization types')

    @staticmethod
    @abc.abstractmethod
    def _format(e_ident: ELFHeader.types.e_ident) -> str: ...

    @classmethod
    def from_bytes(cls: Type[T], data: bytes, e_ident: ELFHeader.types.e_ident) -> T:
        return cls(e_ident, *struct.unpack(cls._format(e_ident), data))

    @classmethod
    def from_fd(cls: Type[T], fd: io.RawIOBase, e_ident: ELFHeader.types.e_ident) -> T:
        data = fd.read(cls.size(e_ident))
        assert data
        return cls.from_bytes(data, e_ident)

    @classmethod
    def multiple_from_bytes(
        cls: Type[T],
        data: bytes,
        count: int,
        e_ident: ELFHeader.types.e_ident,
    ) -> List[T]:
        size = cls.size(e_ident)
        return [
            cls.from_bytes(data[i*size:(i+1)*size], e_ident)
            for i in range(count)
        ]

    @classmethod
    def size(cls, e_ident: ELFHeader.types.e_ident) -> int:
        return struct.calcsize(cls._format(e_ident))

    def __len__(self) -> int:
        return self.size(self._e_ident)

    def __bytes__(self) -> bytes:
        return struct.pack(
            self._format(self._e_ident),
            *tuple(
                value for key, value in vars(self).items()
                if not key.startswith('_')
            ),
        )


@dataclasses.dataclass(repr=False)
class ELFSectionHeader(_Printable, _DeriveSerialization):
    """ELF file section header."""

    _e_ident: ELFHeader.types.e_ident = dataclasses.field(compare=False)

    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    def __post_init__(self) -> None:
        self.sh_type = SHT.from_value_fallback(self.sh_type)
        self.sh_flags = SHF.from_value(self.sh_flags)

    @staticmethod
    def _format(e_ident: ELFHeader.types.e_ident) -> str:
        return ''.join((
            e_ident.endianess,
            'II',
            e_ident.native,
            e_ident.native,
            e_ident.native,
            e_ident.native,
            'II',
            e_ident.native,
            e_ident.native,
        ))


@dataclasses.dataclass(repr=False)
class ELFProgramHeader(_Printable, _DeriveSerialization):
    """ELF file program header."""

    _e_ident: ELFHeader.types.e_ident = dataclasses.field(compare=False)

    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    def __init__(
        self,
        _e_ident: ELFHeader.types.e_ident,
        *args: int,
    ) -> None:
        if len(args) != 8:
            raise ValueError(f'Required 8 arguments, got {len(args)}')
        self._e_ident = _e_ident
        if _e_ident.file_class == ELFCLASS._32:
            (
                self.p_type,
                self.p_offset,
                self.p_vaddr,
                self.p_paddr,
                self.p_filesz,
                self.p_memsz,
                self.p_flags,
                self.p_align,
            ) = args
        elif _e_ident.file_class == ELFCLASS._64:
            (
                self.p_type,
                self.p_flags,
                self.p_offset,
                self.p_vaddr,
                self.p_paddr,
                self.p_filesz,
                self.p_memsz,
                self.p_align,
            ) = args
        else:
            raise ValueError(f'Unknown class: {_e_ident.file_class}')

    @staticmethod
    def _format(e_ident: ELFHeader.types.e_ident) -> str:
        if e_ident.file_class == ELFCLASS._32:
            return e_ident.endianess + 'IIIIIIII'
        elif e_ident.file_class == ELFCLASS._64:
            return e_ident.endianess + 'IIQQQQQQ'
        raise ValueError(f'Unkown class: {e_ident.file_class}')


@dataclasses.dataclass(repr=False)
class ELF(_Printable):
    """ELF file."""

    header: ELFHeader
    section_headers: List[ELFSectionHeader]
    program_headers: List[ELFProgramHeader]
    data: bytearray

    def __post_init__(self) -> None:
        self._original_header = copy.copy(self.header)

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELF:
        header = ELFHeader.from_fd(fd)
        data = fd.read()
        assert data
        # section headers
        offset = header.e_shoff - len(header)
        section_headers = ELFSectionHeader.multiple_from_bytes(
            data[offset:offset+(header.e_shentsize*header.e_shnum)],
            header.e_shnum,
            header.e_ident,
        )
        # program headers
        offset = header.e_phoff - len(header)
        program_headers = ELFProgramHeader.multiple_from_bytes(
            data[offset:offset+(header.e_phentsize*header.e_phnum)],
            header.e_phnum,
            header.e_ident,
        )
        return cls(header, section_headers, program_headers, bytearray(data))

    @classmethod
    def from_path(cls, path: str) -> ELF:
        with open(path, 'rb', buffering=False) as fd:
            assert isinstance(fd, io.RawIOBase)  # oh silly typeshed
            return cls.from_fd(fd)

    def __len__(self) -> int:
        return len(self.header) + len(self.data)

    def __bytes__(self) -> bytes:
        if len(self.section_headers) > self._original_header.e_shnum:
            raise NotImplementedError('Cannot write more section headers than the file had originally')
        if len(self.program_headers) > self._original_header.e_phnum:
            raise NotImplementedError('Cannot write more program headers than the file had originally')

        # update the header
        self.header.e_shnum = len(self.section_headers)
        self.header.e_phnum = len(self.program_headers)

        # write section headers
        offset, size = self._offset(self.header.e_shoff), self.header.e_shentsize
        for i, sh in enumerate(self.section_headers):
            self.data[offset+(i*size):offset+((i+1)*size)] = bytes(sh)
        # write 0xff to the leftover space for easy identification
        if __debug__:
            leftover = self._original_header.e_shnum - self.header.e_shnum
            if leftover:
                start = self._original_header.e_shnum - leftover
                self.data[offset+(start*size):offset+(leftover*size)] = b'\xff' * ((leftover-start)*size)

        # write program headers
        offset, size = self._offset(self.header.e_phoff), self.header.e_phentsize
        for i, ph in enumerate(self.program_headers):
            self.data[offset+(i*size):offset+((i+1)*size)] = bytes(ph)
        # write 0xff to the leftover space for easy identification
        if __debug__:
            leftover = self._original_header.e_phnum - self.header.e_phnum
            if leftover:
                start = self._original_header.e_phnum - leftover
                self.data[offset+(start*size):offset+(leftover*size)] = b'\xff' * ((leftover-start)*size)

        return bytes(self.header) + self.data

    def _offset(self, absolute: int) -> int:
        """Given an absolute offset in the file, returns the offset in self.data."""
        return absolute - len(self.header)
