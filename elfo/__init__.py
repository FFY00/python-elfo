# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import abc
import dataclasses
import io
import struct
import sys
import typing

from typing import Any, Dict, List, Optional, Tuple, Type, Union

from elfo._data import EI, ELFCLASS, ELFDATA, EM, ET, EV, OSABI, PF, PT, SHF, SHT
from elfo._memory import MemoryMap
from elfo._util import _Printable


if sys.version_info >= (3, 8):
    from typing import Literal, Protocol
else:
    from typing_extensions import Literal, Protocol


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
        obj = cls.from_bytes(data, e_ident)
        assert data == bytes(obj), (data, bytes(obj))
        return obj

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
        self.p_type = PT.from_value(self.p_type)
        self.p_flags = PF.from_value(self.p_flags)

    @staticmethod
    def _format(e_ident: ELFHeader.types.e_ident) -> str:
        if e_ident.file_class == ELFCLASS._32:
            return e_ident.endianess + 'IIIIIIII'
        elif e_ident.file_class == ELFCLASS._64:
            return e_ident.endianess + 'IIQQQQQQ'
        raise ValueError(f'Unkown class: {e_ident.file_class}')


@dataclasses.dataclass(repr=False)
class ELFSection(_Printable):
    """ELF file section."""

    header: ELFSectionHeader
    data: bytes

    @classmethod
    def from_fd(cls, fd: io.RawIOBase, header: ELFHeader, num: int) -> ELFSection:
        fd.seek(header.e_shoff + (header.e_shentsize * num))
        sh = ELFSectionHeader.from_fd(fd, header.e_ident)
        fd.seek(sh.sh_offset)
        if sh.sh_type == SHT.NOBITS or not sh.sh_size:
            return cls(sh, bytes())
        data = fd.read(sh.sh_size)
        assert data
        return cls(sh, data)

    @classmethod
    def multiple_from_fd(cls, fd: io.RawIOBase, header: ELFHeader) -> List[ELFSection]:
        return [cls.from_fd(fd, header, i) for i in range(header.e_shnum)]


@dataclasses.dataclass(repr=False)
class ELFSegment(_Printable):
    """ELF file segment."""

    header: ELFProgramHeader
    data: bytes

    @classmethod
    def from_fd(cls, fd: io.RawIOBase, header: ELFHeader, num: int) -> ELFSegment:
        fd.seek(header.e_phoff + (header.e_phentsize * num))
        ph = ELFProgramHeader.from_fd(fd, header.e_ident)
        fd.seek(ph.p_offset)
        if ph.p_filesz:
            data = fd.read(ph.p_filesz)
            assert data
        else:
            data = bytes()
        return cls(ph, data)

    @classmethod
    def multiple_from_fd(cls, fd: io.RawIOBase, header: ELFHeader) -> List[ELFSegment]:
        return [cls.from_fd(fd, header, i) for i in range(header.e_phnum)]

    @property
    def align(self) -> int:
        if self.header.p_align in (0, 1):
            return 0
        return self.header.p_align


class _IntoBytes(Protocol):
    def __bytes__(self) -> bytes: ...


class _Memory():
    @dataclasses.dataclass
    class Pool():
        offset: int
        size: int

        def __contains__(self, other: Any) -> bool:
            return isinstance(other, int) and self.offset <= other <= (self.offset + self.size)

    def __init__(self, default_align: int = 0) -> None:
        self._default_align = default_align
        self._data = bytearray()
        self._free: List[_Memory.Pool] = []

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return self._tail

    @property
    def data(self) -> bytearray:
        return self._data.copy()

    @property
    def _tail(self) -> int:
        return len(self._data)

    def _align(self, address: int, align_number: int) -> int:
        if align_number == 0:
            return address
        unaligned_bytes = address % align_number
        if unaligned_bytes == 0:
            return address
        return address + (align_number - unaligned_bytes)

    def write(self, data_object: Union[bytes, _IntoBytes], align: Optional[int] = None) -> int:
        if align is None:
            align = self._default_align
        assert align is not None
        data = bytes(data_object)
        write_size = len(data)
        # try one of the free memory polls first
        for pool in self._free.copy():
            write_offset = self._align(pool.offset, align)
            if write_offset not in pool:
                print('> found free! writting to', hex(write_offset))
                self._data[write_offset:write_size] = data
                self._free.remove(pool)
                return write_offset
        # write to the tail
        write_offset = self._align(self._tail, align)
        if write_offset > self._tail:  # add skipped memory to the free memory pool list
            skip_bytes = write_offset - self._tail
            self._free.append(self.Pool(self._tail, skip_bytes))
            print('> skiping from', hex(self._tail), 'to', hex(write_offset - 1), f'(align to {hex(align)})')
            self._data += b'\x00' * skip_bytes
        print('> writting to', hex(write_offset))
        self._data[write_offset:write_size] = data
        return write_offset


@dataclasses.dataclass(repr=False)
class ELF(_Printable):
    """ELF file."""

    header: ELFHeader
    sections: List[ELFSection]
    segments: List[ELFSegment]
    string_table: ELFSection
    phdr: Optional[ELFSegment]

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELF:
        header = ELFHeader.from_fd(fd)
        sections = ELFSection.multiple_from_fd(fd, header)
        segments = ELFSegment.multiple_from_fd(fd, header)
        # debug
        print('looking for', hex(header.e_shoff), 'and', hex(header.e_phoff))
        for i, section in enumerate(sections):
            print(
                'section', i, 'at', hex(section.header.sh_offset), 'to',
                hex(section.header.sh_offset + section.header.sh_size),
            )
        for i, segment in enumerate(segments):
            print('segment', i, 'at', hex(segment.header.p_offset), not segment.data)
        # find PHDR
        phdr: Optional[ELFSegment] = None
        for i, segment in enumerate(segments):
            if segment.header.p_type == PT.PHDR:
                if phdr:
                    raise ELFException(f'Multiple PHDR segments: {segments.index(phdr)} and {i}')
                phdr = segment
        return cls(
            header,
            sections,
            segments,
            sections[header.e_shstrndx],
            phdr,
        )

    @classmethod
    def from_path(cls, path: str) -> ELF:
        with open(path, 'rb', buffering=False) as fd:
            assert isinstance(fd, io.RawIOBase)  # oh silly typeshed
            return cls.from_fd(fd)

    def __len__(self) -> int:
        return len(bytes(self))
        return len(self.header) + sum(
            len(section.header) + len(section.data)
            for section in self.sections
        ) + sum(
            len(segment.header) + len(segment.data)
            for segment in self.segments
        )

    @property
    def _section_headers_bytes(self) -> bytes:
        return b''.join(bytes(section.header) for section in self.sections)

    @property
    def _program_headers_bytes(self) -> bytes:
        return b''.join(bytes(segment.header) for segment in self.segments)

    def __bytes__(self) -> bytes:
        if self.phdr:
            assert self.segments[0] is self.phdr

        # TODO: check for memory overlap between segments and/or sections and bail out :(
        # find sections that use the same memory as segments
        duplicated_sections: Dict[int, ELFSegment] = {}
        duplicated_segments: Dict[int, ELFSegment] = {}
        for segment in self.segments:
            for index, overlap_section in enumerate(self.sections):
                if (
                    overlap_section.header.sh_offset == segment.header.p_offset
                    and overlap_section.header.sh_size == segment.header.p_filesz
                ):
                    duplicated_sections[index] = segment
            for index, overlap_segment in enumerate(self.segments):
                if segment is not overlap_segment and index in (0, 1):
                    print('-----')
                    print(segment, overlap_segment)
                if (
                    segment is not overlap_segment
                    and overlap_segment.header.p_offset == segment.header.p_offset
                    and overlap_segment.header.p_filesz == segment.header.p_filesz
                ):
                    duplicated_segments[index] = segment

        print('ELF.__bytes__')
        memory = _Memory(default_align=4 if self.header.e_ident.file_class == ELFCLASS._32 else 8)
        memory.write(self.header)

        print('header', hex(len(memory)))
        # program headers
        was = self.header.e_phoff
        self.header.e_phoff = memory.write(self._program_headers_bytes)
        print('ph headers', hex(self.header.e_phoff), 'was', hex(was))
        # segment data
        for i, segment in enumerate(self.segments):
            if segment is self.phdr:
                continue
            if i in duplicated_segments:
                segment.header.p_offset = duplicated_segments[i].header.p_offset
                print('segment', i, 'reused', hex(segment.header.p_offset), 'was', hex(was))
                continue
            was = segment.header.p_offset
            segment.header.p_offset = memory.write(segment.data, segment.align)
            print('segment', i, hex(segment.header.p_offset), 'was', hex(was))
        # section data
        for i, section in enumerate(self.sections):
            if i in duplicated_sections:
                section.header.sh_offset = duplicated_sections[i].header.p_offset
                print('section', i, 'reused', hex(section.header.sh_offset), 'was', hex(was))
                continue
            was = section.header.sh_offset
            section.header.sh_offset = memory.write(section.data)
            print('section', i, hex(section.header.sh_offset), 'was', hex(was))
        # section headers
        was = self.header.e_shoff
        self.header.e_shoff = memory.write(self._section_headers_bytes)
        print('sh headers', hex(self.header.e_shoff), 'was', hex(was))

        data = memory.data
        # update program headers
        if self.phdr:
            self.phdr.header.p_offset = self.header.e_phoff
            ph_data = self._program_headers_bytes
            self.phdr.data = ph_data
        else:
            ph_data = b''.join(bytes(segment.header) for segment in self.segments)
        size = self.header.e_phentsize
        data[self.header.e_phoff:size*self.header.e_phnum] = ph_data
        # update section count
        self.header.e_shnum = len(self.sections)
        if not self.header.e_shnum:
            self.header.e_shoff = 0
        # update segment count
        self.header.e_phnum = len(self.segments)
        if not self.header.e_phnum:
            self.header.e_phoff = 0
        # update string table index
        self.header.e_shstrndx = self.sections.index(self.string_table)
        # re-write header
        data[:len(self.header)] = bytes(self.header)
        return bytes(data)


@dataclasses.dataclass(repr=False)
class ELF(_Printable):  # noqa: F811
    """ELF file."""

    header: ELFHeader
    _memory: MemoryMap

    @classmethod
    def from_fd(cls, fd: io.RawIOBase) -> ELF:
        data = fd.read()
        assert data
        memory = MemoryMap(data)

        fd.seek(0)
        header = ELFHeader.from_fd(fd)
        sections = ELFSection.multiple_from_fd(fd, header)
        segments = ELFSegment.multiple_from_fd(fd, header)

        # default_align = 4 if header.e_ident.file_class == ELFCLASS._32 else 8
        default_align = 0

        # for i, segment in enumerate(segments):
        #     pprint((i, segment))
        # for i, section in enumerate(sections):
        #     pprint((i, section))

        for section in sections:
            memory.add_pool(section.header.sh_offset, section.header.sh_size, default_align)

        for segment in segments:
            # print(hex(segment.header.p_offset), hex(segment.header.p_filesz), hex(segment.align))
            pool = memory.add_pool(segment.header.p_offset, segment.header.p_filesz, segment.align)
            # constrain PHDR to start of data
            if segment.header.p_type == PT.PHDR:
                pool.offset = len(header)

        # keep offsets in sections that point to the header
        header_size = len(header)
        for pool in memory.pools:
            assert pool.original_offset is not None
            if pool.original_offset < header_size:
                pool.offset = pool.original_offset

        return cls(header, memory)

    @classmethod
    def from_path(cls, path: str) -> ELF:
        with open(path, 'rb', buffering=False) as fd:
            assert isinstance(fd, io.RawIOBase)  # oh silly typeshed
            return cls.from_fd(fd)

    def __bytes__(self) -> bytes:
        with self._memory.custom_modeler() as modeler:
            data_start = len(self.header)
            modeler.constraints += [
                offset >= data_start
                for pool, offset in modeler.offsets.items()
                if pool.offset is not None
            ]
            return bytes(self._memory)
