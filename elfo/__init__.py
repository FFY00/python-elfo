# SPDX-License-Identifier: EUPL-1.2

from __future__ import annotations

import contextlib
import dataclasses
import io
import struct
import sys

from typing import Any, Dict, Iterator, Tuple, Union


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


class ELFException(Exception):
    pass


class NotAnELF(ELFException):
    """File is not an ELF file."""

    def __init__(self, file: io.RawIOBase) -> None:
        super().__init__()
        self._file = file

    def __repr__(self) -> str:
        return f'File is not an ELF file: {self._file}'


class EI(_Enum):
    ## e_ident
    NIDENT = 0x0f  # size
    # indexes
    CLASS = 0x04
    DATA = 0x05
    VERSION = 0x06
    OSABI = 0x07
    ABIVERSION = 0x08
    PAD = 0x09


class ELFCLASS(_Enum):
    NONE = 0
    _32 = 1
    _64 = 2


class ELFDATA(_Enum):
    NONE = 0
    LSB = 1
    MSB = 2


class OSABI(_Enum):
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


class ET(_Enum):
    # e_type
    NONE = 0x00
    REL = 0x01
    EXEC = 0x02
    DYN = 0x03
    CORE = 0x04
    LOOS = 0xfe00
    HIOS = 0xfeff
    LOPROC = 0xff00
    HIPROC = 0xffff


class EM(_Enum):
    # e_machine
    NONE = 0
    M32 = 1
    SPARC = 2
    _386 = 3
    _68K = 4
    _88K = 5
    _860 = 7
    MIPS = 8
    MIPS_RS4_BE = 10
    PARISC = 15
    VPP550 = 17
    SPARC32PLUS = 18
    _960 = 19
    PPC = 20
    PPC64 = 21
    S390 = 22
    V800 = 36
    FR20 = 37
    RH32 = 38
    RCE = 39
    ARM = 40
    ALPHA = 41
    SH = 42
    SPARCV9 = 43
    TRICORE = 44
    ARC = 45
    H8_300 = 46
    H8_300H = 47
    H8S = 48
    H8_500 = 49
    IA_64 = 50
    MIPS_X = 51
    COLDFIRE = 52
    _68HC12 = 53
    MMA = 54
    PCP = 55
    NCPU = 56
    NDR1 = 57
    STARCORE = 58
    ME16 = 59
    ST100 = 60
    TINYJ = 61
    X86_64 = 62
    PDSP = 63
    PDP10 = 64
    PDP11 = 65
    FX66 = 66
    ST9PLUS = 67
    ST7 = 68
    _68HC16 = 69
    _68HC11 = 70
    _68HC08 = 71
    _68HC05 = 72
    SVX = 73
    ST19 = 74
    VAX = 75
    CRIS = 76
    JAVELIN = 77
    FIREPATH = 78
    ZSP = 79
    MMIX = 80
    HUANY = 81
    PRISM = 82
    AVR = 83
    FR30 = 84
    D10V = 85
    D30V = 86
    V850 = 87
    M32R = 88
    MN10300 = 89
    MN10200 = 90
    PJ = 91
    OPENRISC = 92
    ARC_A5 = 93
    XTENSA = 94
    VIDEOCORE = 95
    TMM_GPP = 96
    NS32K = 97
    TPC = 98
    SNP1K = 99
    ST200 = 100


class EV(_Enum):
    NONE = 0x00
    CURRENT = 0x01


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
