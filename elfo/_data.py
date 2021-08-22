# SPDX-License-Identifier: EUPL-1.2

from elfo._util import _Enum, _EnumFlagItem


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


class SHT(_Enum):
    NULL = 0
    PROGBITS = 1
    SYMTAB = 2
    STRTAB = 3
    RELA = 4
    HASH = 5
    DYNAMIC = 6
    NOTE = 7
    NOBITS = 8
    REL = 9
    SHLIB = 10
    DYNSYM = 11
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff
    LOUSER = 0x80000000
    HIUSER = 0xffffffff


class SHF(_Enum, item_cls=_EnumFlagItem):
    WRITE = 0x1
    ALLOC = 0x2
    EXECINSTR = 0x4
    MASKPROC = 0xf0000000
