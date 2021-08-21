# elfo

[![checks](https://github.com/FFY00/python-elfo/actions/workflows/checks.yml/badge.svg)](https://github.com/FFY00/python-elfo/actions/workflows/checks.yml)

ELF file deserializer and serializer library.


```python
>>> with elfo.ELF.from_path('main') as elf:
...     print(elf)
...     print(bytes(elf))
...     elf.header.e_ident.os_abi = elfo.OSABI.FREEBSD
...     elf.header.e_machine = elfo.EM.PPC64
...     print(elf)
...     print(bytes(elf))
...
ELF(
  header=ELFHeader(
    e_ident=e_ident(
      file_identification=b'\x7fELF',
      file_class=<ELFCLASS._64: 2>,
      data_encoding=<ELFDATA.LSB: 1>,
      file_version=0x01,
      os_abi=<OSABI.SYSTEM_V: 0>,
      abi_version=0x00,
    ),
    e_type=<ET.DYN: 3>,
    e_machine=<EM.X86_64: 62>,
    e_version=<EV.CURRENT: 1>,
    e_entry=0x1050,
    e_phoff=0x40,
    e_shoff=0x3780,
    e_flags=0x00,
    e_ehsize=0x40,
    e_phensize=0x38,
    e_phnum=0x0d,
    e_shentsize=0x40,
    e_shnum=0x1e,
    e_shstrndx=0x1d,
  ),
)
b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00P\x10\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x807\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\r\x00@\x00\x1e\x00\x1d\x00'
ELF(
  header=ELFHeader(
    e_ident=e_ident(
      file_identification=b'\x7fELF',
      file_class=<ELFCLASS._64: 2>,
      data_encoding=<ELFDATA.LSB: 1>,
      file_version=0x01,
      os_abi=<OSABI.FREEBSD: 9>,
      abi_version=0x00,
    ),
    e_type=<ET.DYN: 3>,
    e_machine=<EM.PPC64: 21>,
    e_version=<EV.CURRENT: 1>,
    e_entry=0x1050,
    e_phoff=0x40,
    e_shoff=0x3780,
    e_flags=0x00,
    e_ehsize=0x40,
    e_phensize=0x38,
    e_phnum=0x0d,
    e_shentsize=0x40,
    e_shnum=0x1e,
    e_shstrndx=0x1d,
  ),
)
b'\x7fELF\x02\x01\x01\t\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x15\x00\x01\x00\x00\x00P\x10\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x807\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\r\x00@\x00\x1e\x00\x1d\x00'
```
