# elfo

[![checks](https://github.com/FFY00/python-elfo/actions/workflows/checks.yml/badge.svg)](https://github.com/FFY00/python-elfo/actions/workflows/checks.yml)

ELF file deserializer and serializer library.


```python
>>> import elfo
>>> with elfo.ELF.from_path('main') as elf:
...     print(elf)
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
```
