class PE:
    sections: list[SectionStructure]
    def __init__(
        self,
        name: str | None = None,
        data: bytes | None = None,
        fast_load: bool | None = None,
        max_symbol_exports: int = ...,
        max_repeated_symbol: int = ...,
    ) -> None: ...

class Structure: ...

class SectionStructure(Structure):
    PointerToRawData: int
    SizeOfRawData: int

class PEFormatError(Exception): ...
