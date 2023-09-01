import errno

import comtypes
import comtypes.client
import sys
import pefile
import os
import requests
import shutil
import subprocess

dll_path = r'C:\Program Files (x86)\Common Files\Microsoft Shared\VC\amd64\msdia80.dll'
twinuipcshell_path = r'C:\Windows\System32\twinui.pcshell.dll'
actxprxy_path = r'C:\Windows\System32\actxprxy.dll'
SYMBOLS_SERVER = 'https://msdl.microsoft.com/download/symbols'
symbols_path = r'C:\Symbols'


class PEFile(pefile.PE):
    def __init__(self, path):
        pefile.PE.__init__(self, path)

        self.path = path
        self.pdbFileName = None
        self.pdbObj = None
        self.symbols = None

    def download_pdb(self, local_cache=symbols_path):
        def get_pdb_url(pe):
            # pe.parse_data_directories()
            string_version_info = {}
            for fileinfo in pe.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                    for st in fileinfo.StringTable:
                        for entry in st.entries.items():
                            string_version_info[entry[0].decode()] = entry[1].decode()
            ver_str = string_version_info['ProductVersion']
            for directory in pe.DIRECTORY_ENTRY_DEBUG:
                debug_entry = directory.entry
                if hasattr(debug_entry, 'PdbFileName'):
                    pdb_file = debug_entry.PdbFileName[:-1].decode('ascii')
                    guid = f'{debug_entry.Signature_Data1:08x}'
                    guid += f'{debug_entry.Signature_Data2:04x}'
                    guid += f'{debug_entry.Signature_Data3:04x}'
                    guid += f'{int.from_bytes(debug_entry.Signature_Data4, byteorder="big"):016x}'
                    guid = guid.upper()
                    url = f'/{pdb_file}/{guid}{debug_entry.Age:x}/{pdb_file}'
                    pdb_file_name = f'{pdb_file[:-4]}-{ver_str}.pdb'
                    return url, pdb_file_name
            return None

        path = self.path
        pdb_url, pdb_file_name = get_pdb_url(self)
        if not os.path.exists(pdb_file_name):
            pdb_path = pdb_file_name
            if os.path.exists(local_cache):
                pdb_path = local_cache + pdb_url
                pdb_path = os.path.realpath(pdb_path)
            if not os.path.exists(os.path.dirname(pdb_path)):
                try:
                    os.makedirs(os.path.dirname(pdb_path))
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        print(f"Failed to create directory {pdb_path} due to: {e}")
                        return
                r = requests.get(SYMBOLS_SERVER + pdb_url)
                r.raise_for_status()
                try:
                    with open(pdb_path, 'wb') as f:
                        f.write(r.content)
                except PermissionError as e:
                    print(f"Permission error: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
            if pdb_path != pdb_file_name:
                shutil.copyfile(pdb_path, pdb_file_name)

        self.pdbFileName = pdb_file_name

    def load_pdb(self):
        self.download_pdb()
        try:
            dia1 = comtypes.client.CreateObject(msdia.DiaSource)
            dia1.loadDataFromPdb(self.pdbFileName)
            dia_session = dia1.openSession()
        except Exception as exc1:
            print(('[!] loadDataFromPdb() error %s' % (str(exc1))))
            raise
        self.pdbObj = dia_session


# Utility class for capturing some of the data from UDT symbol list in PDB file
class PDBSymbol:

    @classmethod
    def from_dia(cls, symbol_data):
        return PDBSymbol(udt_enum_to_str[symbol_data.udtKind], symbol_data.name, symbol_data.undecoratedName,
                         symbol_data.virtualAddress, symbol_data.length)

    def __init__(self, kind='', name='', und_name='', rva=0, size=0):
        self.kind = kind
        self.name = name
        self.undName = und_name
        self.rva = rva
        self.size = size
        self.pe = None

    def __str__(self):
        sstr = '0x%08x (%4dB) %s\t%s' % (self.rva, self.size, self.kind, self.name)

        return sstr

    def __repr__(self):
        return f'<PDBSymbol {str(self)}>'

    # required for hash
    def __hash__(self):
        return hash((self.name, self.rva, self.kind))

    # required for hash, when buckets contain multiple items
    def __eq__(self, other):
        return self.name == other.name and self.rva == other.rva and self.kind == other.kind

    def __contains__(self, key):
        return self.__eq__(key)

    def read_data(self, length=None):
        if length is None:
            length = self.size

        return self.pe.get_data(self.rva, length)


def parse_pdb(pe):
    pdb_obj = pe.pdbObj
    syms = set()

    # iterate the public syms to find all vtables
    for symb in pdb_obj.globalScope.findChildren(SymTagPublicSymbol, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        symbol_obj = PDBSymbol.from_dia(symbol_data)

        syms.add(symbol_obj)

        # print(symbol_data.undecoratedName, symbol_data.name)

    # iterate all UDT/private? symbols
    for symb in pdb_obj.globalScope.findChildren(SymTagUDT, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        # print(symbol_data.undecoratedName, symbol_data.name)
        symbol_obj = PDBSymbol.from_dia(symbol_data)

        syms.add(symbol_obj)

    syms = list(syms)
    for sym in syms:
        sym.pe = pe
    return syms


def guid_to_str(guid_bytes):
    return '%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X' % (
        int.from_bytes(guid_bytes[:4], 'little'),
        int.from_bytes(guid_bytes[4:6], 'little'),
        int.from_bytes(guid_bytes[6:8], 'little'),
        *[int.from_bytes(guid_bytes[i:i + 1], 'little') for i in range(8, 16)]
    )


def print_guid_sym(symName):
    print("%s: %s" % (symName, guid_to_str(symMap[symName].read_data())))


def save_to_file(symMap):
    with open("output.txt", "w") as f:
        for (k1, _) in symMap.items():
            f.write(k1)
            f.write("\n")


def dump_vft(vft_name):
    vft_sym = symMap[vft_name]
    print("\n\nDumping vftable: %s" % vft_sym.undName)
    vft_data = vft_sym.read_data()
    vft_ptrs = [int.from_bytes(vft_data[c:c + 8], 'little') - vft_sym.pe.OPTIONAL_HEADER.ImageBase for c in
                range(0, len(vft_data), 8)]
    sym_map2 = {c.rva: c for c in vft_sym.pe.symbols}
    for i, ptr in enumerate(vft_ptrs):
        if ptr in sym_map2:
            print("    Method %2d: %s (%s)" % (i, sym_map2[ptr].undName, sym_map2[ptr].name))
        else:
            print("    Method %2d: Unknown (0x%X)" % (i, ptr))


if __name__ == "__main__":
    if not os.path.exists(dll_path):
        print(f"The DLL file at {dll_path} does not exist.\r\nYou need to install C++ Redistributable for Visual Studio 2005 SP1 (x64) from https://www.microsoft.com/en-us/download/details.aspx?id=18471")
        sys.exit(1)

    if not os.path.exists(twinuipcshell_path):
        print(f"The specified file at {twinuipcshell_path} does not exist.")
        sys.exit(1)

    if not os.path.exists(actxprxy_path):
        print(f"The specified file at {actxprxy_path} does not exist.")
        sys.exit(1)

    # this has to be before the import that follows
    try:
        msdia = comtypes.client.GetModule(dll_path)
    except Exception as e:
        print(f"Exception while loading DIA module: {e}")
        sys.exit(1)

    from comtypes.gen._106173A0_0173_4E5C_84E7_E915422BE997_0_2_0 import IDiaSymbol, SymTagPublicSymbol, SymTagUDT
    from comtypes.gen.Dia2Lib import *

    # Try to create the object
    try:
        dia = comtypes.client.CreateObject(msdia.DiaSource)
    except Exception as exc:
        print(f"Exception creating DIA object: {exc}\nTrying to register the DLL...")
        try:
            # Run regsvr32 to register the DLL
            subprocess.run(["regsvr32", "/s", dll_path], check=True)
            print("DLL registered successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to register the DLL: {e}")
            sys.exit(1)

    twinuipcshell = PEFile(twinuipcshell_path)
    twinuipcshell.load_pdb()
    actxprxy = PEFile(actxprxy_path)
    actxprxy.load_pdb()
    udt_enum_to_str = ('struct', 'class', 'union', 'interface')
    twinuipcshell.symbols = parse_pdb(twinuipcshell)
    actxprxy.symbols = parse_pdb(actxprxy)
    symMap = {c.name: c for c in twinuipcshell.symbols + actxprxy.symbols}

    # dump it all to txt file for testing
    # save_to_file(symMap)

    # print the GUIDs
    for (k, _) in symMap.items():
        if "IID_IVirtualDesktop" in k:
            print_guid_sym(k)

    # print the vftables
    for (k, _) in symMap.items():
        if "??_7CWin32ApplicationView" in k and "IApplicationView" in k:
            if "Microsoft" not in k and "IApplicationViewBase" not in k:
                print("---------------------------------------------------------")
                print("")
                print(k)
                dump_vft(k)
                pass
        elif "??_7CVirtualDesktop@@6BIVirtualDesktop@@@" in k \
                or "??_7CVirtualDesktopManager@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00UIVirtualDesktopManagerInternal@@UISuspendableVirtualDesktopManager@@VFtmBase@23@@Details@WRL@Microsoft@@@" in k \
                or "??_7CVirtualDesktopNotificationsDerived@@6BIVirtualDesktopNotification@@@" in k \
                or "??_7CVirtualDesktopNotificationsDerived@@6B@" in k \
                or "??_7CVirtualDesktopHotkeyHandler@@6B@" in k \
                or "??_7CVirtualDesktopHotkeyHandler@@6B@" in k \
                or "??_7VirtualDesktopsApi@@6B@" in k:
            print("---------------------------------------------------------")
            print("")
            print(k)
            dump_vft(k)

