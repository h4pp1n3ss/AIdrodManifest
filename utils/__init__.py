import zipfile
import xml.etree.ElementTree as ET
from xml.dom import minidom



BINARY_XML_MAGIC = b'\x03\x00\x08\x00'


def is_apk(path: str) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except Exception:
        return False

def is_binary_xml(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == BINARY_XML_MAGIC


def extract_manifest_from_apk(apk_path: str) -> bytes:
    with zipfile.ZipFile(apk_path, 'r') as apk:
        if 'AndroidManifest.xml' not in apk.namelist():
            raise FileNotFoundError("AndroidManifest.xml not found inside APK.")
        return apk.read('AndroidManifest.xml')


def pretty_print_xml(data: bytes) -> str:
    ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
    ET.register_namespace('tools', 'http://schemas.android.com/tools')
    ET.register_namespace('app', 'http://schemas.android.com/apk/res-auto')

    root = ET.fromstring(data)
    rough = ET.tostring(root, encoding='unicode', xml_declaration=False)
    lines = minidom.parseString(rough).toprettyxml(indent="    ").splitlines()
    return "\n".join(line for line in lines if line.strip())


def decode_binary_xml(data: bytes) -> str:
    """Try available libraries to decode Android binary XML."""

    # Option 1: androguard (pip install androguard)
    try:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        xml_obj = printer.get_xml_obj()
        return xml_obj.toprettyxml(indent=" ")
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] androguard failed: {e}", file=sys.stderr)

    # Option 2: axml (pip install axml)
    try:
        import axml
        result = axml.parse(data)
        if isinstance(result, bytes):
            result = result.decode('utf-8', errors='replace')
        return result
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] axml failed: {e}", file=sys.stderr)

    # Option 3: pyaxmlparser (pip install pyaxmlparser)
    try:
        from pyaxmlparser import APK
        raise ImportError  # pyaxmlparser needs full APK context, skip here
    except ImportError:
        pass

    raise RuntimeError(
        "No binary XML decoder found.\n"
        "Install one of the following:\n"
        "  pip install androguard\n"
        "  pip install axml"
    )