from pathlib import Path
import importlib.util
import os

BASE = Path(__file__).resolve().parent
RUNTIME = Path(r'C:\Users\10300\.cache\codex-runtimes\codex-primary-runtime')
SCRIPT = Path(r'C:\Users\10300\.codex\plugins\cache\openai-primary-runtime\documents\26.1011.11113\skills\documents\render_docx.py')
poppler = next((RUNTIME / 'dependencies' / 'native' / 'poppler').rglob('pdftoppm.exe')).parent
os.environ['PATH'] = str(poppler) + os.pathsep + os.environ.get('PATH', '')
spec = importlib.util.spec_from_file_location('packaged_render_docx', SCRIPT)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
preview = BASE / 'render' / 'native-preview.pdf'
assert preview.is_file() and preview.stat().st_size > 0

# The Windows runtime has no LibreOffice. WPS exports the real DOCX through
# its native layout engine; retain the packaged renderer for DPI and raster QA.
def native_conversion(*args, **kwargs):
    return str(preview), 'Native WPS ExportAsFixedFormat PDF'

renderer.convert_to_pdf = native_conversion
docx = BASE.parents[1] / '宣发资料' / 'NovaProtect产品宣发文案.docx'
dpi = renderer.calc_dpi_via_ooxml_docx(str(docx), 1600, 2100)
for path in renderer.rasterize(str(docx), str(BASE / 'render'), dpi, False, False):
    print(path)
