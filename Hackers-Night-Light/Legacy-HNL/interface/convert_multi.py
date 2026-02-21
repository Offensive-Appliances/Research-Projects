import gzip
from pathlib import Path

STYLE_TAG = '<link rel="stylesheet" href="styles.css">'
SCRIPT_TAG = '<script src="app.js"></script>'


def inline_assets(html: str, css: str, js: str) -> str:
    if STYLE_TAG in html:
        html = html.replace(STYLE_TAG, f'<style>\n{css}\n</style>')
    else:
        html += f'\n<style>\n{css}\n</style>'

    if SCRIPT_TAG in html:
        html = html.replace(SCRIPT_TAG, f'<script>\n{js}\n</script>')
    else:
        html += f'\n<script>\n{js}\n</script>'

    return html


def remove_legacy_files(output_dir: Path):
    for legacy in ("web_content.c", "web_content.h"):
        legacy_path = output_dir / legacy
        if legacy_path.exists():
            legacy_path.unlink()
            print(f"Removed legacy artifact: {legacy_path.name}")


def generate_web_bundle():
    script_dir = Path(__file__).resolve().parent
    output_dir = (script_dir / '..' / 'main').resolve()

    html = (script_dir / 'index_new.html').read_text(encoding='utf-8')
    css = (script_dir / 'styles.css').read_text(encoding='utf-8')
    charts_js = (script_dir / 'charts.js').read_text(encoding='utf-8')
    export_js = (script_dir / 'export_manager.js').read_text(encoding='utf-8')
    js = (script_dir / 'app.js').read_text(encoding='utf-8')

    combined_js = charts_js + '\n\n' + export_js + '\n\n' + js
    combined_html = inline_assets(html, css, combined_js)
    print(f"Combined size before gzip: {len(combined_html)} bytes")
    compressed = gzip.compress(combined_html.encode('utf-8'), compresslevel=9)

    blob_path = output_dir / 'web_content.gz.h'
    blob_path.write_bytes(compressed)
    print(f"Created gzip blob: {blob_path} ({len(compressed)} bytes)")

    login_html_path = script_dir / 'login.html'
    if login_html_path.exists():
        login_html = login_html_path.read_text(encoding='utf-8')
        login_compressed = gzip.compress(login_html.encode('utf-8'), compresslevel=9)
        login_blob_path = output_dir / 'login_content.gz.h'
        login_blob_path.write_bytes(login_compressed)
        print(f"Created login blob: {login_blob_path} ({len(login_compressed)} bytes)")

    remove_legacy_files(output_dir)


if __name__ == "__main__":
    generate_web_bundle()
