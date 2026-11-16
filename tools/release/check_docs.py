"""检查公开HTML导航及本地附件，拒绝私钥进入文档，不访问外部网页。"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]


class Page(HTMLParser):
    def __init__(self):
        super().__init__();self.links=[];self.ids=set();self.has_title=False;self.has_viewport=False

    def handle_starttag(self, tag, attrs):
        values=dict(attrs)
        if tag=='title':self.has_title=True
        if tag=='meta' and values.get('name')=='viewport':self.has_viewport=True
        if 'id' in values:self.ids.add(values['id'])
        for key in ('href','src'):
            if key in values:self.links.append(values[key])


def main():
    pages={}
    for path in (ROOT/'docs').rglob('*.html'):
        body=path.read_text(encoding='utf-8')
        if 'PRIVATE KEY-----' in body:raise ValueError('private key in documentation')
        parser=Page();parser.feed(body);pages[path.resolve()]=parser
        if not parser.has_title or not parser.has_viewport:raise ValueError('missing title or mobile viewport: '+str(path))
    for path,page in pages.items():
        for link in page.links:
            parsed=urlsplit(link)
            if parsed.scheme or parsed.netloc:continue
            target=(path.parent/unquote(parsed.path)).resolve() if parsed.path else path
            if not target.is_relative_to(ROOT):raise ValueError('local link outside repository: '+str(path)+' '+link)
            if not target.exists():raise ValueError('missing local link: '+str(path)+' '+link)
            if parsed.fragment and target in pages and unquote(parsed.fragment) not in pages[target].ids:
                raise ValueError('missing local anchor: '+str(path)+' '+link)
    print('Verified',len(pages),'HTML pages, mobile metadata, local links and anchors')


if __name__=='__main__':main()
