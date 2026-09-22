"""Scrape an index page for *.pcap.xz links and download them.

Configure ``download.source_url`` and ``download.link_regex`` in config.yaml.
Downloads stream to disk and skip files that already exist (idempotent).
"""
from __future__ import annotations

import re
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

import requests
from tqdm import tqdm

# (connect, read) timeouts. The ISI share occasionally stalls mid-stream; a read
# timeout fires if no data arrives within this many seconds.
_TIMEOUT = (30, 180)
_MAX_RETRIES = 6


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)


def discover_links(source_url: str, link_regex: str, verify_tls: bool = True,
                   auth: tuple[str, str] | None = None) -> list[str]:
    resp = requests.get(source_url, verify=verify_tls, timeout=60, auth=auth)
    resp.raise_for_status()
    parser = _LinkParser()
    parser.feed(resp.text)
    pat = re.compile(link_regex)
    # Resolve relative hrefs against the *final* URL (after any redirect) and
    # ensure it names a directory (trailing slash), so a source_url like
    # ".../set1" doesn't drop the "set1/" segment when joined with "mypcap_...".
    base = resp.url
    if not base.endswith("/"):
        base += "/"
    out, seen = [], set()
    for href in parser.hrefs:
        if pat.search(href):
            full = urljoin(base, href)
            if full not in seen:
                seen.add(full)
                out.append(full)
    return out


def download_file(url: str, dest_dir: Path, verify_tls: bool = True,
                  auth: tuple[str, str] | None = None) -> Path:
    """Stream a file to disk, surviving transient stalls.

    On a read timeout / dropped connection the download is retried (up to
    ``_MAX_RETRIES``) and *resumed* from the bytes already on disk via an HTTP
    Range request, so a hiccup near the end of a 200 MB capture doesn't restart
    it. Falls back to a clean re-fetch if the server ignores Range (200) or the
    resume offset is unsatisfiable (416)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = url.rstrip("/").split("/")[-1]
    dest = dest_dir / name
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  skip (exists): {name}")
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")

    for attempt in range(1, _MAX_RETRIES + 1):
        resume = tmp.stat().st_size if tmp.exists() else 0
        headers = {"Range": f"bytes={resume}-"} if resume else {}
        try:
            with requests.get(url, stream=True, verify=verify_tls,
                              timeout=_TIMEOUT, auth=auth, headers=headers) as r:
                if r.status_code == 416:  # offset past EOF: restart clean
                    tmp.unlink(missing_ok=True)
                    raise requests.exceptions.RequestException("range unsatisfiable")
                if resume and r.status_code == 206:        # resume accepted
                    mode = "ab"
                    cr = r.headers.get("Content-Range", "")
                    total = int(cr.split("/")[-1]) if "/" in cr else 0
                else:                                       # full transfer (200)
                    r.raise_for_status()
                    resume, mode = 0, "wb"
                    total = int(r.headers.get("Content-Length", 0))
                with open(tmp, mode) as fh, tqdm(
                    total=total or None, initial=resume, unit="B",
                    unit_scale=True, desc=name, leave=False
                ) as bar:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        fh.write(chunk)
                        bar.update(len(chunk))
            if total and tmp.stat().st_size < total:
                raise IOError(f"incomplete {tmp.stat().st_size:,}/{total:,}")
            tmp.rename(dest)
            return dest
        except (requests.exceptions.RequestException, IOError) as e:
            if attempt >= _MAX_RETRIES:
                raise
            got = tmp.stat().st_size if tmp.exists() else 0
            wait = min(30, 2 ** attempt)
            print(f"  download error on {name} (attempt {attempt}/{_MAX_RETRIES}): "
                  f"{type(e).__name__}; have {got:,} bytes, retrying in {wait}s",
                  flush=True)
            time.sleep(wait)


def download_all(source_url: str, link_regex: str, dest_dir: Path,
                 verify_tls: bool = True, auth: tuple[str, str] | None = None,
                 max_files: int = 0, skip: int = 0) -> list[Path]:
    if not source_url:
        raise ValueError("download.source_url is empty; set it in config.yaml "
                         "or run the orchestrator with --skip-download.")
    links = discover_links(source_url, link_regex, verify_tls, auth)
    total = len(links)
    if skip > 0:
        links = links[skip:]
    if max_files and max_files > 0:
        links = links[:max_files]
    extra = ""
    if skip > 0 or (max_files and max_files > 0):
        extra = f" (selecting {len(links)} after skip={skip}, max_files={max_files or 'all'})"
    print(f"discovered {total} file(s) at {source_url}{extra}")
    return [download_file(u, dest_dir, verify_tls, auth) for u in links]
