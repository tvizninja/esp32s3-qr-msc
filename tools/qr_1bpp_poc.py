#!/usr/bin/env python3
import argparse, json, struct, time, resource
from pathlib import Path


def _token(f):
    while True:
        c = f.read(1)
        if not c:
            raise EOFError
        if c == b'#':
            f.readline()
            continue
        if c.isspace():
            continue
        out = bytearray(c)
        while True:
            c = f.read(1)
            if not c or c.isspace():
                return bytes(out)
            out += c


def image_info(path):
    path = Path(path)
    with open(path, 'rb') as f:
        sig = f.read(2)

    if sig == b'P5':
        with open(path, 'rb') as f:
            if _token(f) != b'P5':
                raise ValueError('P5 PGM required')
            w = int(_token(f)); h = int(_token(f)); maxv = int(_token(f))
            if maxv != 255:
                raise ValueError('8-bit PGM required')
            off = f.tell()
        return {
            'format': 'PGM_P5', 'width': w, 'height': h,
            'pixel_offset': off, 'row_stride': w, 'top_down': True,
        }

    if sig == b'BM':
        with open(path, 'rb') as f:
            hdr = f.read(54)
        if len(hdr) < 54:
            raise ValueError('short BMP header')
        off = struct.unpack_from('<I', hdr, 10)[0]
        dib = struct.unpack_from('<I', hdr, 14)[0]
        if dib < 40:
            raise ValueError('BITMAPINFOHEADER or later required')
        w = struct.unpack_from('<i', hdr, 18)[0]
        hs = struct.unpack_from('<i', hdr, 22)[0]
        planes, bpp = struct.unpack_from('<HH', hdr, 26)
        compression = struct.unpack_from('<I', hdr, 30)[0]
        if w <= 0 or hs == 0:
            raise ValueError('invalid BMP dimensions')
        if planes != 1 or bpp != 8 or compression != 0:
            raise ValueError('8-bit uncompressed BMP required')
        h = abs(hs)
        stride = ((w * bpp + 31) // 32) * 4

        # Firmware LATEST.BMP uses a linear grayscale palette. Validate it so
        # the palette index can safely be treated as GRAY8 without expansion.
        palette_entries = (off - (14 + dib)) // 4
        if palette_entries < 256:
            raise ValueError('BMP must contain a 256-entry grayscale palette')
        with open(path, 'rb') as f:
            f.seek(14 + dib)
            palette = f.read(256 * 4)
        if len(palette) != 1024:
            raise ValueError('short BMP palette')
        for i in range(256):
            b, g, r, _ = palette[i*4:(i+1)*4]
            if r != i or g != i or b != i:
                raise ValueError('BMP palette is not linear grayscale')

        return {
            'format': 'BMP_GRAY8', 'width': w, 'height': h,
            'pixel_offset': off, 'row_stride': stride, 'top_down': hs < 0,
        }

    raise ValueError('P5 PGM or firmware 8-bit grayscale BMP required')


def iter_rows(path, info):
    w = info['width']; h = info['height']
    off = info['pixel_offset']; stride = info['row_stride']
    top_down = info['top_down']
    with open(path, 'rb', buffering=0) as f:
        if top_down:
            f.seek(off)
            for _ in range(h):
                row = f.read(stride)
                if len(row) != stride:
                    raise EOFError('short pixel data')
                yield row[:w]
        else:
            for y in range(h):
                f.seek(off + (h - 1 - y) * stride)
                row = f.read(stride)
                if len(row) != stride:
                    raise EOFError('short pixel data')
                yield row[:w]


def histogram_stream(path, info):
    hist = [0] * 256
    for row in iter_rows(path, info):
        for v in row:
            hist[v] += 1
    return hist


def otsu(hist, total):
    sum_total = sum(i*n for i, n in enumerate(hist))
    sum_b = 0; w_b = 0; best = -1.0; threshold = 0
    for t, n in enumerate(hist):
        w_b += n
        if not w_b:
            continue
        w_f = total - w_b
        if not w_f:
            break
        sum_b += t*n
        m_b = sum_b / w_b
        m_f = (sum_total - sum_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best:
            best = var
            threshold = t
    return threshold


def pack_1bpp_stream(path, info, threshold, out_path=None):
    w = info['width']; h = info['height']
    stride = (w + 7) // 8
    buf = bytearray(stride * h)
    for y, row in enumerate(iter_rows(path, info)):
        base = y * stride
        for x, v in enumerate(row):
            # 1 = black, matching common QR BitMatrix semantics.
            if v <= threshold:
                buf[base + (x >> 3)] |= 0x80 >> (x & 7)
    if out_path:
        Path(out_path).write_bytes(buf)
    return buf, stride


def unpack_for_validation(bits, w, h, stride):
    # PC validation only. Embedded design does not need this allocation.
    import numpy as np
    a = np.empty((h, w), dtype=np.uint8)
    for y in range(h):
        row = bits[y*stride:(y+1)*stride]
        for x in range(w):
            a[y, x] = 0 if (row[x >> 3] & (0x80 >> (x & 7))) else 255
    return a


def main():
    ap = argparse.ArgumentParser(description='Streaming GRAY8 -> Otsu -> packed 1bpp QR PoC')
    ap.add_argument('image', help='P5 PGM or firmware LATEST.BMP')
    ap.add_argument('--bin', default='LATEST.1BPP')
    args = ap.parse_args()

    t0 = time.perf_counter()
    info = image_info(args.image)
    w = info['width']; h = info['height']
    hist = histogram_stream(args.image, info)
    t1 = time.perf_counter()
    th = otsu(hist, w*h)
    bits, stride = pack_1bpp_stream(args.image, info, th, args.bin)
    t2 = time.perf_counter()

    result = {
        'input_format': info['format'],
        'width': w, 'height': h,
        'pixel_offset': info['pixel_offset'],
        'input_row_stride': info['row_stride'],
        'top_down': info['top_down'],
        'threshold': th,
        'gray8_bytes': w*h,
        'packed_1bpp_bytes': len(bits),
        'ratio': len(bits)/(w*h),
        'histogram_ms': (t1-t0)*1000,
        'pack_ms': (t2-t1)*1000,
        'peak_rss_kb': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }

    try:
        import cv2
        img = unpack_for_validation(bits, w, h, stride)
        det = cv2.QRCodeDetector()
        s, pts, _ = det.detectAndDecode(img)
        result['opencv_decode_ok'] = bool(s)
        result['opencv_payload_bytes'] = len(s.encode()) if s else 0
        result['opencv_points'] = pts.tolist() if pts is not None else None
    except Exception as e:
        result['opencv_error'] = repr(e)

    try:
        from pyzbar.pyzbar import decode
        dec = decode(unpack_for_validation(bits, w, h, stride))
        result['zbar_decode_ok'] = bool(dec)
        result['zbar_payload_bytes'] = len(dec[0].data) if dec else 0
    except Exception as e:
        result['zbar_error'] = repr(e)

    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
