#!/usr/bin/env python3
"""
Advanced PDF Analysis and Disarm Tool
Author: Exfil0
Version: 0.2.0
Date: 2025/02/12

This script provides a powerful PDF scanning and analysis utility with the following features:
 - Concurrent scanning with ThreadPoolExecutor
 - Ability to parse PDF structures, detect keywords, compute entropy
 - Optional "disarm" mode to neutralize malicious elements (e.g. JS, Launch actions)
 - Directory recursion, wildcard expansion
 - Plugin architecture for custom scoring
 - CSV or console output

Use at your own risk. Distributed without warranty of any kind.
"""

import os
import re
import sys
import csv
import glob
import fnmatch
import math
import operator
import traceback
import collections
import argparse
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed

# Attempt to import pyzipper for AES; fallback to zipfile otherwise
try:
    import pyzipper as zipfile
except ImportError:
    import zipfile

import urllib.request as urllib3
import json

# =============================================================================
# HELPER CLASSES & FUNCTIONS
# =============================================================================

def CreateZipFileObject(arg1, arg2):
    """
    Returns a ZIP file object supporting AES if available (pyzipper).
    Otherwise, fallback to standard ZipFile.
    """
    if 'AESZipFile' in dir(zipfile):
        return zipfile.AESZipFile(arg1, arg2)
    else:
        return zipfile.ZipFile(arg1, arg2)

class cBinaryFile:
    """
    Handles file/stream reading for PDFs:
     - local files,
     - URLs (HTTP/HTTPS),
     - ZIP with password='infected',
     - stdin.
    Allows unget operations for parsing convenience.
    """
    def __init__(self, file, data=None):
        self.file = file
        if data is not None:
            self.infile = BytesIO(data)
        elif file == '':
            self.infile = sys.stdin.buffer
        elif file.lower().startswith('http://') or file.lower().startswith('https://'):
            try:
                self.infile = urllib3.urlopen(file, timeout=5)
            except urllib3.HTTPError:
                print(f'[ERROR] Cannot access URL: {file}')
                print(sys.exc_info()[1])
                sys.exit()
        elif file.lower().endswith('.zip'):
            try:
                self.zipfile = CreateZipFileObject(file, 'r')
                self.infile = self.zipfile.open(self.zipfile.infolist()[0], 'r', b'infected')
            except:
                print(f'[ERROR] Cannot open ZIP file: {file}')
                print(sys.exc_info()[1])
                sys.exit()
        else:
            try:
                self.infile = open(file, 'rb')
            except:
                print(f'[ERROR] Cannot open file: {file}')
                print(sys.exc_info()[1])
                sys.exit()
        self.ungetted = []

    def byte(self):
        """
        Read 1 byte; return None at EOF.
        """
        if self.ungetted:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte:
            self.infile.close()
            return None
        return inbyte[0]

    def bytes(self, size):
        """
        Read 'size' bytes; return as a list of int.
        """
        if size <= len(self.ungetted):
            result = self.ungetted[:size]
            del self.ungetted[:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if not inbytes:
            self.infile.close()
            inbytes = b''
        result = self.ungetted + list(inbytes)
        self.ungetted = []
        return result

    def unget(self, byte):
        """
        Push back 1 byte.
        """
        self.ungetted.append(byte)

    def ungets(self, bytes_lst):
        """
        Push back multiple bytes.
        """
        bytes_lst.reverse()
        self.ungetted.extend(bytes_lst)

class cPDFDate:
    """
    Minimal parser for PDF date objects (D:YYYYMMDDHHmmSS+XX'YY).
    """
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == 'D':
            self.state = 1
            return None
        elif self.state == 1:
            if char == ':':
                self.state = 2
                self.digits1 = ''
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char.isdigit():
                    self.digits1 += char
                else:
                    self.state = 0
                    return None
            elif char in '+-Z':
                self.state = 3
                self.digits2 = ''
                self.TZ = char
            elif char == '"':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            elif not char.isdigit():
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            else:
                self.state = 0
            return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char.isdigit():
                    self.digits2 += char
                else:
                    self.state = 0
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                else:
                    self.state = 0
            elif len(self.digits2) < 5:
                if char.isdigit():
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = 'D:' + self.digits1 + self.TZ + self.digits2
                        return self.date
                else:
                    self.state = 0
            return None

def fEntropy(countByte, countTotal):
    """
    Partial entropy computation for a single bucket.
    """
    x = float(countByte) / countTotal
    if x > 0:
        return - x * math.log(x, 2)
    else:
        return 0.0

class cEntropy:
    """
    Track byte frequency globally and inside streams, compute entropies.
    """
    def __init__(self):
        self.allBucket = [0]*256
        self.streamBucket = [0]*256

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        nonStreamBucket = list(map(operator.sub, self.allBucket, self.streamBucket))
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(nonStreamBucket)
        if allCount == 0:
            return (0, 0, 0, None, 0, 0)
        entropyAll = sum(fEntropy(x, allCount) for x in self.allBucket)
        entropyStream = sum(fEntropy(x, streamCount) for x in self.streamBucket) if streamCount > 0 else None
        entropyNonStream = sum(fEntropy(x, nonStreamCount) for x in nonStreamBucket) if nonStreamCount > 0 else 0
        return (allCount, entropyAll, streamCount, entropyStream, nonStreamCount, entropyNonStream)

class cPDFEOF:
    """
    Track %%EOF occurrences & chars after last %%EOF.
    """
    def __init__(self):
        self.token = ''
        self.cntEOFs = 0
        self.cntCharsAfterLastEOF = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == '' and char == '%':
            self.token = '%'
        elif self.token == '%' and char == '%':
            self.token = '%%'
        elif self.token == '%%' and char == 'E':
            self.token = '%%E'
        elif self.token == '%%E' and char == 'O':
            self.token = '%%EO'
        elif self.token == '%%EO' and char == 'F':
            self.token = '%%EOF'
        elif self.token == '%%EOF' and char in ('\n', '\r', ' ', '\t'):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == '\n':
                self.token = ''
            else:
                self.token += char
        elif self.token == '%%EOF\r':
            if char == '\n':
                self.cntCharsAfterLastEOF = 0
            self.token = ''
        else:
            if self.token not in ('', '%%EOF'):
                self.token = ''

def FindPDFHeaderRelaxed(oBinaryFile):
    """
    Look for '%PDF' in the first 1024 bytes, ignoring some leading noise.
    Return (header_bytes, 'header string') or ([], None).
    """
    chunk = oBinaryFile.bytes(1024)
    chunk_str = ''.join(chr(b) for b in chunk)
    idx = chunk_str.find('%PDF')
    if idx == -1:
        oBinaryFile.ungets(chunk)
        return ([], None)
    end_header = idx + 4
    while end_header < len(chunk) and end_header < idx + 14:
        if chunk[end_header] in (10, 13):
            break
        end_header += 1
    oBinaryFile.ungets(chunk[end_header:])
    return (chunk[:end_header], chunk_str[idx:end_header])

def Hexcode2String(char):
    """
    Convert numeric char to #hex string.
    """
    return f'#{char:02x}'

def SwapCase(char):
    """
    Swap case for a single integer-based char code.
    """
    return ord(chr(char).swapcase())

def HexcodeName2String(hexcodeName):
    """
    Convert a list of char codes or strings to a #xx or literal string sequence.
    """
    out = []
    for c in hexcodeName:
        if isinstance(c, int):
            out.append(Hexcode2String(c))
        else:
            out.append(c)
    return ''.join(out)

def SwapName(wordExact):
    """
    Swap the case (for disarm).
    """
    swapped = []
    for c in wordExact:
        if isinstance(c, int):
            swapped.append(SwapCase(c))
        else:
            swapped.append(c.swapcase())
    return swapped

def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    """
    Update counters for recognized tokens and handle disarm output if fOut is set.
    """
    if word:
        token = slash + word
        if token in words:
            words[token][0] += 1
            if hexcode:
                words[token][1] += 1
        elif slash == '/' and allNames:
            words[token] = [1, 1 if hexcode else 0]

        if slash == '/':
            lastName = token

        if slash == '':
            if word == 'stream':
                insideStream = True
            elif word == 'endstream':
                if insideStream and oEntropy is not None:
                    for ch in "endstream":
                        oEntropy.removeInsideStream(ord(ch))
                insideStream = False

        if fOut is not None:
            # Disarm certain keywords
            if slash == '/' and token in ('/JS','/JavaScript','/AA','/OpenAction','/JBIG2Decode','/RichMedia','/Launch'):
                swapped_word = HexcodeName2String(SwapName(wordExact))
                fOut.write(swapped_word.encode('latin-1','ignore'))
            else:
                fOut.write(HexcodeName2String(wordExact).encode('latin-1','ignore'))

    return ('', [], False, lastName, insideStream)

class cCVE_2009_3459:
    """
    Check for suspicious /Colors > 2^24.
    """
    def __init__(self):
        self.count = 0

    def Check(self, lastName, word):
        if lastName == '/Colors' and word.isdigit() and int(word) > (1<<24):
            self.count += 1

def PDFiD(filename, allNames=False, extraData=False, disarm=False, force=False, data=None):
    """
    Main analysis function that returns a dictionary with PDF stats,
    keyword occurrences, possible dates, entropies, EOF info, etc.
    """
    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    insideStream = False

    # List of PDF-related keywords
    keywords = [
        'obj','endobj','stream','endstream','xref','trailer','startxref',
        '/Page','/Encrypt','/ObjStm','/JS','/JavaScript','/AA','/OpenAction',
        '/AcroForm','/JBIG2Decode','/RichMedia','/Launch','/EmbeddedFile','/XFA'
    ]
    # Dictionary to store counts: key -> [count, hexcodeCount]
    words = {kw: [0, 0] for kw in keywords}
    dates = []

    cveChecker = cCVE_2009_3459()
    oPDFDate = cPDFDate() if extraData else None
    oEntropy = cEntropy() if extraData else None
    oPDFEOF = cPDFEOF() if extraData else None

    # Final result dictionary
    result = {
        'filename': filename,
        'errorOccured': False,
        'errorMessage': '',
        'isPDF': None,
        'header': None,
        'keywords': words,
        'dates': [],
        'entropy': {
            'totalCount': None,
            'totalEntropy': None,
            'streamCount': None,
            'streamEntropy': None,
            'nonStreamCount': None,
            'nonStreamEntropy': None,
        },
        'countEOF': None,
        'countCharsAfterLastEOF': None,
        'colors_gt_2_24': 0,
        'disarmedFile': None
    }

    fOut = None
    try:
        oBinaryFile = cBinaryFile(filename, data)
        headerBytes, pdfHeader = FindPDFHeaderRelaxed(oBinaryFile)

        if disarm:
            base, ext = os.path.splitext(filename)
            disarmedFilename = base + '.disarmed' + ext
            fOut = open(disarmedFilename, 'wb')
            for hb in headerBytes:
                fOut.write(bytes([hb]))
            result['disarmedFile'] = disarmedFilename

        if oEntropy is not None:
            for hb in headerBytes:
                oEntropy.add(hb, insideStream)

        if pdfHeader is None and not force:
            result['isPDF'] = False
            result['header'] = ''
            return result
        else:
            result['isPDF'] = (pdfHeader is not None)
            if pdfHeader is None:
                pdfHeader = ''
            # Store up to first 10 chars for the header
            result['header'] = repr(pdfHeader[:10]).strip("'")

        b = oBinaryFile.byte()
        slash = ''
        while b is not None:
            ch = chr(b)
            if ch.isalnum():
                word += ch
                wordExact.append(ch)
            elif slash == '/' and ch == '#':
                d1 = oBinaryFile.byte()
                if d1 is not None:
                    d2 = oBinaryFile.byte()
                    if (d2 is not None 
                        and chr(d1) in '0123456789ABCDEFabcdef' 
                        and chr(d2) in '0123456789ABCDEFabcdef'):
                        val = int(chr(d1)+chr(d2), 16)
                        word += chr(val)
                        wordExact.append(val)
                        hexcode = True
                        if oEntropy is not None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF is not None:
                            oPDFEOF.parse(chr(d1))
                            oPDFEOF.parse(chr(d2))
                    else:
                        if d2 is not None:
                            oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        word, wordExact, hexcode, lastName, insideStream = UpdateWords(
                            word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                        )
                        if disarm and fOut is not None:
                            fOut.write(ch.encode('latin-1','ignore'))
                else:
                    if d1 is not None:
                        oBinaryFile.unget(d1)
                    word, wordExact, hexcode, lastName, insideStream = UpdateWords(
                        word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                    )
                    if disarm and fOut is not None:
                        fOut.write(ch.encode('latin-1','ignore'))
            else:
                cveChecker.Check(lastName, word)
                word, wordExact, hexcode, lastName, insideStream = UpdateWords(
                    word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                )
                slash = '/' if ch == '/' else ''
                if disarm and fOut is not None:
                    fOut.write(ch.encode('latin-1','ignore'))

            if oPDFDate is not None:
                dt = oPDFDate.parse(ch)
                if dt:
                    dates.append([dt, lastName])
            if oEntropy is not None:
                oEntropy.add(b, insideStream)
            if oPDFEOF is not None:
                oPDFEOF.parse(ch)

            b = oBinaryFile.byte()

        # Final flush
        cveChecker.Check(lastName, word)
        UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)

        if oPDFEOF is not None and oPDFEOF.token == '%%EOF':
            oPDFEOF.cntEOFs += 1
            oPDFEOF.cntCharsAfterLastEOF = 0
            oPDFEOF.token = ''

    except SystemExit:
        sys.exit()
    except Exception as e:
        result['errorOccured'] = True
        result['errorMessage'] = traceback.format_exc()

    if fOut is not None:
        fOut.close()

    # Fill final dictionary values
    dates.sort(key=lambda x: x[0])
    result['dates'] = dates
    result['colors_gt_2_24'] = cveChecker.count

    if oEntropy is not None:
        (countAll, entAll, countStream, entStream, countNonStream, entNonStream) = oEntropy.calc()
        result['entropy']['totalCount'] = countAll
        result['entropy']['totalEntropy'] = f"{entAll:.5f}" if entAll != 0 else None
        result['entropy']['streamCount'] = countStream
        result['entropy']['streamEntropy'] = f"{entStream:.5f}" if entStream else None
        result['entropy']['nonStreamCount'] = countNonStream
        result['entropy']['nonStreamEntropy'] = f"{entNonStream:.5f}" if entNonStream else None

    if oPDFEOF is not None:
        result['countEOF'] = oPDFEOF.cntEOFs
        result['countCharsAfterLastEOF'] = oPDFEOF.cntCharsAfterLastEOF if oPDFEOF.cntEOFs > 0 else None

    return result

def PDFiD2String(resultDict, nozero=False, force=False):
    """
    Produce a human-readable string from the dictionary returned by PDFiD().
    """
    lines = []
    lines.append(f"PDF Analysis for: {resultDict['filename']}")

    if resultDict['errorOccured']:
        lines.append("***ERROR OCCURRED***")
        lines.append(resultDict['errorMessage'])
        return "\n".join(lines)

    if not force and resultDict['isPDF'] is False:
        lines.append("Not a PDF document.")
        return "\n".join(lines)

    lines.append(f" PDF Header: {resultDict.get('header','')}")
    for kw, (count, hexcount) in resultDict['keywords'].items():
        if nozero and count == 0:
            continue
        if hexcount > 0:
            lines.append(f" {kw:16s} {count:7d}({hexcount})")
        else:
            lines.append(f" {kw:16s} {count:7d}")

    if resultDict['colors_gt_2_24'] > 0:
        lines.append(f" /Colors>2^24         {resultDict['colors_gt_2_24']:7d}")

    if resultDict['countEOF'] is not None:
        lines.append(f" {'%%EOF':16s} {resultDict['countEOF']:7d}")
    if resultDict['countCharsAfterLastEOF'] is not None:
        lines.append(f" {'After last %%EOF':16s} {resultDict['countCharsAfterLastEOF']:7d}")

    if resultDict['dates']:
        for dt, name in resultDict['dates']:
            lines.append(f" {dt:23s} {name}")

    ent = resultDict.get('entropy', {})
    if ent.get('totalEntropy') is not None:
        lines.append(f" Total entropy:           {ent['totalEntropy']} ({ent['totalCount']} bytes)")
        if ent['streamEntropy'] is not None:
            lines.append(f" Entropy inside streams:  {ent['streamEntropy']} ({ent['streamCount']} bytes)")
        lines.append(f" Entropy outside streams: {ent['nonStreamEntropy']} ({ent['nonStreamCount']} bytes)")

    return "\n".join(lines)

def PDFiD2JSON(resultDict):
    """
    Convert PDFiD's result dictionary to a JSON string.
    """
    data = {
        'filename': resultDict['filename'],
        'errorOccured': resultDict['errorOccured'],
        'errorMessage': resultDict['errorMessage'],
        'isPDF': resultDict['isPDF'],
        'header': resultDict['header'],
        'keywords': resultDict['keywords'],
        'dates': resultDict['dates'],
        'entropy': resultDict['entropy'],
        'countEOF': resultDict['countEOF'],
        'countCharsAfterLastEOF': resultDict['countCharsAfterLastEOF'],
        'colors_gt_2_24': resultDict['colors_gt_2_24'],
        'disarmedFile': resultDict['disarmedFile'],
    }
    return json.dumps([{'pdfid': data}], indent=2)

# Simple plugin system
class cPluginParent:
    onlyValidPDF = True

class cCount:
    def __init__(self, count, hexcount):
        self.count = count
        self.hexcount = hexcount

class cPDFiD:
    """
    Helper to interpret PDFiD dictionary. Simplified usage in plugins.
    """
    def __init__(self, resultDict, force):
        self.errorOccured = resultDict['errorOccured']
        self.isPDF = resultDict['isPDF']
        if not force and not self.isPDF:
            return
        self.keywords = {}
        for k, v in resultDict['keywords'].items():
            self.keywords[k] = cCount(v[0], v[1])

        def cc(n):
            return self.keywords.get(n, cCount(0,0))

        self.obj = cc('obj')
        self.endobj = cc('endobj')
        self.stream = cc('stream')
        self.endstream = cc('endstream')
        self.xref = cc('xref')
        self.trailer = cc('trailer')
        self.startxref = cc('startxref')
        self.page = cc('/Page')
        self.encrypt = cc('/Encrypt')
        self.objstm = cc('/ObjStm')
        self.js = cc('/JS')
        self.javascript = cc('/JavaScript')
        self.aa = cc('/AA')
        self.openaction = cc('/OpenAction')
        self.acroform = cc('/AcroForm')
        self.jbig2decode = cc('/JBIG2Decode')
        self.richmedia = cc('/RichMedia')
        self.launch = cc('/Launch')
        self.embeddedfile = cc('/EmbeddedFile')
        self.xfa = cc('/XFA')
        self.colors_gt_2_24 = resultDict.get('colors_gt_2_24', 0)

def gather_filenames(paths, recurse=False):
    """
    Expand file paths, directories (with optional recursion), or wildcard patterns.
    """
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p) and recurse:
            for root, dirs, files in os.walk(p):
                for f in files:
                    yield os.path.join(root, f)
        else:
            matches = glob.glob(p)
            if matches:
                for m in matches:
                    if os.path.isfile(m):
                        yield m
            else:
                yield p

def scan_single_file(filename, options, plugins):
    """
    Perform PDF analysis on a single file, optionally evaluate a selection
    expression or run plugin-based scoring.
    """
    result = PDFiD(filename,
                   allNames=options.all,
                   extraData=options.extra,
                   disarm=options.disarm,
                   force=options.force)
    if plugins or options.select:
        pdfid_obj = cPDFiD(result, options.force)
        # Evaluate select expression
        if options.select:
            if options.force or (not pdfid_obj.errorOccured and pdfid_obj.isPDF):
                try:
                    selected = eval(options.select, {}, {'pdf': pdfid_obj})
                    result['selected'] = bool(selected)
                except Exception as e:
                    result['selectError'] = f"Error in expression '{options.select}': {str(e)}"
                    result['selected'] = False
        # Run plugins
        if plugins:
            result['pluginScores'] = {}
            for cPlugin in plugins:
                if cPlugin.onlyValidPDF and (pdfid_obj.errorOccured or not pdfid_obj.isPDF):
                    result['pluginScores'][cPlugin.name] = None
                else:
                    try:
                        plugin_instance = cPlugin(pdfid_obj, options.pluginoptions)
                        score = plugin_instance.Score()
                        result['pluginScores'][cPlugin.name] = score
                    except Exception as err:
                        result['pluginScores'][cPlugin.name] = f"Plugin error: {str(err)}"
    return result

def main():
    parser = argparse.ArgumentParser(description="Advanced PDF Analysis & Disarm by Exfil0")
    parser.add_argument("files", nargs="*", help="PDF/ZIP files, directories, or wildcard patterns.")
    parser.add_argument("-r", "--recursedir", action="store_true", help="Recurse into directories.")
    parser.add_argument("-o", "--output", default="", help="Output CSV file (default: none).")
    parser.add_argument("--all", action="store_true", help="Display all recognized PDF names.")
    parser.add_argument("--extra", action="store_true", help="Display extra data (dates, entropy).")
    parser.add_argument("--force", action="store_true", help="Force scanning even w/o proper PDF header.")
    parser.add_argument("--disarm", action="store_true", help="Disarm malicious constructs into .disarmed file.")
    parser.add_argument("--select", default="", help="Selection expression, e.g. 'pdf.js.count>0'.")
    parser.add_argument("--nozero", action="store_true", help="Hide counts that are zero.")
    parser.add_argument("--threads", type=int, default=4, help="Number of worker threads (default=4).")
    parser.add_argument("--scan", action="store_true", help="Similar to scanning directory, for backward compat.")
    parser.add_argument("--plugins", default="", help="Comma-separated plugin file(s).")
    parser.add_argument("--pluginoptions", default="", help="Extra options for plugins.")
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format.")
    parser.add_argument("--minimumscore", type=float, default=0.0, help="Min plugin score required for output.")
    parser.add_argument("--verbose", action="store_true", help="Show verbose tracebacks on errors.")

    args = parser.parse_args()

    if not args.files:
        if args.disarm:
            print("[WARN] --disarm not supported with stdin.")
            args.disarm = False
        if args.scan:
            print("[WARN] --scan not supported with stdin.")
            args.scan = False
        args.files = [""]

    # Load plugins if specified
    loaded_plugins = []
    if args.plugins:
        scriptPath = os.path.dirname(sys.argv[0])
        plugin_files = []
        for item in args.plugins.split(","):
            item = item.strip()
            if not item.lower().endswith(".py"):
                item += ".py"
            if not os.path.exists(item):
                guess = os.path.join(scriptPath, item)
                if os.path.exists(guess):
                    item = guess
            plugin_files.append(item)

        for pf in plugin_files:
            try:
                g = {}
                with open(pf, "r", encoding="utf-8") as handle:
                    code = handle.read()
                exec(code, g)
                for oname, oval in g.items():
                    if isinstance(oval, type) and issubclass(oval, cPluginParent) and oval is not cPluginParent:
                        loaded_plugins.append(oval)
            except Exception as e:
                print(f"[ERROR] Loading plugin {pf}: {str(e)}")
                if args.verbose:
                    traceback.print_exc()

    # Gather filenames
    filelist = list(gather_filenames(args.files, recurse=args.recursedir))
    if not filelist:
        print("[INFO] No files found to process.")
        sys.exit(0)

    # Concurrent scanning
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {executor.submit(scan_single_file, f, args, loaded_plugins): f for f in filelist}
        for fut in as_completed(future_map):
            fname = future_map[fut]
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                if args.verbose:
                    traceback.print_exc()
                results.append({
                    'filename': fname,
                    'errorOccured': True,
                    'errorMessage': str(e),
                    'isPDF': None
                })

    # Output handling
    if args.csv:
        # CSV output
        if not args.output:
            csvfile = sys.stdout
        else:
            csvfile = open(args.output, "w", newline="", encoding="utf-8")

        fieldnames = [
            "filename","isPDF","errorOccured","errorMessage","header","disarmedFile",
            "colors_gt_2_24","countEOF","countCharsAfterLastEOF","selected"
        ]
        plugin_names = set()
        for r in results:
            if 'pluginScores' in r:
                plugin_names.update(r['pluginScores'].keys())
        plugin_names = sorted(plugin_names)
        fieldnames.extend(plugin_names)

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = {
                "filename": r.get("filename",""),
                "isPDF": r.get("isPDF",""),
                "errorOccured": r.get("errorOccured",""),
                "errorMessage": r.get("errorMessage",""),
                "header": r.get("header",""),
                "disarmedFile": r.get("disarmedFile",""),
                "colors_gt_2_24": r.get("colors_gt_2_24",""),
                "countEOF": r.get("countEOF",""),
                "countCharsAfterLastEOF": r.get("countCharsAfterLastEOF",""),
                "selected": r.get("selected",""),
            }
            scores = r.get('pluginScores', {})
            for pn in plugin_names:
                val = scores.get(pn, "")
                if isinstance(val, (int,float)) and val < args.minimumscore:
                    val = ""
                row[pn] = val
            writer.writerow(row)

        if csvfile is not sys.stdout:
            csvfile.close()
        print(f"[INFO] Processed {len(results)} file(s). CSV written to {args.output or 'stdout'}.")

    else:
        # Textual console output
        for r in results:
            # If there's a selection filter, skip unselected
            if args.select and not r.get('selected', True):
                continue

            # If plugin minscore is set, skip if none pass
            if 'pluginScores' in r:
                plugin_ok = False
                for sc in r['pluginScores'].values():
                    if isinstance(sc, (int,float)) and sc >= args.minimumscore:
                        plugin_ok = True
                        break
                if not plugin_ok and args.minimumscore > 0:
                    continue

            txt = PDFiD2String(r, nozero=args.nozero, force=args.force)
            print(txt)
            print("-"*60)

if __name__ == "__main__":
    main()
