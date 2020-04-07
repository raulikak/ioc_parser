#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:             iocp.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            iocp.py [-h] [-p INI] [-f FORMAT] PDF
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import sys
import os
import fnmatch
import glob
import re
import six.moves.configparser as ConfigParser
from six import StringIO
import csv

try:
    import configparser
except ImportError:
    import configparser as ConfigParser

# Import optional third-party libraries
try:
    import xlrd
except ImportError:
    pass

try:
    import gmail
except ImportError:
    pass

try:
    from PyPDF2 import PdfFileReader
except ImportError:
    pass

try:
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager
    from pdfminer.converter import TextConverter
    from pdfminer.pdfinterp import PDFPageInterpreter
    from pdfminer.layout import LAParams
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
except ImportError:
    pass

try:
    import requests
except ImportError:
    pass
try:
    import docx2txt
except ImportError:
    pass

# Import project source files
import iocp
from iocp import Output


class Parser(object):
    patterns = {}
    defang   = {}

    def __init__(self, patterns_ini=None, input_format='pdf', dedup=False, library='pdfminer', output_format='csv', proxy=None, output_handler=None):
        self.__init_patterns(patterns_ini)
        self.__init_whitelist()
        self.__init_dedup(dedup)
        self.__init_output_handler(output_format, output_handler)
        self.__init_parser(input_format)
        self.__init_library(library, input_format)

        # Depending on the type of proxy, set the proper proxy setting for storage to be used with Requests
        if proxy is not None:
            if proxy.startswith('http://'):
                self.proxy = {'http': proxy}
            elif proxy.startswith('https://'):
                self.proxy = {'https': proxy}
        else:
            self.proxy = proxy

    def __init_patterns(self, patterns_ini):
        if patterns_ini is None:
            patterns_ini = os.path.join(iocp.get_basedir(), 'data/patterns.ini')

        self.load_patterns(patterns_ini)

    def __init_whitelist(self):
        wldir = os.path.join(iocp.get_basedir(), 'data/whitelists')
        self.whitelist = self.load_whitelists(wldir)

    def __init_dedup(self, dedup):
        self.dedup = dedup

        if dedup:
            self.dedup_store = set()

    def __init_output_handler(self, output_format, output_handler):
        self.handler = output_handler if output_handler else Output.getHandler(output_format)

    def __init_parser(self, input_format):
        self.ext_filter = "*.{}".format(input_format)
        parser_format = "parse_{}".format(input_format)

        self.parser_func = getattr(self, parser_format, None)
        if not self.parser_func:
            print(('Selected parser format is not supported: {}'.format(input_format)))
            sys.exit(-1)

    def __init_library(self, library, input_format):
        self.library = library

        if input_format in ('pdf', ) and library not in sys.modules:
            print(('PDF parser library not found: {}'.format(library)))
            sys.exit(-1)

        if input_format in ('html', ) and 'bs4' not in sys.modules:
            print('HTML parser library not found: BeautifulSoup')
            sys.exit(-1)

        if input_format in ('xlsx', ) and 'xlrd' not in sys.modules:
            print('XLRD Library not found. Please visit: https://github.com/python-excel/xlrd or pip install xlrd')
            sys.exit(-1)

        if input_format in ('gmail', ) and 'gmail' not in sys.modules:
            print('Gmail library not found. Please visit: https://github.com/charlierguo/gmail')
            sys.exit(-1)

    def load_patterns(self, fpath):
        config = configparser.ConfigParser()

        with open(fpath) as f:
            config.readfp(f)

        for ind_type in config.sections():
            try:
                ind_pattern = config.get(ind_type, 'pattern')
            except configparser.NoOptionError:
                continue

            if ind_pattern:
                if ind_type == 'URL':
                    ind_regex = re.compile(ind_pattern, re.IGNORECASE|re.MULTILINE|re.DOTALL)
                else:
                    ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

            try:
                ind_defang = config.get(ind_type, 'defang')
            except configparser.NoOptionError:
                continue

            if ind_defang:
                self.defang[ind_type] = True

    def load_whitelists(self, fpath):
        whitelist = {}

        searchdir = os.path.join(fpath, "whitelist_*.ini")
        fpaths = glob.glob(searchdir)
        for fpath in fpaths:
            t = os.path.splitext(os.path.split(fpath)[1])[0].split('_', 1)[1]
            patterns = [line.strip() for line in open(fpath)]
            whitelist[t] = [re.compile(p, flags = re.IGNORECASE) for p in patterns]

        return whitelist

    def is_whitelisted(self, ind_match, ind_type):
        try:
            for w in self.whitelist[ind_type]:
                if w.findall(ind_match):
                    return True
        except KeyError:
            pass

        return False

    def parse_page(self, fpath, data, page_num, flag=0, sheet_name=''):
        """ Added flag and sheet_name variables for new inputs to help properly
        print output
        
        @param fpath: the file path, directory, URL or email account
        @param data: the data to be parsed
        @param page_num: the page number of a pdf, line number of csv, xls or xlsx
        @param flag:
            0 = default (pdf/txt/html)
            1 = gmail
            2 = csv
            3 = xls and xlsx
        @param sheet_name: to be used only with Excel spreadsheets
        """
        for ind_type, ind_regex in list(self.patterns.items()):
            matches = ind_regex.findall(data)

            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, ind_type):
                    continue

                if ind_type in self.defang:
                    ind_match = re.sub(r'\[\.\]', '.', ind_match)

                if self.dedup:
                    if (ind_type, ind_match) in self.dedup_store:
                        continue

                    self.dedup_store.add((ind_type, ind_match))

                # Added flag and sheet_name to determine which type of output to display
                self.handler.print_match(fpath, page_num, ind_type, ind_match, flag, sheet_name)

    def parse_pdf_pypdf2(self, f, fpath):
        try:
            pdf = PdfFileReader(f, strict = False)

            self.handler.print_header(fpath)
            page_num = 0
            for page in pdf.pages:
                page_num += 1

                data = page.extractText()

                self.parse_page(fpath, data, page_num)

            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise

    def parse_pdf_pdfminer(self, f, fpath):
        try:
            laparams = LAParams()
            laparams.all_texts = True
            rsrcmgr = PDFResourceManager()
            pagenos = set()

            self.handler.print_header(fpath)
            page_num = 0

            for page in PDFPage.get_pages(f, pagenos, check_extractable=True):
                page_num += 1

                retstr = StringIO()
                device = TextConverter(rsrcmgr, retstr, codec='utf-8', laparams=laparams)
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                interpreter.process_page(page)
                data = retstr.getvalue()
                retstr.close()

                self.parse_page(fpath, data, page_num)

            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise

    def parse_pdf(self, f, fpath):
        parser_format = "parse_pdf_" + self.library

        self.parser_func = getattr(self, parser_format, None)
        if not self.parser_func:
            e = 'Selected PDF parser library is not supported: {}'.format(self.library)
            raise NotImplementedError(e)

        self.parser_func(f, fpath)

    def parse_txt(self, f, fpath):
        try:
            data = f.read()
            self.handler.print_header(fpath)
            self.parse_page(fpath, data, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise

    def parse_html(self, f, fpath):
        try:
            data = f.read()
            soup = BeautifulSoup(data, "lxml")
            html = soup.findAll(text = True)

            text = ''
            for elem in html:
                if elem.parent.name in ['style', 'script', '[document]', 'head', 'title']:
                    continue
                elif re.match('<!--.*-->', str(elem)):
                    continue
                else:
                    text += str(elem)

            self.handler.print_header(fpath)
            self.parse_page(fpath, text, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise

    def parse_docx(self, f, fpath):
        try:
            text = docx2txt.process(f)

            if self.dedup:
                self.dedup_store = set()
            self.handler.print_header(fpath)
            self.parse_page(fpath, text, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise

    def parse_csv(self, f, fpath):
        """ This method is used to parse a csv file. The flag
        used for this method to send to output.py is 2.

        @author Robb Krasnow
        """
        try:
            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)

            with open(fpath, 'rb') as csvfile:
                csv_data = csv.reader(csvfile, delimiter=',', quotechar='|')
                
                for row in csv_data:
                    line = ', '.join(row).rstrip()
                    unicode_output = str(line, 'ascii', errors='ignore')
                                        
                    self.parse_page(fpath, unicode_output, csv_data.line_num, 2)

            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)


    def parse_xls(self, f, fpath):
        """ Created this function just to allow a user to use 'xls' as an input
        option without any errors.

        @author Robb Krasnow
        """
        self.parse_xlsx(f, fpath)


    def parse_xlsx(self, f, fpath):
        """ This method is used to parse Microsoft Excel files
        with either .xls or .xlsx extentions. The flag
        used for this method to send to output.py is 3. Because
        Excel spreadsheets may have multiple tabs, the sheet's
        name is passed through the parse_page method in turn showing
        that in the output.

        @author Robb Krasnow
        """
        try:
            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            workbook = xlrd.open_workbook(fpath)
            sheets = workbook.sheets()

            for sheet in sheets:
                sheet_name = sheet.name

                for row in range(sheet.nrows):
                    for col in range(sheet.ncols):
                        if sheet.cell_value(row, col) is not xlrd.empty_cell.value:
                            val = repr(sheet.cell_value(row, col))
            
                            self.parse_page(fpath, val, row+1, 3, sheet_name)

            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)


    def parse_gmail(self, username, password):
        """ This method is used to parse the inbox of a valid 
        Gmail account. The flag used for this method to send to
        output.py is 1.

        @author                 Robb Krasnow
        @param      username    The gmail account's username
        @param      password    The gmail account's password
        """
        try:
            if self.dedup:
                self.dedup_store = set()

            # Log the user in
            g = gmail.login(username, password)

            # When the user is logged in, grab all the email from their inbox
            # and parse all the messages for IOCs
            if g.logged_in:
                print('***** Login Successful. *****\n')

                self.handler.print_header(username)
                emails = g.inbox().mail()

                for email in range(0, len(emails)):
                    try:
                        emails[email].fetch()
                        content = emails[email].body
                        subject = re.sub('(^\s|re:\s+|\r\n|fwd:\s+)', '', emails[email].subject, flags=re.IGNORECASE)

                        self.parse_page(subject, content, 1, 1)
                    except Exception as e:
                        continue
                
                self.handler.print_footer(username)

                print('\n***** %s emails found. *****' % len(emails))
                g.logout()
                print('***** Logout Successful. *****')
            else:
                sys.exit()
        except gmail.exceptions.AuthenticationError:
            print('Authentication Error')
            sys.exit()


    def parse(self, path):
        try:
            if path.startswith('http://') or path.startswith('https://'):
                if 'requests' not in sys.modules:
                    e = 'HTTP library not found: requests'
                    raise ImportError(e)

                headers = { 'User-Agent': 'Mozilla/5.0 Gecko Firefox' }

                # If using proxy, make request with proxy from --proxy switch
                # Otherwise make the call normally
                if self.proxy is not None:
                    r = requests.get(path, headers=headers, proxies=self.proxy)
                else:
                    r = requests.get(path, headers=headers)
                r.raise_for_status()

                f = StringIO(r.content)
                self.parser_func(f, path)
                return
            if os.path.isfile(path):
                with open(path, 'rb') as f:
                    self.parser_func(f, path)
                return
            if os.path.isdir(path):
                for walk_root, walk_dirs, walk_files in os.walk(path):
                    for walk_file in fnmatch.filter(walk_files, self.ext_filter):
                        fpath = os.path.join(walk_root, walk_file)
                        with open(fpath, 'rb') as f:
                            self.parser_func(f, fpath)
                return
            # Check if the input from CLI has @gmail.com attached
            # If so, grab the credentials, and send them to parse_gmail()
            elif path.count('@gmail.com ') == 1 and len(path.split()) == 2:
                gmail_account = path.split()
                username = gmail_account[0]
                password = gmail_account[1]
                self.parser_func(username, password)

                return

            e = 'File path is not a file, directory or URL: %s' % (path)
            raise IOError(e)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(path, e)

if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument('PATH', action='store', help='File/directory/URL to report(s)/Gmail account in double quotes ("username@gmail.com password")')
    argparser.add_argument('-p', dest='INI', default=None, help='Pattern file')
    argparser.add_argument('-i', dest='INPUT_FORMAT', default='pdf', help='Input format (pdf/txt/html/csv/xls/xlsx/gmail)')
    argparser.add_argument('-o', dest='OUTPUT_FORMAT', default='csv', help='Output format (csv/json/yara/netflow)')
    argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
    argparser.add_argument('-l', dest='LIB', default='pdfminer', help='PDF parsing library (pypdf2/pdfminer)')
    argparser.add_argument('--proxy', dest='PROXY', default=None, help='Sets proxy (http(s)://server:port)')
    args = argparser.parse_args()

    parser = IOC_Parser(args.INI, args.INPUT_FORMAT, args.DEDUP, args.LIB, args.OUTPUT_FORMAT, args.PROXY)
    parser.parse(args.PATH)
