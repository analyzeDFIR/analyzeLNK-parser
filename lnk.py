## -*- coding: UTF-8 -*_
## lnk.py
##
## Copyright (c) 2018 analyzeDFIR
## 
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
## 
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
## 
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.

from construct.lib import Container

try:
    from lib.parsers import FileParser, ByteParser
    from lib.parsers.utils import StructureProperty, WindowsTime
    from structures import lnk as lnkstructs
except ImportError:
    from .lib.parsers import FileParser, ByteParser
    from .lib.parsers.utils import StructureProperty, WindowsTime
    from .structures import lnk as lnkstructs

class LNK(FileParser):
    '''
    Class for parsing Windows LNK file
    '''
    header = StructureProperty(0, 'header')
    linktarget_idlist = StructureProperty(1, 'linktarget_idlist', deps=['header'])
    link_info = StructureProperty(2, 'link_info', deps=['header'])
    string_data = StructureProperty(3, 'string_data', deps=['header'])
    extra_data = StructureProperty(4, 'extra_data', deps=['header'])

    def _parse_link_info(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            LNK file link (target) info (see: structures.LNKLocationInformation)
        Preconditions:
            N/A
        '''
        pass
    def _parse_linktarget_idlist(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            LNK file link target ID list (see: structures.LNKLinkTargetIDListItemID)
        Preconditions:
            N/A
        '''
        if not self.header.DataFlags.HasTargetIDList:
            return None
        idlist = Container()
        idlist.Size = LNKLinkTargetIDListSize.parse_stream(self.stream)
        idlist.idlist = None
        original_position = self.stream.tell()
        try:
            if idlist_size > 2:
                idlist.idlist = list()
                while self.stream.tell() < ( original_position + idlist.Size ):
                    idlist.idlist.append(LNKLinkTargetIDListItemID.parse_stream(self.stream))
            return self._clean_value(idlist)
        finally:
            self.stream.seek(original_position + idlist.Size)
    def _parse_header(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            LNK file header (see: structures.LNKFileHeader)
        Preconditions:
            N/A
        '''
        header = lnkstructs.LNKFileHeader.parse_stream(self.stream)
        if not (
            header.LNKClassIdentifier.Group1 == 0x00021401 and \
            header.LNKClassIdentifier.Group2 == 0x0000 and \
            header.LNKClassIdentifier.Group3 == 0x0000 and \
            header.LNKClassIdentifier.Group4 == 0xC000 and \
            header.LNKClassIdentifier.Group5 == 0x000000000046
        ):
            raise ValueError('found incorrect link class identifier')
        return self._clean_value(header)
