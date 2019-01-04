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

import logging
Logger = logging.getLogger(__name__)
from io import SEEK_CUR
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

    def __init__(self, *args, codepage='UTF8', **kwargs):
        super().__init__(*args, **kwargs)
        self.codepage = codepage
    @property
    def codepage(self):
        '''
        Getter for codepage
        '''
        return self.__codepage
    @codepage.setter
    def codepage(self, value):
        '''
        Setter for codepage
        '''
        assert isinstance(value, str)
        self.__codepage = value
    def __parse_string_data_string(self, encoding='UTF16'):
        '''
        Args:
            encoding: String    => encoding of string to parse
        Returns:
            String
            Parsed string from stream
        Preconditions:
            encoding is of type String
        '''
        assert isinstance(encoding, str)
        num_chars = lnkstructs.Int16ul.parse_stream(self.stream)
        return self.stream.read( num_chars * 2 ).decode(encoding)
    def __parse_link_info_string(self, offset=0, encoding='UTF8'):
        '''
        Args:
            offset: Integer     => offset into stream
            encoding: String    => encoding of string to parse
        Returns:
            String
            Parsed string from stream
        Preconditions:
            offset is of type Integer
            encoding is of type String
        '''
        assert isinstance(offset, int)
        assert isinstance(encoding, str)
        if offset > 0:
            self.stream.seek(offset)
        try:
            return lnkstructs.CString(encoding).parse_stream(self.stream)
        except:
            return None
    def _parse_string_data(self):
        '''
        Args:
            N/A
        Returns:
            Container<String, Any>
            LNK file string data
        Preconditions:
            N/A
        '''
        string_data = Container()
        if self.header.DataFlags.HasName:
            string_data.NAME_STRING = self.__parse_string_data_string()
        if self.header.DataFlags.HasRelativePath:
            string_data.RELATIVE_PATH = self.__parse_string_data_string()
        if self.header.DataFlags.HasWorkingDir:
            string_data.WORKING_DIR = self.__parse_string_data_string()
        if self.header.DataFlags.HasArguments:
            string_data.COMMAND_LINE_ARGUMENTS = self.__parse_string_data_string()
        if self.header.DataFlags.HasIconLocation:
            string_data.ICON_LOCATION = self.__parse_string_data_string()
        return string_data
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
        if not self.header.DataFlags.HasLinkInfo:
            return None
        link_info = Container()
        original_position = self.stream.tell()
        # STEP: Parse the link information header
        link_info.header = lnkstructs.LNKLocationInformationHeader.parse_stream(self.stream)
        try:
            # STEP: Parse the link information common path suffix
            if link_info.header.HeaderSize >= 0x24:
                target_offset = link_info.header.UCommonPathSuffixOffset
                encoding = 'UTF8'
            else:
                target_offset = link_info.header.CommonPathSuffixOffset
                encoding = self.codepage
            link_info.CommonPathSuffix = self.__parse_link_info_string(
                offset=(original_position + target_offset), 
                encoding=encoding
            )
            # CONDITION: Has volume ID and local base path
            if link_info.header.Flags.VolumeIDAndLocalBasePath:
                # STEP: Parse volume ID
                self.stream.seek(original_position + link_info.header.VolumeIDOffset)
                link_info.VolumeID = lnkstructs.LNKVolumeInformationHeader.parse_stream(self.stream)
                # STEP: Parse volume ID volume label
                if link_info.VolumeID.VolumeLabelOffset == 0x14:
                    target_offset = link_info.VolumeID.UVolumeLabelOffset
                    encoding = 'UTF8'
                else:
                    target_offset = link_info.VolumeID.VolumeLabelOffset
                    encoding = self.codepage
                link_info.VolumeID.VolumeLabel = self.__parse_link_info_string(offset=(
                    original_position + \
                    link_info.header.VolumeIDOffset + \
                    target_offset
                ), encoding=encoding)
                # Step: Parse local base path
                if link_info.header.HeaderSize >= 0x24:
                    target_offset = link_info.header.ULocalBasePathOffset
                    encoding = 'UTF8'
                else:
                    target_offset = link_info.header.LocalBasePathOffset
                    encoding = self.codepage
                link_info.LocalBasePath = self.__parse_link_info_string(
                    offset=(original_position + target_offset), 
                    encoding=encoding
                )
            # CONDITION: Has common network relative link structure and path suffix
            if link_info.header.Flags.CommonNetworkRelativeLinkAndPathSuffix:
                # STEP: Parse common network relative link structure
                self.stream.seek(original_position + link_info.header.CommonNetworkRelativeLinkOffset)
                link_info.CommonNetworkRelativeLink = lnkstructs.LNKNetworkShareInformationHeader.parse_stream(self.stream)
                # STEP: Parse common network relative link share (net) name
                if link_info.CommonNetworkRelativeLink.UShareNameOffset is not None:
                    target_offset = link_info.CommonNetworkRelativeLink.UShareNameOffset
                    encoding = 'UTF8'
                else:
                    target_offset = link_info.CommonNetworkRelativeLink.ShareNameOffset
                    encoding = self.codepage
                link_info.CommonNetworkRelativeLink.ShareName = self.__parse_link_info_string(offset=(
                    original_position + \
                    link_info.header.CommonNetworkRelativeLinkOffset + \
                    target_offset
                ), encoding=encoding)
                # CONDITION: Has valid device name
                if link_info.CommonNetworkRelativeLink.Flags.ValidDevice:
                    # STEP: Parse common network relative link device name
                    if link_info.CommonNetworkRelativeLink.UDeviceNameOffset is not None:
                        target_offset = link_info.CommonNetworkRelativeLink.UDeviceNameOffset
                        encoding = 'UTF8'
                    else:
                        target_offset = link_info.CommonNetworkRelativeLink.DeviceNameOffset
                        encoding = self.codepage
                    link_info.CommonNetworkRelativeLink.DeviceName = self.__parse_link_info_string(offset=(
                        original_position + \
                        link_info.header.CommonNetworkRelativeLinkOffset + \
                        target_offset
                    ), encoding=encoding)
        finally:
            self.stream.seek(original_position + link_info.header.Size)
        return link_info
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
        idlist.Size = lnkstructs.LNKLinkTargetIDListSize.parse_stream(self.stream)
        idlist.idlist = None
        original_position = self.stream.tell()
        try:
            if idlist.Size > 2:
                idlist.idlist = list()
                while self.stream.tell() < ( original_position + idlist.Size ):
                    idlist.idlist.append(
                        lnkstructs.LNKLinkTargetIDListItemID.parse_stream(self.stream)
                    )
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
            header.LNKClassIdentifier.Group4 == 0x00C0 and \
            header.LNKClassIdentifier.Group5 == 0x000000000046
        ):
            Logger.warning('found incorrect link class identifier')
        header.CreateTime = WindowsTime.parse_filetime(header.RawCreateTime)
        header.LastAccessTime = WindowsTime.parse_filetime(header.RawLastAccessTime)
        header.LastModifiedTime = WindowsTime.parse_filetime(header.RawLastModifiedTime)
        return self._clean_value(header)
