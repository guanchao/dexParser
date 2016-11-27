#!/usr/bin/env python
#coding:utf-8

# BSD 2-Clause License
#
# Copyright (c) [2016], [guanchao wen], shuwoom.wgc@gmail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import binascii

import OpCode
import InstrUtils

MAP_ITEM_TYPE_CODES = {
    0x0000 : "kDexTypeHeaderItem",
    0x0001 : "kDexTypeStringIdItem",
    0x0002 : "kDexTypeTypeIdItem",
    0x0003 : "kDexTypeProtoIdItem",
    0x0004 : "kDexTypeFieldIdItem",
    0x0005 : "kDexTypeMethodIdItem",
    0x0006 : "kDexTypeClassDefItem",
    0x1000 : "kDexTypeMapList",
    0x1001 : "kDexTypeTypeList",
    0x1002 : "kDexTypeAnnotationSetRefList",
    0x1003 : "kDexTypeAnnotationSetItem",
    0x2000 : "kDexTypeClassDataItem",
    0x2001 : "kDexTypeCodeItem",
    0x2002 : "kDexTypeStringDataItem",
    0x2003 : "kDexTypeDebugInfoItem",
    0x2004 : "kDexTypeAnnotationItem",
    0x2005 : "kDexTypeEncodedArrayItem",
    0x2006 : "kDexTypeAnnotationsDirectoryItem",
}


class DexFile(object):
    """docstring for DexFile"""
    def __init__(self, filepath):
        super(DexFile, self).__init__()
        self.filepath = filepath
        self.init_header(self.filepath) # Init dex header
        self.init_DexStringId() # Init DexStringId index table
        self.init_DexTypeId() # Init DexTypeId index table
        self.init_DexProtoId() # Init DexProtoId index table
        self.int_DexFieldId() # Init DexFieldId index table
        self.init_DexMethodId() # Init DexMethodId index table


    def init_header(self, filepath):
        """
        typedef struct DexHeader {
            u1  magic[8];           /* includes version number */
            u4  checksum;           /* adler32 checksum */
            u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
            u4  fileSize;           /* length of entire file */
            u4  headerSize;         /* offset to start of next section */
            u4  endianTag;
            u4  linkSize;
            u4  linkOff;
            u4  mapOff;
            u4  stringIdsSize;
            u4  stringIdsOff;
            u4  typeIdsSize;
            u4  typeIdsOff;
            u4  protoIdsSize;
            u4  protoIdsOff;
            u4  fieldIdsSize;
            u4  fieldIdsOff;
            u4  methodIdsSize;
            u4  methodIdsOff;
            u4  classDefsSize;
            u4  classDefsOff;
            u4  dataSize;
            u4  dataOff;
        } DexHeader;
        """
        f = open(filepath, "rb")
        self.f = f

        f.seek(0x0, 0)
        self.magic = binascii.b2a_hex(f.read(8))

        f.seek(0x8, 0)
        self.checksum = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0xc, 0)
        self.signature = binascii.b2a_hex(f.read(20))

        f.seek(0x20, 0)
        self.file_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x24, 0)
        self.header_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x28, 0)
        self.endian_tag = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x2c, 0)
        self.link_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x30, 0)
        self.link_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x34, 0)
        self.map_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x38, 0)
        self.string_ids_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x3c, 0)
        self.string_ids_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x40, 0)
        self.type_ids_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x44, 0)
        self.type_ids_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x48, 0)
        self.proto_ids_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x4c, 0)
        self.proto_ids_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x50, 0)
        self.field_ids_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x54, 0)
        self.field_ids_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x58, 0)
        self.method_ids_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x5c, 0)
        self.method_ids_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x60, 0)
        self.class_defs_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x64, 0)
        self.class_defs_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x68, 0)
        self.data_size = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

        f.seek(0x6c, 0)
        self.data_off = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')

    def print_header(self):
        print '[+] magic:\t0x' + self.magic
        print '[+] checksum:\t0x' + self.checksum
        print '[+] signature:\t' + self.signature
        print '[+] file_size:\t0x' + self.file_size
        print '[+] header_size:\t0x' + self.header_size
        print '[+] endian_tag:\t0x' + self.endian_tag
        print '[+] link_size:\t0x' + self.link_size
        print '[+] link_off:\t0x' + self.link_off
        print '[+] map_off:\t0x' + self.map_off
        print '[+] string_ids_size:\t0x' + self.string_ids_size
        print '[+] string_ids_off:\t0x' + self.string_ids_off
        print '[+] type_ids_size:\t0x' + self.type_ids_size
        print '[+] type_ids_off:\t0x' + self.type_ids_off
        print '[+] proto_ids_size:\t0x' + self.proto_ids_size
        print '[+] proto_ids_off:\t0x' + self.proto_ids_off
        print '[+] field_ids_size:\t0x' + self.field_ids_size
        print '[+] field_ids_off:\t0x' + self.field_ids_off
        print '[+] method_ids_size:\t0x' + self.method_ids_size
        print '[+] method_ids_off:\t0x' + self.method_ids_off
        print '[+] class_defs_size:\t0x' + self.class_defs_size
        print '[+] class_defs_off:\t0x' + self.class_defs_off
        print '[+] data_size:\t0x' + self.data_size
        print '[+] data_off:\t0x' + self.data_off

    def print_DexMapList(self):
        """
        typedef struct DexMapList {
            u4  size;               /* #of entries in list */
            DexMapItem list[1];     /* entries */
        } DexMapList;
        """
        map_off_int = int(self.map_off, 16)

        #u4 size
        self.f.seek(map_off_int, 0)
        size_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
        size = int(size_hex, 16)

        for index in range(size):
            # DexMapItem list[]
            self.print_DexMapItem(map_off_int+4, index)

    def print_DexMapItem(self, map_off, index):
        """
        typedef struct DexMapItem {
            u2  type;              /* type code (see kDexType* above) */
            u2  unused;
            u4  size;              /* count of items of the indicated type */
            u4  offset;            /* file offset to the start of data */
        } DexMapItem;
        """
        #u2 type
        self.f.seek(map_off + index*12, 0)
        dexType = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')

        #u2 unused
        self.f.seek(map_off + index*12 + 2, 0)
        unused = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')

        #u4 size
        self.f.seek(map_off + index*12 + 4, 0)
        size = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')

        #u4 offset
        self.f.seek(map_off + index*12 + 8, 0)
        offset = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')

        print '\n'
        print '[+] #%d DexMapItem:\t' % index
        print '    u2 dexType\t%s #%s' % (dexType, MAP_ITEM_TYPE_CODES[int(dexType, 16)])
        print '    u2 unused\t' + unused
        print '    u4 size\t' + size
        print '    u4 offset\t' + offset

    def init_DexStringId(self):
        """
        typedef struct DexStringId {
            u4  stringDataOff;      /* file offset to string_data_item */
        } DexStringId;
        """
        string_ids_off_int = int(self.string_ids_off, 16)
        string_ids_size_int = int(self.string_ids_size, 16)


        self.DexStringIdList = []
        for index in range(string_ids_size_int):
            # string offset
            self.f.seek(string_ids_off_int + index*4, 0)
            string_data_off = int(binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            self.f.seek(string_data_off, 0)

            # length of str
            self.f.read(1)

            length = 0
            while int(binascii.b2a_hex(self.f.read(1)).decode('hex')[::-1].encode('hex'),16) != 0:
                length += 1

            self.f.seek(string_data_off + 1,0)
            dex_str = self.f.read(length)
            self.f.read(1) # remove \x00
            string_data_off += (length + 2) # + \0 + size bit

            # self.DexStringIdList.append(dex_str.decode('utf-8'))
            self.DexStringIdList.append(dex_str)

    def print_DexStringId(self):

        print '\n'
        print '[+] DexStringId:'
        for index in range(len(self.DexStringIdList)):
            print '    #%s %s' % (hex(index), self.DexStringIdList[index])

    def init_DexTypeId(self):
        type_ids_off_int = int(self.type_ids_off, 16)
        type_ids_size_int = int(self.type_ids_size, 16)

        self.f.seek(type_ids_off_int, 0)

        self.DexTypeIdList = []
        for index in range(type_ids_size_int):
            descriptorIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            descriptorIdx_int = int(descriptorIdx_hex, 16)

            self.DexTypeIdList.append(self.DexStringIdList[descriptorIdx_int])

    def print_DexTypeId(self):
        print '\n'
        print '[+] DexTypeId:'
        for index in range(len(self.DexTypeIdList)):
            print '    #%s #%s' % (hex(index), self.DexTypeIdList[index])

    def init_DexProtoId(self):
        proto_ids_size_int = int(self.proto_ids_size, 16)
        proto_ids_off_int = int(self.proto_ids_off, 16)
        self.DexProtoIdList = []

        for index in range(proto_ids_size_int):
            self.f.seek(proto_ids_off_int+index*12, 0)
            # u4 shortyIdx
            shortyIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            shortyIdx = int(shortyIdx_hex, 16)
            # u4 returnTypeIdx
            returnTypeIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            returnTypeIdx = int(returnTypeIdx_hex, 16)
            # u4 parametersOff
            parametersOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            parametersOff = int(parametersOff_hex, 16)

            if parametersOff == 0:
                self.DexProtoIdList.append((self.DexStringIdList[shortyIdx], self.DexTypeIdList[returnTypeIdx], parametersOff_hex, "()"))
                continue
            self.f.seek(parametersOff, 0)

            parameter_str = ""
            # Struct DexTypeList
            # u4 size
            dexTypeItemSize_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            dexTypeItemSize = int(dexTypeItemSize_hex, 16)
            # DexTypeItem list[]
            for i in range(dexTypeItemSize):
                # Struct DexTypeItem
                # u2 typeIdx
                typeIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
                typeIdx = int(typeIdx_hex, 16)
                parameter_str = parameter_str + self.DexTypeIdList[typeIdx] + ", "
            self.DexProtoIdList.append((self.DexStringIdList[shortyIdx], self.DexTypeIdList[returnTypeIdx], parametersOff_hex,'('+parameter_str+')'))

    def print_DexProtoId(self):
        proto_ids_off_int = int(self.proto_ids_off, 16)
        print '\n'
        print '[+] DexProtoId:'
        for index in range(len(self.DexProtoIdList)):
            shortyIdx, returnTypeIdx, parametersOff_hex, parameters = self.DexProtoIdList[index]
            print '    #%s' % hex(index)
            print '    DexProtoId[%d]->shortyIdx= %s' % (index,shortyIdx)
            print '    DexProtoId[%d]->returnTypeIdx= %s\t#%s' % (index,returnTypeIdx, returnTypeIdx)
            print '    DexProtoId[%d]->parametersOff= 0x%s' % (index,parametersOff_hex)
            print '      DexTypeList->list= ' + parameters
            print ''

    def int_DexFieldId(self):
        field_ids_off = int(self.field_ids_off, 16)
        field_ids_size = int(self.field_ids_size, 16)

        self.f.seek(field_ids_off, 0)
        self.DexFieldIdList = []
        for index in range(field_ids_size):
            # DexFieldId
            # u2 classIdx
            classIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            classIdx = int(classIdx_hex, 16)
            # u2 typeIdx
            typeIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            typeIdx = int(typeIdx_hex, 16)
            # u4 nameIdx
            nameIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            nameIdx = int(nameIdx_hex, 16)

            self.DexFieldIdList.append((self.DexTypeIdList[classIdx], self.DexTypeIdList[typeIdx], self.DexStringIdList[nameIdx]))

    def print_DexFieldId(self):
        field_ids_off = int(self.field_ids_off, 16)
        field_ids_size = int(self.field_ids_size, 16)

        self.f.seek(field_ids_off, 0)
        print '[+] DexFieldId:'
        for index in range(field_ids_size):
            # DexFieldId
            # u2 classIdx
            classIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            classIdx = int(classIdx_hex, 16)
            # u2 typeIdx
            typeIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            typeIdx = int(typeIdx_hex, 16)
            # u4 nameIdx
            nameIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            nameIdx = int(nameIdx_hex, 16)

            print '    #%s (%s~%s)' % (hex(index), hex(field_ids_off + index*8), hex(field_ids_off + index*8 + 7))
            print '    DexFieldId[%d]->classIdx=%s # Class type: %s' % (index, hex(classIdx), self.DexTypeIdList[classIdx])
            print '    DexFieldId[%d]->typeIdx=%s # Field type: %s' % (index, hex(typeIdx), self.DexTypeIdList[typeIdx])
            print '    DexFieldId[%d]->nameIdx=%s # Field name: %s' % (index, hex(nameIdx), self.DexStringIdList[nameIdx])
            print ''

    def init_DexMethodId(self):
        method_ids_off = int(self.method_ids_off, 16)
        method_ids_size = int(self.method_ids_size, 16)

        self.f.seek(method_ids_off, 0)
        self.DexMethodIdList = []

        for index in range(method_ids_size):
            # DexMethodId
            # u2 classIdx
            classIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            classIdx = int(classIdx_hex, 16)
            # u2 protoIdx
            protoIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            protoIdx = int(protoIdx_hex, 16)
            # u4 nameIdx
            nameIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            nameIdx = int(nameIdx_hex, 16)

            shortyIdx, returnTypeIdx, _ , parameters =self.DexProtoIdList[protoIdx]
            self.DexMethodIdList.append((self.DexTypeIdList[classIdx], parameters+returnTypeIdx, self.DexStringIdList[nameIdx]))

    def print_DexMethodId(self):
        method_ids_off = int(self.method_ids_off, 16)
        method_ids_size = int(self.method_ids_size, 16)

        self.f.seek(method_ids_off, 0)
        print '\n'
        print '[+] DexMethodId:'

        for index in range(method_ids_size):
            # DexMethodId
            # u2 classIdx
            classIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            classIdx = int(classIdx_hex, 16)
            # u2 protoIdx
            protoIdx_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
            protoIdx = int(protoIdx_hex, 16)
            # u4 nameIdx
            nameIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            nameIdx = int(nameIdx_hex, 16)

            print '    #%s (%s~%s)' % (hex(index), hex(method_ids_off + index*8), hex(method_ids_off + index*8 + 7))
            print '    DexMethodId[%d]->classIdx=%s # %s' % (index, hex(classIdx), self.DexTypeIdList[classIdx])
            shortyIdx, returnTypeIdx, _ , parameters =self.DexProtoIdList[protoIdx]
            print '    DexMethodId[%d]->protoIdx=%s # %s %s %s' % (index, hex(protoIdx), shortyIdx, returnTypeIdx, parameters)
            print '    DexMethodId[%d]->nameIdx=%s # %s' % (index, hex(nameIdx), self.DexStringIdList[nameIdx])
            print ''

    def print_DexClassDef(self):
        class_defs_size_int = int(self.class_defs_size, 16)
        class_defs_off_int = int(self.class_defs_off, 16)
        dexClassDefList = []
        for index in range(class_defs_size_int):
            dexClassDefObj = DexClassDef()
            dexClassDefList.append(dexClassDefObj)

            #u4 classIdx
            self.f.seek(class_defs_off_int + index*32, 0)
            classIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            classIdx = int(classIdx_hex, 16)

            #u4 accessFlags
            self.f.seek(class_defs_off_int + index*32 + 4, 0)
            accessFlags_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            accessFlags = int(accessFlags_hex, 16)

            #u4 superclassIdx
            self.f.seek(class_defs_off_int + index*32 + 8, 0)
            superclassIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            superclassIdx = int(superclassIdx_hex, 16)

            #u4 interfaceOff
            self.f.seek(class_defs_off_int + index*32 + 12, 0)
            interfaceOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            interfaceOff = int(interfaceOff_hex, 16)

            #u4 sourceFieldIdx
            self.f.seek(class_defs_off_int + index*32 + 16, 0)
            sourceFieldIdx_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            sourceFieldIdx = int(sourceFieldIdx_hex, 16)

            #u4 annotationsOff
            self.f.seek(class_defs_off_int + index*32 + 20, 0)
            annotationsOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            annotationsOff = int(annotationsOff_hex, 16)

            #u4 classDataOff
            self.f.seek(class_defs_off_int + index*32 + 24, 0)
            classDataOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            classDataOff = int(classDataOff_hex, 16)

            #u4 staticValueOff
            self.f.seek(class_defs_off_int + index * 32 + 28, 0)
            staticValueOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
            staticValueOff = int(staticValueOff_hex, 16)

            dexClassDefObj.classIdx = classIdx
            dexClassDefObj.accessFlags = accessFlags
            dexClassDefObj.superclassIdx = superclassIdx
            dexClassDefObj.interfaceOff = interfaceOff
            dexClassDefObj.sourceFieldIdx = sourceFieldIdx
            dexClassDefObj.annotationsOff = annotationsOff
            dexClassDefObj.classDataOff = classDataOff
            dexClassDefObj.staticValueOff = staticValueOff

            if classDataOff == 0x0:
                print '\n'
                print '[+] #%s~%s' % (hex(class_defs_off_int + index * 32), hex(class_defs_off_int + index * 32 + 31))
                print '    DexClassDef[%d]:\t' % index
                print '    DexClassDef[%d]->classIdx\t= %s # %s' % (
                    index, hex(dexClassDefObj.classIdx), self.DexTypeIdList[dexClassDefObj.classIdx])
                print '    DexClassDef[%d]->accessFlags\t= %s' % (index, hex(dexClassDefObj.accessFlags))
                print '    DexClassDef[%d]->superclassIdx\t= %s # %s' % (
                    index, hex(dexClassDefObj.superclassIdx), self.DexTypeIdList[dexClassDefObj.superclassIdx])
                print '    DexClassDef[%d]->interfaceOff\t= %s' % (index, hex(dexClassDefObj.interfaceOff))
                if dexClassDefObj.sourceFieldIdx == 0xffffffff:
                    print '    DexClassDef[%d]->sourceFieldIdx\t= %s # UNKNOWN' % (
                        index, hex(dexClassDefObj.sourceFieldIdx))
                else:
                    print '    DexClassDef[%d]->sourceFieldIdx\t= %s # %s' % (
                        index, hex(dexClassDefObj.sourceFieldIdx), self.DexStringIdList[dexClassDefObj.sourceFieldIdx])
                print '    DexClassDef[%d]->annotationsOff\t= %s' % (index, hex(dexClassDefObj.annotationsOff))
                print '    DexClassDef[%d]->classDataOff\t= %s' % (index, hex(classDataOff))
                print '    DexClassDef[%d]->staticValueOff\t= %s' % (index, hex(staticValueOff))
                continue

            # 获取DexClassData结构
            ######################################################
            # 解析DexClassData结构体中header成员
            self.f.seek(classDataOff, 0)
            dexClassDataHeader = []
            for i in range(4):
                cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                cur_bytes = int(cur_bytes_hex, 16)
                value = cur_bytes_hex

                while cur_bytes > 0x7f:
                    cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                    value += cur_bytes_hex
                    cur_bytes = int(cur_bytes_hex, 16)
                dexClassDataHeader.append(value)
            staticFieldsSize = self.readUnsignedLeb128(dexClassDataHeader[0])
            instanceFieldsSize = self.readUnsignedLeb128(dexClassDataHeader[1])
            directMethodsSize = self.readUnsignedLeb128(dexClassDataHeader[2])
            virtualMethodsSize = self.readUnsignedLeb128(dexClassDataHeader[3])

            dexClassDefObj.header.staticFieldsSize = staticFieldsSize
            dexClassDefObj.header.instanceFieldsSize = instanceFieldsSize
            dexClassDefObj.header.directMethodsSize = directMethodsSize
            dexClassDefObj.header.virtualMethodsSize = virtualMethodsSize

            # 解析DexClassData结构体中staticFields、instanceFields、directMethods和virtualMethods成员
            # (1)解析DexField* staticFields成员
            """
            struct DexField{
                u4 fieldIdx;
                u4 accessFlags;
            }
            """
            for i in range(staticFieldsSize):
                array = []
                for j in range(2):
                    cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                    cur_bytes = int(cur_bytes_hex, 16)
                    value = cur_bytes_hex

                    while cur_bytes > 0x7f:
                        cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                        cur_bytes = int(cur_bytes_hex, 16)
                        value += cur_bytes_hex

                    array.append(value)

                dexField = DexField()
                dexField.fieldIdx = self.readUnsignedLeb128(array[0])
                dexField.accessFlags = self.readUnsignedLeb128(array[1])

                dexClassDefObj.staticFields.append(dexField)

            # (2)解析DexField* instanceFields成员
            for i in range(instanceFieldsSize):
                array = []
                for j in range(2):
                    cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                    cur_bytes = int(cur_bytes_hex, 16)
                    value = cur_bytes_hex

                    while cur_bytes > 0x7f:
                        cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                        cur_bytes = int(cur_bytes_hex, 16)
                        value += cur_bytes_hex

                    array.append(value)

                dexField = DexField()
                dexField.fieldIdx = self.readUnsignedLeb128(array[0])
                dexField.accessFlags = self.readUnsignedLeb128(array[1])

                dexClassDefObj.instanceFields.append(dexField)

            # (3)解析DexMethod* directMethods成员
            for i in range(directMethodsSize):
                array = []
                for j in range(3):
                    cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                    cur_bytes = int(cur_bytes_hex, 16)
                    value = cur_bytes_hex

                    while cur_bytes > 0x7f:
                        cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                        cur_bytes = int(cur_bytes_hex, 16)
                        value += cur_bytes_hex

                    array.append(value)

                dexMethod = DexMethod()
                dexMethod.methodIdx = self.readUnsignedLeb128(array[0])
                dexMethod.accessFlags = self.readUnsignedLeb128(array[1])
                dexMethod.codeOff = self.readUnsignedLeb128(array[2])

                dexClassDefObj.directMethods.append(dexMethod)

            # (4)解析DexMethod* virtualMethods成员
            for i in range(virtualMethodsSize):
                array = []
                for j in range(3):
                    cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                    cur_bytes = int(cur_bytes_hex, 16)
                    value = cur_bytes_hex

                    while cur_bytes > 0x7f:
                        cur_bytes_hex = binascii.b2a_hex(self.f.read(1))
                        cur_bytes = int(cur_bytes_hex, 16)
                        value += cur_bytes_hex

                    array.append(value)

                dexMethod = DexMethod()
                dexMethod.methodIdx = self.readUnsignedLeb128(array[0])
                dexMethod.accessFlags = self.readUnsignedLeb128(array[1])
                dexMethod.codeOff = self.readUnsignedLeb128(array[2])

                dexClassDefObj.virtualMethods.append(dexMethod)
            ######################################################

            # 解析DexCode
            for dexMethod in dexClassDefObj.directMethods:
                # 跳转到指向DexCode的偏移处
                if dexMethod.codeOff != 0x0:
                    dexCode = self.parseDexCode(dexMethod.codeOff)
                    dexMethod.dexCode = dexCode
                else:
                    dexMethod.dexCode = None

            for dexMethod in dexClassDefObj.virtualMethods:
                # 跳转到指向DexCode的偏移处
                if dexMethod.codeOff != 0x0:
                    dexCode = self.parseDexCode(dexMethod.codeOff)
                    dexMethod.dexCode = dexCode
                else:
                    dexMethod.dexCode = None

            print '\n'
            print '[+] #%s~%s' % (hex(class_defs_off_int + index*32), hex(class_defs_off_int + index*32 + 31))
            print '    DexClassDef[%d]:\t' % index
            print '    DexClassDef[%d]->classIdx\t= %s # %s' % (index, hex(dexClassDefObj.classIdx), self.DexTypeIdList[dexClassDefObj.classIdx])
            print '    DexClassDef[%d]->accessFlags\t= %s' % (index, hex(dexClassDefObj.accessFlags) )
            print '    DexClassDef[%d]->superclassIdx\t= %s # %s' % (index, hex(dexClassDefObj.superclassIdx), self.DexTypeIdList[dexClassDefObj.superclassIdx])
            print '    DexClassDef[%d]->interfaceOff\t= %s' % (index, hex(dexClassDefObj.interfaceOff))
            if dexClassDefObj.sourceFieldIdx == 0xffffffff:
                print '    DexClassDef[%d]->sourceFieldIdx\t= %s # UNKNOWN' % (index, hex(dexClassDefObj.sourceFieldIdx))
            else:
                print '    DexClassDef[%d]->sourceFieldIdx\t= %s # %s' % (index, hex(dexClassDefObj.sourceFieldIdx), self.DexStringIdList[dexClassDefObj.sourceFieldIdx])
            print '    DexClassDef[%d]->annotationsOff\t= %s' % (index, hex(dexClassDefObj.annotationsOff))
            print '    DexClassDef[%d]->classDataOff\t= %s' % (index, hex(classDataOff))
            print '    DexClassDef[%d]->staticValueOff\t= %s' % (index, hex(staticValueOff))
            print '    DexClassDef[%d]->DexClassData->DexClassDataHeader->staticFieldsSize \t= %s' % (index, hex(dexClassDefObj.header.staticFieldsSize))
            print '    DexClassDef[%d]->DexClassData->DexClassDataHeader->instanceFieldsSize \t= %s' % (index, hex(dexClassDefObj.header.instanceFieldsSize))
            print '    DexClassDef[%d]->DexClassData->DexClassDataHeader->directMethodsSize \t= %s' % (index, hex(dexClassDefObj.header.directMethodsSize))
            print '    DexClassDef[%d]->DexClassData->DexClassDataHeader->virtualMethodsSize \t= %s' % (index, hex(dexClassDefObj.header.virtualMethodsSize))
            lastFieldIdx = 0
            for k in range(len(dexClassDefObj.staticFields)):
                currFieldIdx = lastFieldIdx + dexClassDefObj.staticFields[k].fieldIdx
                _,_, fieldName = self.DexFieldIdList[currFieldIdx]
                lastFieldIdx = currFieldIdx
                print '    DexClassDef[%d]->DexClassData->staticFields[%d]\t= %s // %s' % (index, k, fieldName, dexClassDefObj.staticFields[k])

            lastFieldIdx = 0
            for k in range(len(dexClassDefObj.instanceFields)):
                currFieldIdx = lastFieldIdx + dexClassDefObj.instanceFields[k].fieldIdx
                _, _, fieldName = self.DexFieldIdList[currFieldIdx]
                lastFieldIdx = currFieldIdx
                print '    DexClassDef[%d]->DexClassData->instanceFields[%d]\t= %s // %s' % (index, k, fieldName, dexClassDefObj.instanceFields[k])

            lastMethodIdx = 0
            for k in range(len(dexClassDefObj.directMethods)):
                currMethodIdx = lastMethodIdx + dexClassDefObj.directMethods[k].methodIdx
                classIdx, protoIdx, nameIdx = self.DexMethodIdList[currMethodIdx]
                lastMethodIdx = currMethodIdx
                print '    DexClassDef[%d]->DexClassData->directMethods[%d]\t= %s.%s:%s // %s' % (index, k, classIdx, nameIdx, protoIdx, dexClassDefObj.directMethods[k])
                self.dumpDexCode(dexClassDefObj.directMethods[k])

            lastMethodIdx = 0
            for k in range(len(dexClassDefObj.virtualMethods)):

                currMethodIdx = lastMethodIdx + dexClassDefObj.virtualMethods[k].methodIdx
                classIdx, protoIdx, nameIdx = self.DexMethodIdList[currMethodIdx]
                lastMethodIdx = currMethodIdx
                print '    DexClassDef[%d]->DexClassData->virtualMethods[%d]\t= %s.%s:%s // %s' % (index, k, classIdx, nameIdx, protoIdx, dexClassDefObj.virtualMethods[k])
                self.dumpDexCode(dexClassDefObj.virtualMethods[k])

    def dumpDexCode(self, dexMethod):
        if dexMethod.dexCode == None:
            return

        print '    DexCode=%s' % dexMethod.dexCode
        offset = 0
        insnsSize = dexMethod.dexCode.insnsSize * 4

        while offset < insnsSize:
            opcode = int(dexMethod.dexCode.insns[offset:offset + 2], 16)
            formatIns, _ = OpCode.getOpCode(opcode)

            decodedInstruction = InstrUtils.dexDecodeInstruction(self, dexMethod.dexCode, offset)

            smaliCode = decodedInstruction.smaliCode
            if smaliCode == None:
                continue

            insns = dexMethod.dexCode.insns[decodedInstruction.offset:decodedInstruction.offset + decodedInstruction.length]
            print '    \t%-16s|%04x: %s' % (insns, offset/4, smaliCode)
            offset += len(insns)

            if smaliCode == 'nop':
                break

    def parseDexCode(self, codeOff):
        self.f.seek(codeOff, 0)

        registersSize_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
        registersSize = int(registersSize_hex, 16)

        insSize_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
        insSize = int(insSize_hex, 16)

        outsSize_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
        outsSize = int(outsSize_hex, 16)

        triesSize_hex = binascii.b2a_hex(self.f.read(2)).decode('hex')[::-1].encode('hex')
        triesSize = int(triesSize_hex, 16)

        debugInfoOff_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
        debugInfoOff = int(debugInfoOff_hex, 16)

        insnsSize_hex = binascii.b2a_hex(self.f.read(4)).decode('hex')[::-1].encode('hex')
        insnsSize = int(insnsSize_hex, 16)

        if insnsSize == 0:
            insns = ''
        else:
            if insnsSize*2 > sys.maxint:
                size = insnsSize*2
                insns = ''
                while size > sys.maxint:
                    insns += binascii.b2a_hex(self.f.read(sys.maxint))
                    size -= sys.maxint
            else:
                insns = binascii.b2a_hex(self.f.read(insnsSize*2))

        dexCode = DexCode()
        dexCode.registersSize = registersSize
        dexCode.insSize = insSize
        dexCode.outsSize = outsSize
        dexCode.triesSize = triesSize
        dexCode.debugInfoOff = debugInfoOff
        dexCode.insnsSize = insnsSize
        dexCode.insns = insns

        return dexCode

    def readUnsignedLeb128(self, hex_value):
        byte_counts = len(hex_value)/2

        #找出第一个不是0的byte位置
        index = 0
        for i in range(byte_counts):
            v1 = int(hex_value[i*2:i*2+2], 16)
            if v1 > 0:
                index = i
                break

        hex_value = hex_value[index*2:]
        byte_counts = len(hex_value)/2

        result = 0
        for i in range(byte_counts):
            cur = int(hex_value[i*2:i*2+2], 16)
            if cur > 0x7f:
                result = result | ((cur & 0x7f) << (7*i))
            else:
                result = result | ((cur & 0x7f) << (7*i))
                break
        return result

class DexClassDef(object):
    def __init__(self,):
        super(DexClassDef, self).__init__()
        self.classIdx = None
        self.accessFlags = None
        self.superclassIdx = None
        self.interfaceOff = None
        self.sourceFieldIdx = None
        self.annotationsOff = None
        self.classDataOff = None
        self.staticValueOff = None

        self.header = DexClassDataHeader()
        self.staticFields = []
        self.instanceFields = []
        self.directMethods = []
        self.virtualMethods = []

class DexClassDataHeader(object):
    """docstring for ClassName"""
    def __init__(self):
        super(DexClassDataHeader, self).__init__()
        self.staticFieldsSize = None
        self.instanceFieldsSize = None
        self.directMethodsSize = None
        self.virtualMethodsSize = None

class DexField(object):
    """docstring for DexField"""
    def __init__(self):
        super(DexField, self).__init__()
        self.fieldIdx = None
        self.accessFlags = None

    def __str__(self):
        return '[fieldIdx = %s, accessFlags = %s]' % (hex(self.fieldIdx), hex(self.accessFlags))

class DexMethod(object):
    """docstring for DexMethod"""
    def __init__(self):
        super(DexMethod, self).__init__()
        self.methodIdx = None
        self.accessFlags = None
        self.codeOff = None

        self.dexCode = DexCode()

    def __str__(self):
        return '[methodIdx = %s, accessFlags = %s, codeOff = %s]' % (hex(self.methodIdx), hex(self.accessFlags), hex(self.codeOff))

class DexCode(object):
    """docstring for DexCode"""
    def __init__(self):
        super(DexCode, self).__init__()
        self.registersSize = None
        self.insSize = None
        self.outsSize = None
        self.triesSize = None
        self.debugInfoOff = None
        self.insnsSize = None
        self.insns = None

    def __str__(self):
        return '[registersSize = %s, insSize = %s, outsSize = %s, triesSize = %s, debugInfoOff = %s, insnsSize = %s, insns = %s]' % \
                (self.registersSize, self.insSize, self.outsSize, self.triesSize, hex(self.debugInfoOff), self.insnsSize, self.insns)


def main():
    dex = DexFile(sys.argv[1])
    dex.print_header()
    dex.print_DexMapList()
    dex.print_DexStringId()
    dex.print_DexTypeId()
    dex.print_DexProtoId()
    dex.print_DexFieldId()
    dex.print_DexMethodId()
    dex.print_DexClassDef()

if __name__ == '__main__':
    main()



