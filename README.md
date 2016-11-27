### dex文件解析工具 
####(1)usage:
python dexParser.py Test.dex
####(2)例子：

Test.java源码

```java
public class Test{
    public int a;
    private long b;
    public static int c;

    public int add(int a, int b){
    	return a + b;
    }

    public float minus(float a, float b){
    	return a - b;
    }

    public void print(){
    	System.out.println("Hello World!");
    }
}
```
用下面的dx命令生成dex文件
dx --dex --output=Test.dex Test.class

####(3)测试:
python dexParser.py Test.dex
输出结构如下：
```
[+] magic:	0x6465780a30333500
[+] checksum:	0x09d96791
[+] signature:	8f03232ed0cfeb1c33c5ff784b6bfd9311917cd5
[+] file_size:	0x000003a4
[+] header_size:	0x00000070
[+] endian_tag:	0x12345678
[+] link_size:	0x00000000
[+] link_off:	0x00000000
[+] map_off:	0x00000304
[+] string_ids_size:	0x00000017
[+] string_ids_off:	0x00000070
[+] type_ids_size:	0x00000009
[+] type_ids_off:	0x000000cc
[+] proto_ids_size:	0x00000004
[+] proto_ids_off:	0x000000f0
[+] field_ids_size:	0x00000004
[+] field_ids_off:	0x00000120
[+] method_ids_size:	0x00000006
[+] method_ids_off:	0x00000140
[+] class_defs_size:	0x00000001
[+] class_defs_off:	0x00000170
[+] data_size:	0x00000214
[+] data_off:	0x00000190


[+] #0 DexMapItem:	
    u2 dexType	0000 #kDexTypeHeaderItem
    u2 unused	0000
    u4 size	00000001
    u4 offset	00000000


[+] #1 DexMapItem:	
    u2 dexType	0001 #kDexTypeStringIdItem
    u2 unused	0000
    u4 size	00000017
    u4 offset	00000070


[+] #2 DexMapItem:	
    u2 dexType	0002 #kDexTypeTypeIdItem
    u2 unused	0000
    u4 size	00000009
    u4 offset	000000cc


[+] #3 DexMapItem:	
    u2 dexType	0003 #kDexTypeProtoIdItem
    u2 unused	0000
    u4 size	00000004
    u4 offset	000000f0


[+] #4 DexMapItem:	
    u2 dexType	0004 #kDexTypeFieldIdItem
    u2 unused	0000
    u4 size	00000004
    u4 offset	00000120


[+] #5 DexMapItem:	
    u2 dexType	0005 #kDexTypeMethodIdItem
    u2 unused	0000
    u4 size	00000006
    u4 offset	00000140


[+] #6 DexMapItem:	
    u2 dexType	0006 #kDexTypeClassDefItem
    u2 unused	0000
    u4 size	00000001
    u4 offset	00000170


[+] #7 DexMapItem:	
    u2 dexType	2001 #kDexTypeCodeItem
    u2 unused	0000
    u4 size	00000004
    u4 offset	00000190


[+] #8 DexMapItem:	
    u2 dexType	1001 #kDexTypeTypeList
    u2 unused	0000
    u4 size	00000003
    u4 offset	000001f8


[+] #9 DexMapItem:	
    u2 dexType	2002 #kDexTypeStringDataItem
    u2 unused	0000
    u4 size	00000017
    u4 offset	0000020e


[+] #10 DexMapItem:	
    u2 dexType	2003 #kDexTypeDebugInfoItem
    u2 unused	0000
    u4 size	00000004
    u4 offset	000002ce


[+] #11 DexMapItem:	
    u2 dexType	2000 #kDexTypeClassDataItem
    u2 unused	0000
    u4 size	00000001
    u4 offset	000002e7


[+] #12 DexMapItem:	
    u2 dexType	1000 #kDexTypeMapList
    u2 unused	0000
    u4 size	00000001
    u4 offset	00000304


[+] DexStringId:
    #0x0 <init>
    #0x1 F
    #0x2 FFF
    #0x3 Hello World!
    #0x4 I
    #0x5 III
    #0x6 J
    #0x7 LTest;
    #0x8 Ljava/io/PrintStream;
    #0x9 Ljava/lang/Object;
    #0xa Ljava/lang/String;
    #0xb Ljava/lang/System;
    #0xc Test.java
    #0xd V
    #0xe VL
    #0xf a
    #0x10 add
    #0x11 b
    #0x12 c
    #0x13 minus
    #0x14 out
    #0x15 print
    #0x16 println


[+] DexTypeId:
    #0x0 #F
    #0x1 #I
    #0x2 #J
    #0x3 #LTest;
    #0x4 #Ljava/io/PrintStream;
    #0x5 #Ljava/lang/Object;
    #0x6 #Ljava/lang/String;
    #0x7 #Ljava/lang/System;
    #0x8 #V


[+] DexProtoId:
    #0x0
    DexProtoId[0]->shortyIdx= FFF
    DexProtoId[0]->returnTypeIdx= F	#F
    DexProtoId[0]->parametersOff= 0x000001f8
      DexTypeList->list= (F, F, )

    #0x1
    DexProtoId[1]->shortyIdx= III
    DexProtoId[1]->returnTypeIdx= I	#I
    DexProtoId[1]->parametersOff= 0x00000200
      DexTypeList->list= (I, I, )

    #0x2
    DexProtoId[2]->shortyIdx= V
    DexProtoId[2]->returnTypeIdx= V	#V
    DexProtoId[2]->parametersOff= 0x00000000
      DexTypeList->list= ()

    #0x3
    DexProtoId[3]->shortyIdx= VL
    DexProtoId[3]->returnTypeIdx= V	#V
    DexProtoId[3]->parametersOff= 0x00000208
      DexTypeList->list= (Ljava/lang/String;, )

[+] DexFieldId:
    #0x0 (0x120~0x127)
    DexFieldId[0]->classIdx=0x3 # Class type: LTest;
    DexFieldId[0]->typeIdx=0x1 # Field type: I
    DexFieldId[0]->nameIdx=0xf # Field name: a

    #0x1 (0x128~0x12f)
    DexFieldId[1]->classIdx=0x3 # Class type: LTest;
    DexFieldId[1]->typeIdx=0x2 # Field type: J
    DexFieldId[1]->nameIdx=0x11 # Field name: b

    #0x2 (0x130~0x137)
    DexFieldId[2]->classIdx=0x3 # Class type: LTest;
    DexFieldId[2]->typeIdx=0x1 # Field type: I
    DexFieldId[2]->nameIdx=0x12 # Field name: c

    #0x3 (0x138~0x13f)
    DexFieldId[3]->classIdx=0x7 # Class type: Ljava/lang/System;
    DexFieldId[3]->typeIdx=0x4 # Field type: Ljava/io/PrintStream;
    DexFieldId[3]->nameIdx=0x14 # Field name: out



[+] DexMethodId:
    #0x0 (0x140~0x147)
    DexMethodId[0]->classIdx=0x3 # LTest;
    DexMethodId[0]->protoIdx=0x2 # V V ()
    DexMethodId[0]->nameIdx=0x0 # <init>

    #0x1 (0x148~0x14f)
    DexMethodId[1]->classIdx=0x3 # LTest;
    DexMethodId[1]->protoIdx=0x1 # III I (I, I, )
    DexMethodId[1]->nameIdx=0x10 # add

    #0x2 (0x150~0x157)
    DexMethodId[2]->classIdx=0x3 # LTest;
    DexMethodId[2]->protoIdx=0x0 # FFF F (F, F, )
    DexMethodId[2]->nameIdx=0x13 # minus

    #0x3 (0x158~0x15f)
    DexMethodId[3]->classIdx=0x3 # LTest;
    DexMethodId[3]->protoIdx=0x2 # V V ()
    DexMethodId[3]->nameIdx=0x15 # print

    #0x4 (0x160~0x167)
    DexMethodId[4]->classIdx=0x4 # Ljava/io/PrintStream;
    DexMethodId[4]->protoIdx=0x3 # VL V (Ljava/lang/String;, )
    DexMethodId[4]->nameIdx=0x16 # println

    #0x5 (0x168~0x16f)
    DexMethodId[5]->classIdx=0x5 # Ljava/lang/Object;
    DexMethodId[5]->protoIdx=0x2 # V V ()
    DexMethodId[5]->nameIdx=0x0 # <init>



[+] #0x170~0x18f
    DexClassDef[0]:	
    DexClassDef[0]->classIdx	= 0x3 # LTest;
    DexClassDef[0]->accessFlags	= 0x1
    DexClassDef[0]->superclassIdx	= 0x5 # Ljava/lang/Object;
    DexClassDef[0]->interfaceOff	= 0x0
    DexClassDef[0]->sourceFieldIdx	= 0xc # Test.java
    DexClassDef[0]->annotationsOff	= 0x0
    DexClassDef[0]->classDataOff	= 0x2e7
    DexClassDef[0]->staticValueOff	= 0x0
    DexClassDef[0]->DexClassData->DexClassDataHeader->staticFieldsSize 	= 0x1
    DexClassDef[0]->DexClassData->DexClassDataHeader->instanceFieldsSize 	= 0x2
    DexClassDef[0]->DexClassData->DexClassDataHeader->directMethodsSize 	= 0x1
    DexClassDef[0]->DexClassData->DexClassDataHeader->virtualMethodsSize 	= 0x3
    DexClassDef[0]->DexClassData->staticFields[0]	= c // [fieldIdx = 0x2, accessFlags = 0x9]
    DexClassDef[0]->DexClassData->instanceFields[0]	= a // [fieldIdx = 0x0, accessFlags = 0x1]
    DexClassDef[0]->DexClassData->instanceFields[1]	= b // [fieldIdx = 0x1, accessFlags = 0x2]
    DexClassDef[0]->DexClassData->directMethods[0]	= LTest;.<init>:()V // [methodIdx = 0x0, accessFlags = 0x10001, codeOff = 0x190]
    DexCode=[registersSize = 1, insSize = 1, outsSize = 1, triesSize = 0, debugInfoOff = 0x2ce, insnsSize = 4, insns = 7010050000000e00]
    	701005000000    |0000: invoke-direct {v0}, method@0005 //Ljava/lang/Object;.<init>:()V
    	0e00            |0003: return-void
    DexClassDef[0]->DexClassData->virtualMethods[0]	= LTest;.add:(I, I, )I // [methodIdx = 0x1, accessFlags = 0x1, codeOff = 0x1a8]
    DexCode=[registersSize = 4, insSize = 3, outsSize = 0, triesSize = 0, debugInfoOff = 0x2d3, insnsSize = 3, insns = 900002030f00]
    	90000203        |0000: add-int v0, v2, v3
    	0f00            |0002: return v0
    DexClassDef[0]->DexClassData->virtualMethods[1]	= LTest;.minus:(F, F, )F // [methodIdx = 0x1, accessFlags = 0x1, codeOff = 0x1c0]
    DexCode=[registersSize = 4, insSize = 3, outsSize = 0, triesSize = 0, debugInfoOff = 0x2da, insnsSize = 3, insns = a70002030f00]
    	a7000203        |0000: sub-float v0, v2, v3
    	0f00            |0002: return v0
    DexClassDef[0]->DexClassData->virtualMethods[2]	= LTest;.print:()V // [methodIdx = 0x1, accessFlags = 0x1, codeOff = 0x1d8]
    DexCode=[registersSize = 3, insSize = 1, outsSize = 2, triesSize = 0, debugInfoOff = 0x2e1, insnsSize = 8, insns = 620003001a0103006e20040010000e00]
    	62000300        |0000: sget-object v0, field@0003 //Ljava/lang/System;.out:Ljava/io/PrintStream;
    	1a010300        |0002: const-string v1, string@0003 //Hello World!
    	6e2004001000    |0004: invoke-virtual {v0, v1}, method@0004 //Ljava/io/PrintStream;.println:(Ljava/lang/String;, )V
    	0e00            |0007: return-void

```
