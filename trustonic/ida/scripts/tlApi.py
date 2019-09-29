#!/usr/bin/env python
#TlApi Func Auto-Renamer (c) B.Kerler 2019
#Licensed under MIT license
#IDA Pro plugin. Use MCLF Loader, let autoanalysis finish, then run this script for fun
    
tlapilist = {
    0x1:"tlApiGetVersion",
    0x2:"tlApiGetMobicoreVersion",
    0x4:"tlApiExit",
    0x6:"tlApiWaitNotification",
    0x5:"tlApiLogvPrintf",
    0x7:"tlApiNotify",
    0x8:"tlApi_callDriver",
    0x9:"tlApiWrapObjectExt",
    0xA:"tlApiUnwrapObjectExt",
    0xB:"tlApiGetSuid",
    0xC:"tlApi_callDriverEx",
    0xD:"tlApiCrAbort",
    0xE:"tlApiRandomGenerateData",
    0xF:"tlApiGenerateKeyPair",
    0x10:"tlApiCipherInitWithData",
    0x11:"tlApiCipherUpdate",
    0x12:"tlApiCipherDoFinal",
    0x13:"tlApiSignatureInitWithData",
    0x14:"tlApiSignatureUpdate",
    0x15:"tlApiSignatureSign",
    0x16:"tlApiSignatureVerify",
    0x17:"tlApiMessageDigestInitWithData",
    0x18:"tlApiMessageDigestUpdate",
    0x19:"tlApiMessageDigestDoFinal",
    0x1A:"tlApiGetVirtMemType",
    0x1B:"tlApiDeriveKey",
    0x1C:"tlApiMalloc",
    0x1D:"tlApiRealloc",
    0x1E:"tlApiFree",
    0x55:"tlApiEndorse",
    0x56:"tlApiTuiGetScreenInfo",
    0x57:"tlApiTuiOpenSession",
    0x58:"tlApiTuiCloseSession",
    0x59:"tlApiTuiSetImage",
    0x5A:"tlApiTuiGetTouchEvent",
    0x5D:"tlApiDrmOpenSession",
    0x5E:"tlApiDrmCloseSession",
    0x5F:"tlApiDrmCheckLink",
    0x62:"tlApiGetSecureTimestamp",
    0x64:"tlApiAddEntropy",
    0x65:"tlApiCreateHeap",
    0x68:"TEE_TBase_CloseSessions",
    0x69:"TEE_TBase_TakeIdentity",
    0x6A:"TEE_TBase_RevertIdentity",
    0x6B:"TEE_TBase_DeleteAllObjects"
}

import logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def search_ea(sig, segment="", callback=None):
    eas=[]
    if segment!="":
        seg = idaapi.get_segm_by_name(segment)
        if not seg:
            return
        ea, maxea = seg.startEA, seg.endEA
        count = 0
        while ea != idaapi.BADADDR:
            ea = idaapi.find_binary(ea, maxea, sig, 16, idaapi.SEARCH_DOWN)
            if ea != idaapi.BADADDR:
                count = count + 1
                if callback!=None:
                    callback(ea)
                else:
                    eas.append(ea)
                ea += 2
    else:
        for seg in Segments():
            ea=SegStart(seg)
            maxea=SegEnd(ea)
            count = 0
            while ea != idaapi.BADADDR:
                ea = idaapi.find_binary(ea, maxea, sig, 16, idaapi.SEARCH_DOWN)
                if ea != idaapi.BADADDR:
                    count = count + 1
                    if callback!=None:
                        callback(ea)
                    else:
                        eas.append(ea)
                    ea += 2
    return eas 

def generatefunc(ea,name):
    idc.MakeCode(ea)
    idc.MakeFunction(ea)
    idc.MakeNameEx(ea, name, idc.SN_NOWARN)
    logger.debug("Rename %x:%s" % (ea,name))

def addr_to_bhex(ea):
    ea=hex(ea)[2:]
    return ea[6:8]+" "+ea[4:6]+" "+ea[2:4]+" "+ea[0:2]


def get_tlapi_num(addr):
    i=addr
    while (i<addr+100):
        op = GetMnem(i).lower()
        if op in ("bx", "blx", "ret"):
            return -1
        if op=="movs":
            opnd=GetOpnd(i, 1)
            return int(opnd[1:],16)
        i = idc.NextHead(i)
    return -1

def getcaller(ea):
    pea=[]
    for addr in XrefsTo(ea, flags=0):
        pea.append(GetFunctionAttr(addr.frm, idc.FUNCATTR_START))
    return pea

def get_string(addr):
  out = ""
  while True:
    if Byte(addr) != 0:
      out += chr(Byte(addr))
    else:
      break
    addr += 1
  return out

def tlapicallback(ea):
    val=get_tlapi_num(ea)
    if val in tlapilist:
        name=tlapilist[val]
        paddr = idc.PrevHead(ea)
        pop=GetMnem(paddr).lower()
        if not pop in ("bx","blx","pop","ret"):
            ea = GetFunctionAttr(ea, idc.FUNCATTR_START)
        print("[TlApi Call] %08X:%s" % (ea, name))
        generatefunc(ea,name)
        if val==1:
            generatefunc(getcaller(ea)[0],"tlMain")
        elif val==5:
            pea=getcaller(ea)[0]
            generatefunc(pea,"tlApiLogPrintf")
            for sea in XrefsTo(pea, flags=0):
                mea=sea.frm
                for pos in range(0,0x100):
                    mea = idc.PrevHead(mea)
                    ppop=GetMnem(mea).lower()
                    if ppop in ("mov","movw","adr"):
                        fopnd=GetOpnd(mea,0).lower()
                        found=False
                        if fopnd=="r0":
                            ropnd=GetOpnd(mea,1).lower()
                            #print(ropnd)
                            if ropnd=="#0":
                                continue
                            if "#0x" in ropnd:
                                op_plain_offset(mea, 1, 0)
                                ropnd=GetOpnd(mea,1).lower()
                                found=True
                            if "#a" in ropnd:
                                opv=GetOperandValue(mea,1)
                                pstring=get_string(opv)
                                #print(pstring)
                                #MTK here be lions
                                if ("[" in pstring) and ("]" in pstring):
                                    idx=pstring.index("[")
                                    if idx==0:
                                        funcname=pstring[idx+1:]
                                        funcname=funcname[:funcname.index("]")]
                                        if not funcname.lower() in ("key","key1","ki"):
                                            if not " " in funcname:
                                                fea=GetFunctionAttr(mea,idc.FUNCATTR_START)
                                                if not fea is 0xFFFFFFFF:
                                                    print("0x%08x:%s" % (fea,funcname))
                                                    generatefunc(fea,funcname)
                            if ropnd[0]=="a":
                                opv=GetOperandValue(mea,1)
                                #pstring=get_string(opv)    #Uncomment to see printf for samsung
                                #print("%s:0x%08X" % (pstring,mea))        #Uncomment me as well    
                        if found==True:
                            break
                          

    return 0

for opcode in ("2D E9 FF","2D E9 F0","F0 B5","00 B5","30 B5"): #Make sure undefined funcs are defined
    funcs=search_ea(opcode,"",None)
    for ea in funcs:
        idc.MakeCode(ea)
        idc.MakeFunction(ea)

for addr in XrefsTo(0x108C, flags=0): #References to tlApi
  tlapicallback(addr.frm)

#Here be Samsungs (s6, s7)
kprintfs=search_ea("0F B4 1C B5 0C 00 07 AA 00 90 01 D0","",None) #log_I
for ea in kprintfs:
    generatefunc(ea,"LOG_I")
    for addr in XrefsTo(ea, flags=0):
        subea=addr.frm
        break
    break

#Here be Samsungs (s6, s7)
strlens=search_ea("42 1C 02 E0 10 F8 01 1B 69 B1","",None) #strlen
for ea in strlens:
    generatefunc(ea,"strlen")
    for addr in XrefsTo(ea, flags=0):
        subea=addr.frm
        nea=subea
        pea=subea
        for i in range(0,20):
            nea = idc.NextHead(nea)
            ppop=GetMnem(nea).lower()
            if ppop in ("ldr"):
                fopnd=GetOpnd(nea,0).lower()
                if fopnd=="r1":
                    nnd=GetOpnd(nea,1).lower()
                    if nnd[:2]=="=a":
                        opv=GetOperandValue(nea,1)
                        sopv=Dword(opv)
                        #print(hex(sopv))
                        pstring=get_string(sopv)
                        #print("0x%08X:%s" % (nea,pstring)) #Here we see all command references from Samsung
                        for x in range(0,20):
                            pea=idc.PrevHead(pea)
                            ppop=GetMnem(pea).lower()
                            if ppop in ("bl","blx"):
                                sop=GetOperandValue(pea,0)
                                if "(" in pstring and ")" in pstring:
                                    funcname=pstring[:pstring.index("(")]
                                    print("[Samsung Func Ref] 0x%08X:%s" % (sop,funcname))
                                    generatefunc(sop,funcname)
                                break
                    break
    break

